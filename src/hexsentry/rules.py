"""Detection rules. Each one is a transparent statistical check, not a model.

Every alert carries:
  * a plain-English reason that says what was seen and which limit it crossed
  * a confidence score that grows with how far past the limit the activity went
  * the thresholds in force (after feedback tuning) and the log lines behind it
"""

from __future__ import annotations

import bisect
import math
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import timedelta, timezone
from typing import Callable, Dict, Iterator, List, Optional, Sequence, Tuple

from .geo import Location, Resolver, haversine_km
from .model import SEVERITIES, Alert, Event, is_token

DEFAULTS: Dict[str, Dict[str, float]] = {
    "brute_force":            {"failures": 10, "window_min": 10},
    "password_spray":         {"users": 5, "window_min": 30, "max_per_user": 3},
    "distributed_attack":     {"sources": 5, "window_min": 60},
    "success_after_failures": {"failures": 5, "lookback_min": 30},
    "impossible_travel":      {"speed_kmh": 900, "min_km": 500},
    "odd_hours":              {"min_history": 10, "rare_share": 0.03, "quiet_start": 0, "quiet_end": 5},
}

# Which threshold in each rule is scaled by feedback tuning (a "how much is too much" number).
TUNABLE = {
    "brute_force": "failures",
    "password_spray": "users",
    "distributed_attack": "sources",
    "success_after_failures": "failures",
    "impossible_travel": "speed_kmh",
    "odd_hours": "rare_share",           # inverted: a smaller share is required to alert
}

RULE_INFO = {
    "brute_force": ("Brute force", "Many failed logins for one account from one source in a short window."),
    "password_spray": ("Password spraying", "One source trying many different usernames, a few attempts each."),
    "distributed_attack": ("Distributed attack", "One account failing from many different sources."),
    "success_after_failures": ("Login after failures", "A successful login from a source, or for an account, "
                                                       "that just produced a burst of failures."),
    "impossible_travel": ("Impossible travel", "Two successful logins for one user from places too far apart "
                                               "for the time between them."),
    "odd_hours": ("Unusual login time", "A successful login at an hour this user almost never logs in."),
}

PRIVILEGED = {"root", "admin", "administrator", "ubuntu", "ec2-user", "oracle", "postgres", "git", "deploy"}


def effective_thresholds(multipliers: Optional[Dict[str, float]] = None,
                         overrides: Optional[Dict[str, Dict[str, float]]] = None) -> Dict[str, Dict[str, float]]:
    out: Dict[str, Dict[str, float]] = {}
    for rule, base in DEFAULTS.items():
        th = dict(base)
        th.update((overrides or {}).get(rule, {}))
        m = (multipliers or {}).get(rule, 1.0)
        k = TUNABLE[rule]
        if rule == "odd_hours":
            th[k] = round(th[k] / m, 4)
        elif rule == "impossible_travel":
            th[k] = round(th[k] * m)
        else:
            th[k] = max(1, math.ceil(th[k] * m))
        out[rule] = th
    return out


# ---- helpers ------------------------------------------------------------

def _confidence(ratio: float, base: float, k: float = 1.1) -> float:
    """base at exactly the threshold, rising towards 0.99 as activity exceeds it."""
    return base + (0.99 - base) * (1 - math.exp(-k * max(0.0, ratio - 1.0)))


def _bump(sev: str, steps: int = 1) -> str:
    return SEVERITIES[max(0, min(len(SEVERITIES) - 1, SEVERITIES.index(sev) + steps))]


def _dur(td: timedelta) -> str:
    s = int(td.total_seconds())
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m {s % 60:02d}s"
    return f"{s // 3600}h {(s % 3600) // 60:02d}m"


def _refs(evs: Sequence[Event], limit: int = 12) -> List[str]:
    return [f"{e.file}:{e.line}" for e in evs[:limit]]


def _q(name: str) -> str:
    """Quote real usernames; hexredact tokens are already delimited."""
    return name if is_token(name) else f"'{name}'"


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def _bursts(evs: Sequence[Event], window: timedelta, threshold: float,
            key_of: Optional[Callable[[Event], object]] = None) -> Iterator[Tuple[int, int, int]]:
    """Sliding window over time-sorted events.

    The measure is the summed attempt count (key_of=None) or the number of
    distinct keys. Yields (start, end, peak) for each run of activity that
    reached the threshold; runs separated by more than one window are split.
    """
    counter: Counter = Counter()
    total, left = 0, 0
    active: Optional[List[int]] = None
    for j, e in enumerate(evs):
        if active is not None and e.ts - evs[active[1]].ts > window:
            yield active[0], active[1], active[2]
            active = None
        counter[key_of(e) if key_of else 0] += e.count
        total += e.count
        while e.ts - evs[left].ts > window:
            o = evs[left]
            k = key_of(o) if key_of else 0
            counter[k] -= o.count
            total -= o.count
            if counter[k] <= 0:
                del counter[k]
            left += 1
        v = len(counter) if key_of else total
        if v >= threshold:
            if active is None:
                active = [left, j, v]
            else:
                active[1], active[2] = j, max(active[2], v)
    if active is not None:
        yield active[0], active[1], active[2]


@dataclass
class Ctx:
    th: Dict[str, Dict[str, float]]
    resolver: Resolver
    tz: timezone

    def where(self, src: str) -> str:
        loc = self.resolver.lookup(src) if self.resolver.enabled else None
        return f" ({loc.label()})" if loc and loc.label() != "unknown" else ""


# ---- rules --------------------------------------------------------------

def rule_brute_force(events: List[Event], ctx: Ctx) -> List[Alert]:
    th = ctx.th["brute_force"]
    win = timedelta(minutes=th["window_min"])
    groups: Dict[Tuple[str, str], List[Event]] = defaultdict(list)
    for e in events:
        if e.kind == "fail":
            groups[(e.src, e.user)].append(e)
    alerts = []
    for (src, user), evs in groups.items():
        for s, t, peak in _bursts(evs, win, th["failures"]):
            burst = evs[s:t + 1]
            total = sum(e.count for e in burst)
            ratio = peak / th["failures"]
            methods = sorted({e.method for e in burst})
            invalid = all(e.invalid_user for e in burst)
            sev = "high" if user in PRIVILEGED else "medium"
            if ratio >= 3:
                sev = _bump(sev)
            reason = (f"{total} failed logins ({', '.join(methods)}) for {_q(user)} from {src}{ctx.where(src)} "
                      f"over {_dur(burst[-1].ts - burst[0].ts)}. Peak was {peak} within {int(th['window_min'])} min; "
                      f"the limit is {int(th['failures'])}.")
            if invalid:
                reason += " The account does not exist on this host, so this is guessing, not a forgotten password."
            elif user in PRIVILEGED:
                reason += " The target is a privileged or well-known account."
            alerts.append(Alert(
                "brute_force", RULE_INFO["brute_force"][0], sev, _confidence(ratio, 0.6),
                {"user": user, "src": src}, burst[0].ts, burst[-1].ts, reason,
                {"failures": total, "peak_in_window": peak, "methods": methods, "invalid_user": invalid},
                dict(th), _refs(burst)))
    return alerts


def rule_password_spray(events: List[Event], ctx: Ctx) -> List[Alert]:
    th = ctx.th["password_spray"]
    win = timedelta(minutes=th["window_min"])
    by_src: Dict[str, List[Event]] = defaultdict(list)
    for e in events:
        if e.kind == "fail":
            by_src[e.src].append(e)
    alerts = []
    for src, evs in by_src.items():
        for s, t, peak in _bursts(evs, win, th["users"], key_of=lambda e: e.user):
            burst = evs[s:t + 1]
            users = Counter()
            for e in burst:
                users[e.user] += e.count
            invalid = {e.user for e in burst if e.invalid_user}
            per_user = sum(users.values()) / len(users)
            ratio = peak / th["users"]
            spray = per_user <= th["max_per_user"]
            title = RULE_INFO["password_spray"][0] if spray else "Multi-account guessing"
            sev = "high" if spray else "medium"
            if ratio >= 3:
                sev = _bump(sev)
            conf = _confidence(ratio, 0.6 if spray else 0.5)
            reason = (f"{src}{ctx.where(src)} tried {len(users)} different usernames in "
                      f"{_dur(burst[-1].ts - burst[0].ts)}, averaging {per_user:.1f} attempts each "
                      f"(limit: {int(th['users'])} usernames within {int(th['window_min'])} min).")
            if spray:
                reason += " Few attempts per account is the signature of spraying: it stays under per-account lockouts."
            if invalid:
                reason += f" {len(invalid)} of the {len(users)} usernames don't exist here, which points to a wordlist."
            alerts.append(Alert(
                "password_spray", title, sev, conf, {"src": src}, burst[0].ts, burst[-1].ts, reason,
                {"distinct_users": len(users), "attempts": sum(users.values()),
                 "avg_attempts_per_user": round(per_user, 2), "invalid_users": len(invalid),
                 "top_users": [u for u, _ in users.most_common(10)]},
                dict(th), _refs(burst)))
    return alerts


def rule_distributed_attack(events: List[Event], ctx: Ctx) -> List[Alert]:
    th = ctx.th["distributed_attack"]
    win = timedelta(minutes=th["window_min"])
    by_user: Dict[str, List[Event]] = defaultdict(list)
    for e in events:
        if e.kind == "fail":
            by_user[e.user].append(e)
    alerts = []
    for user, evs in by_user.items():
        for s, t, peak in _bursts(evs, win, th["sources"], key_of=lambda e: e.src):
            burst = evs[s:t + 1]
            srcs = Counter()
            for e in burst:
                srcs[e.src] += e.count
            ratio = peak / th["sources"]
            countries = set()
            if ctx.resolver.enabled:
                for sv in srcs:
                    loc = ctx.resolver.lookup(sv)
                    if loc and loc.country:
                        countries.add(loc.country)
            sev = "high" if user in PRIVILEGED or ratio >= 2 else "medium"
            reason = (f"{_q(user)} failed to log in from {len(srcs)} different sources in "
                      f"{_dur(burst[-1].ts - burst[0].ts)} (limit: {int(th['sources'])} sources within "
                      f"{int(th['window_min'])} min). Rotating addresses like this dodges per-IP blocking.")
            if len(countries) > 1:
                reason += f" The sources span {len(countries)} countries: {', '.join(sorted(countries))}."
            alerts.append(Alert(
                "distributed_attack", RULE_INFO["distributed_attack"][0], sev, _confidence(ratio, 0.55),
                {"user": user}, burst[0].ts, burst[-1].ts, reason,
                {"distinct_sources": len(srcs), "attempts": sum(srcs.values()),
                 "countries": sorted(countries), "top_sources": [x for x, _ in srcs.most_common(10)]},
                dict(th), _refs(burst)))
    return alerts


def rule_success_after_failures(events: List[Event], ctx: Ctx) -> List[Alert]:
    th = ctx.th["success_after_failures"]
    look = timedelta(minutes=th["lookback_min"])
    fails_by_src: Dict[str, List[Event]] = defaultdict(list)
    fails_by_user: Dict[str, List[Event]] = defaultdict(list)
    for e in events:
        if e.kind == "fail":
            fails_by_src[e.src].append(e)
            fails_by_user[e.user].append(e)
    ts_src = {k: [e.ts for e in v] for k, v in fails_by_src.items()}
    ts_user = {k: [e.ts for e in v] for k, v in fails_by_user.items()}

    def window(lst: List[Event], tss: List, end) -> List[Event]:
        return lst[bisect.bisect_left(tss, end - look):bisect.bisect_right(tss, end)]

    alerts = []
    open_alert: Dict[Tuple[str, str], Alert] = {}
    for ok in (e for e in events if e.kind == "success"):
        prev = open_alert.get((ok.user, ok.src))
        if prev is not None and ok.ts - prev.last_seen <= look:
            # Same account and source logging in again on the back of the same burst:
            # extend the existing alert rather than raising a duplicate.
            prev.last_seen = ok.ts
            prev.evidence["logins"] = prev.evidence.get("logins", 1) + 1
            prev.lines = (prev.lines + _refs([ok]))[-12:]
            continue
        from_src = window(fails_by_src.get(ok.src, []), ts_src.get(ok.src, []), ok.ts)
        on_user = window(fails_by_user.get(ok.user, []), ts_user.get(ok.user, []), ok.ts)
        n_src = sum(e.count for e in from_src)
        n_user = sum(e.count for e in on_user)
        same_pair = sum(e.count for e in from_src if e.user == ok.user)
        best = max(n_src, n_user)
        if best < th["failures"]:
            continue
        ratio = best / th["failures"]
        if same_pair >= th["failures"]:
            sev = "critical"
            lead = (f"{_q(ok.user)} logged in from {ok.src}{ctx.where(ok.src)} after {same_pair} failed attempts "
                    f"on the same account from the same source in the previous {int(th['lookback_min'])} min. "
                    f"That pattern is what a guessed password looks like.")
        elif n_src >= n_user:
            sev = "high"
            n_users = len({e.user for e in from_src})
            lead = (f"{ok.src}{ctx.where(ok.src)} produced {n_src} failed logins across "
                    f"{_plural(n_users, 'account')} in the {int(th['lookback_min'])} min before it logged in "
                    f"successfully as {_q(ok.user)}.")
        else:
            sev = "high"
            n_srcs = len({e.src for e in on_user})
            lead = (f"{_q(ok.user)} had {n_user} failed logins from {_plural(n_srcs, 'source')} in the "
                    f"{int(th['lookback_min'])} min before this successful login from {ok.src}{ctx.where(ok.src)}.")
        reason = lead + f" (Limit: {int(th['failures'])} failures.)"
        if ok.method == "publickey" and sev != "critical":
            sev = "medium"
            reason += (" The login used a key, not a password, so the failures may be unrelated noise from a "
                       "shared address (NAT, VPN); confirm the key holder made it.")
        evidence_evs = (from_src if n_src >= n_user else on_user) + [ok]
        a = Alert(
            "success_after_failures", RULE_INFO["success_after_failures"][0], sev,
            _confidence(ratio, 0.7 if sev == "critical" else 0.6),
            {"user": ok.user, "src": ok.src}, (evidence_evs[0].ts if evidence_evs else ok.ts), ok.ts, reason,
            {"failures_from_source": n_src, "failures_on_account": n_user, "same_account_and_source": same_pair,
             "login_method": ok.method, "logins": 1},
            dict(th), _refs(evidence_evs[-12:]))
        alerts.append(a)
        open_alert[(ok.user, ok.src)] = a
    return alerts


def rule_impossible_travel(events: List[Event], ctx: Ctx) -> List[Alert]:
    if not ctx.resolver.enabled:
        return []
    th = ctx.th["impossible_travel"]
    by_user: Dict[str, List[Tuple[Event, Location]]] = defaultdict(list)
    for e in events:
        if e.kind != "success" or ctx.resolver.is_lan(e.src):
            continue
        loc = ctx.resolver.lookup(e.src)
        if loc and loc.has_coords:
            by_user[e.user].append((e, loc))
    alerts = []
    for user, seq in by_user.items():
        for (a, la), (b, lb) in zip(seq, seq[1:]):
            if a.src == b.src:
                continue
            km = haversine_km(la, lb)
            if km < th["min_km"]:
                continue
            hours = max((b.ts - a.ts).total_seconds() / 3600, 1 / 60)
            speed = km / hours
            if speed <= th["speed_kmh"]:
                continue
            ratio = speed / th["speed_kmh"]
            sev = "critical" if ratio >= 5 else "high"
            reason = (f"{_q(user)} logged in from {la.label()} ({a.src}) and then from {lb.label()} ({b.src}) "
                      f"{_dur(b.ts - a.ts)} later. The places are {km:,.0f} km apart, which needs "
                      f"{speed:,.0f} km/h; the limit is {int(th['speed_kmh']):,} km/h (airliner speed). "
                      f"Either the account is shared, a VPN changed exit point, the GeoIP data is wrong for one of the "
                      f"addresses (common for mobile and VPN ranges), or someone else has the credentials.")
            alerts.append(Alert(
                "impossible_travel", RULE_INFO["impossible_travel"][0], sev, _confidence(ratio, 0.6, k=0.6),
                {"user": user, "src": b.src, "prev_src": a.src}, a.ts, b.ts, reason,
                {"distance_km": round(km), "elapsed_min": round((b.ts - a.ts).total_seconds() / 60, 1),
                 "speed_kmh": round(speed), "from": la.label(), "to": lb.label()},
                dict(th), _refs([a, b])))
    return alerts


def _usual_hours(hours: List[int]) -> str:
    """Smallest circular window holding all of these hours, so night shifts read as e.g. 22:00-06:00."""
    present = sorted(set(hours))
    if len(present) == 24:
        return "log in at all hours"
    gaps = [((present[(i + 1) % len(present)] - present[i]) % 24 or 24, i) for i in range(len(present))]
    _, i = max(gaps)
    start, end = present[(i + 1) % len(present)], (present[i] + 1) % 24
    return f"usually log in between {start:02d}:00 and {end:02d}:00"


def rule_odd_hours(events: List[Event], ctx: Ctx) -> List[Alert]:
    th = ctx.th["odd_hours"]
    by_user: Dict[str, List[Event]] = defaultdict(list)
    for e in events:
        if e.kind == "success":
            by_user[e.user].append(e)
    qs, qe = int(th["quiet_start"]), int(th["quiet_end"])

    def quiet(h: int) -> bool:
        return qs <= h < qe if qs <= qe else (h >= qs or h < qe)

    alerts = []
    for user, evs in by_user.items():
        hours = [e.ts.astimezone(ctx.tz).hour for e in evs]
        hist = Counter(hours)
        for i, (e, h) in enumerate(zip(evs, hours)):
            others = len(evs) - 1
            if others >= th["min_history"]:
                near = sum(hist[(h + d) % 24] for d in (-1, 0, 1)) - 1      # exclude this login
                share = near / others
                if share > th["rare_share"]:
                    continue
                typical = _usual_hours(hours[:i] + hours[i + 1:])
                ratio = (th["rare_share"] + 0.01) / (share + 0.01)
                sev = "medium" if quiet(h) else "low"
                reason = (f"{_q(user)} logged in at {e.ts.astimezone(ctx.tz):%H:%M} from {e.src}{ctx.where(e.src)}. "
                          f"Of their {others} other logins in this data, {near} were within an hour of that time "
                          f"({share:.0%}; alerts at or below {th['rare_share']:.0%}). "
                          f"They {typical}.")
                conf = _confidence(ratio, 0.4, k=0.5) * min(1.0, 0.6 + others / 50)
                alerts.append(Alert(
                    "odd_hours", RULE_INFO["odd_hours"][0], sev, conf, {"user": user, "src": e.src},
                    e.ts, e.ts, reason,
                    {"hour": h, "history": others, "logins_near_hour": near, "share": round(share, 3),
                     "baseline": "per-user"}, dict(th), _refs([e])))
            elif quiet(h):
                reason = (f"{_q(user)} logged in at {e.ts.astimezone(ctx.tz):%H:%M}, inside the quiet hours "
                          f"{qs:02d}:00-{qe:02d}:00. There are only {others} other logins for this user, fewer than "
                          f"the {int(th['min_history'])} needed for a personal baseline, so this uses the fixed "
                          f"window instead and is low confidence.")
                alerts.append(Alert(
                    "odd_hours", RULE_INFO["odd_hours"][0], "low", 0.35, {"user": user, "src": e.src},
                    e.ts, e.ts, reason, {"hour": h, "history": others, "baseline": "quiet-hours fallback"},
                    dict(th), _refs([e])))
    return alerts


RULES = {
    "brute_force": rule_brute_force,
    "password_spray": rule_password_spray,
    "distributed_attack": rule_distributed_attack,
    "success_after_failures": rule_success_after_failures,
    "impossible_travel": rule_impossible_travel,
    "odd_hours": rule_odd_hours,
}


def run_rules(events: List[Event], resolver: Resolver, tz: timezone,
              thresholds: Dict[str, Dict[str, float]], enabled: Optional[Sequence[str]] = None) -> List[Alert]:
    ctx = Ctx(thresholds, resolver, tz)
    alerts: List[Alert] = []
    for name, fn in RULES.items():
        if enabled and name not in enabled:
            continue
        alerts.extend(fn(events, ctx))
    alerts.sort(key=lambda a: (-SEVERITIES.index(a.severity), -a.confidence, a.first_seen))
    return alerts
