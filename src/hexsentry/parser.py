"""Parse OpenSSH authentication events from auth.log / secure / journal exports.

Works on raw logs and on hexredact output alike: users, hosts and source
addresses may be tokens such as <USER_0547966c40>; they are treated as opaque
identifiers, so the same person or address still correlates across lines.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

from .model import Event

MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}

_PROG = r"(?P<prog>sshd(?:-session|-auth)?)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$"
SYSLOG_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})(?:\.\d+)?\s+(?P<host>\S+)\s+" + _PROG)
ISO_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(?P<host>\S+)\s+" + _PROG)
ANY_SSHD_RE = re.compile(r"\bsshd(?:-session|-auth)?(?:\[\d+\])?:")

REPEAT_RE = re.compile(r"^message repeated (?P<n>\d+) times:\s*\[\s*(?P<msg>.*?)\s*\]\s*$")
# Usernames are attacker-controlled and may contain " from <ip> port N". The user group is
# greedy and the tail is anchored, so the source is always the *last* "from X port N" sshd wrote.
_TAIL = r" from (?P<src>\S+)(?: port (?:\d+|<[A-Z0-9_]+_[0-9a-f]+>))?(?: ssh\d?)?(?:: .*)?(?: \[preauth\])?\s*$"
FAILED_RE = re.compile(r"^Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>.*)" + _TAIL)
ACCEPTED_RE = re.compile(r"^Accepted (?P<method>\S+) for (?P<user>.*)" + _TAIL)
INVALID_RE = re.compile(r"^Invalid user (?P<user>.*)" + _TAIL)

# Lines that are sshd chatter, not an auth outcome. Recognised so the
# "unrecognised" counter stays meaningful.
NOISE_PREFIXES = (
    "Connection closed", "Connection reset", "Disconnected from", "Received disconnect",
    "pam_unix(", "PAM ", "Server listening", "Received signal", "error:", "fatal:",
    "Timeout before authentication", "banner exchange", "Unable to negotiate",
    "drop connection", "Did not receive identification", "Close session", "Starting session",
    "User child is on pid", "Postponed", "input_userauth_request", "maximum authentication",
    "Bad protocol version", "Protocol major versions differ", "kex_exchange_identification",
    "srclimit_penalise", "Connection from", "Accepted key", "Disconnecting", "Exiting on signal",
    "pam_systemd(", "pam_env(", "pam_lastlog(", "pam_motd(", "Invalid user  from",
)


@dataclass
class ParseStats:
    lines: int = 0
    sshd_lines: int = 0
    events: int = 0
    failures: int = 0
    successes: int = 0
    unrecognised: int = 0
    tokens_seen: bool = False
    files: List[Dict[str, object]] = field(default_factory=list)


def _parse_iso(s: str, default_tz: timezone) -> Optional[datetime]:
    s = s.replace(",", ".").replace(" ", "T", 1)
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    m = re.match(r"^(.*[+-]\d{2})(\d{2})$", s)        # +0000 -> +00:00
    if m and "T" in m.group(1):
        s = f"{m.group(1)}:{m.group(2)}"
    if "." in s:                                        # trim to microseconds
        head, _, tail = s.partition(".")
        frac = re.match(r"\d+", tail).group(0)
        s = f"{head}.{frac[:6].ljust(6, '0')}{tail[len(frac):]}"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=default_tz)


class _YearTracker:
    """Classic syslog has no year. Start from a reference year and roll over on Dec -> Jan."""

    def __init__(self, year: Optional[int], now: datetime):
        self.fixed = year is not None
        self.year = year if year is not None else now.year
        self.now = now
        self.last_month: Optional[int] = None

    def resolve(self, month: int, day: int) -> int:
        if self.last_month is None:
            if not self.fixed:
                # A first line dated more than a day ahead of now belongs to last year
                # (e.g. December lines read in January).
                first = datetime(self.year, month, min(day, 28), tzinfo=self.now.tzinfo)
                if first > self.now + timedelta(days=1):
                    self.year -= 1
        elif month < self.last_month - 6:
            self.year += 1
        self.last_month = month
        return self.year


class _HashTee(io.RawIOBase):
    """Passes bytes through and hashes them as read, so the SHA-256 in the report
    matches `sha256sum` of the file as stored (compressed bytes for .gz)."""

    def __init__(self, raw, digest, owns: bool = True):
        self.raw, self.digest, self.owns = raw, digest, owns

    def readable(self) -> bool:
        return True

    def readinto(self, b) -> int:
        data = self.raw.read(len(b))
        if not data:
            return 0
        n = len(data)
        b[:n] = data
        self.digest.update(data)
        return n

    def close(self) -> None:
        if self.owns and not self.closed:
            self.raw.close()
        super().close()


def _open_text(path: str, digest) -> Tuple[io.TextIOBase, str]:
    if path == "-":
        raw, label, owns = sys.stdin.buffer, "<stdin>", False
    else:
        raw, label, owns = open(path, "rb"), str(path), True
    stream = io.BufferedReader(_HashTee(raw, digest, owns))
    if path != "-" and Path(path).suffix == ".gz":
        stream = gzip.GzipFile(fileobj=stream, mode="rb")
    return io.TextIOWrapper(stream, encoding="utf-8", errors="replace"), label


def expand_inputs(paths: Iterable[str]) -> List[str]:
    """Directories expand to auth.log* / secure* files, oldest rotation first."""
    out: List[str] = []
    for raw in paths:
        if raw == "-":
            if raw not in out:                 # stdin can only be read once
                out.append(raw)
            continue
        if any(c in raw for c in "*?[") and not Path(raw).exists():
            import glob                        # Windows cmd doesn't expand wildcards
            out.extend(sorted(glob.glob(raw)) or [raw])
            continue
        p = Path(raw)
        if p.is_dir():
            found = [f for f in p.iterdir() if f.is_file() and
                     (f.name.startswith(("auth.log", "secure")) or f.suffix in (".log", ".gz", ".txt"))]

            def rot(f: Path) -> Tuple[int, str]:
                m = re.search(r"\.(\d+)(?:\.gz)?$", f.name)
                return (-(int(m.group(1))) if m else 0, f.name)
            out.extend(str(f) for f in sorted(found, key=rot))
        else:
            out.append(str(p))
    return out


def iter_events(lines: Iterable[str], source: str = "", *, year: Optional[int] = None,
                tz: timezone = timezone.utc, now: Optional[datetime] = None,
                stats: Optional[ParseStats] = None) -> Iterator[Event]:
    """Yield auth events from an iterable of log lines."""
    stats = stats if stats is not None else ParseStats()
    years = _YearTracker(year, now or datetime.now(tz))
    pending_invalid: Dict[Tuple[str, str, str], Event] = {}

    def flush() -> Iterator[Event]:
        for ev in pending_invalid.values():
            yield ev
        pending_invalid.clear()

    for n, line in enumerate(lines, 1):
        stats.lines += 1
        line = line.rstrip("\r\n")
        m = SYSLOG_RE.match(line)
        ts: Optional[datetime] = None
        if m:
            mon = MONTHS.get(m.group("mon"))
            if mon is None:
                continue
            hh, mm, ss = (int(x) for x in m.group("time").split(":"))
            day = int(m.group("day"))
            try:
                ts = datetime(years.resolve(mon, day), mon, day, hh, mm, ss, tzinfo=tz)
            except ValueError:                 # e.g. Feb 29 in a guessed non-leap year
                stats.sshd_lines += 1
                stats.unrecognised += 1
                continue
        else:
            m = ISO_RE.match(line)
            if m:
                ts = _parse_iso(m.group("ts"), tz)
        if m is None or ts is None:
            if ANY_SSHD_RE.search(line):
                stats.sshd_lines += 1
                stats.unrecognised += 1
            continue

        stats.sshd_lines += 1
        host, pid, msg = m.group("host"), m.group("pid") or "", m.group("msg")
        count = 1
        rep = REPEAT_RE.match(msg)
        if rep:
            count, msg = int(rep.group("n")), rep.group("msg")

        ev: Optional[Event] = None
        f = FAILED_RE.match(msg)
        if f:
            user = f.group("user").strip() or "(empty)"
            ev = Event(ts, "fail", user, f.group("src"), f.group("method"), bool(f.group("invalid")),
                       host, pid, count, source, n)
            # "Invalid user X" is usually followed by "Failed ... for invalid user X": count once.
            pending_invalid.pop((pid, user, ev.src), None)
        else:
            a = ACCEPTED_RE.match(msg)
            if a:
                ev = Event(ts, "success", a.group("user").strip() or "(empty)", a.group("src"), a.group("method"), False,
                           host, pid, count, source, n)
            else:
                i = INVALID_RE.match(msg)
                if i:
                    user = i.group("user").strip() or "(empty)"
                    # Held back: if no matching "Failed" line arrives (key-only servers), it still counts.
                    key = (pid, user, i.group("src"))
                    pending_invalid[key] = Event(ts, "fail", user, i.group("src"), "none", True,
                                                 host, pid, count, source, n)
                    if len(pending_invalid) > 256:
                        k0 = next(iter(pending_invalid))
                        yield pending_invalid.pop(k0)
                    continue
                if not msg.startswith(NOISE_PREFIXES):
                    stats.unrecognised += 1
                continue

        if "<" in ev.user or "<" in ev.src:
            stats.tokens_seen = True
        yield ev
    yield from flush()


def load_events(paths: Iterable[str], *, year: Optional[int] = None, tz: timezone = timezone.utc,
                now: Optional[datetime] = None) -> Tuple[List[Event], ParseStats]:
    stats = ParseStats()
    events: List[Event] = []
    for path in expand_inputs(paths):
        digest = hashlib.sha256()
        fh, label = _open_text(path, digest)
        before_lines = stats.lines
        try:
            name = os.path.basename(label) if path != "-" else label
            events.extend(iter_events(fh, name, year=year, tz=tz, now=now, stats=stats))
            while fh.buffer.read(65536):       # hash any bytes after the last full line
                pass
        finally:
            if path == "-":
                fh.detach()                    # leave sys.stdin usable
            else:
                fh.close()
        stats.files.append({"path": label if path == "-" else os.path.basename(label),
                            "sha256": digest.hexdigest(), "lines": stats.lines - before_lines})
    events.sort(key=lambda e: (e.ts, e.file, e.line))
    stats.events = len(events)
    stats.failures = sum(e.count for e in events if e.kind == "fail")
    stats.successes = sum(e.count for e in events if e.kind == "success")
    return events, stats


def parse_tz(spec: Optional[str]) -> timezone:
    """'UTC', '+01:00', '-0500' -> timezone. Only fixed offsets (stdlib, no tz database needed)."""
    if not spec or spec.upper() in ("UTC", "Z", "GMT"):
        return timezone.utc
    m = re.fullmatch(r"([+-])(\d{1,2}):?(\d{2})?", spec.strip())
    if not m:
        raise ValueError(f"timezone must be UTC or an offset like +01:00, got {spec!r}")
    delta = timedelta(hours=int(m.group(2)), minutes=int(m.group(3) or 0))
    return timezone(delta if m.group(1) == "+" else -delta)
