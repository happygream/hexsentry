"""Terminal, JSON and CSV output for a scan."""

from __future__ import annotations

import csv
import json
from collections import Counter
from typing import Dict, List, TextIO

from . import __version__
from .model import SEVERITIES, iso
from .scan import ScanResult
from .ui import Term, wrap


def _sev_badge(term: Term, sev: str) -> str:
    label = f" {sev.upper():<8} "
    colour = {"critical": "1;37;41", "high": "1;31", "medium": "1;33", "low": "1;36"}[sev]
    return term.c(colour, label)


def _bar(term: Term, conf: float, width: int = 10) -> str:
    n = round(conf * width)
    return term.g("█" * n + "░" * (width - n), "#" * n + "." * (width - n))


def _group_refs(refs: List[str], per_file: int = 8) -> str:
    """['a.log:5', 'a.log:7'] -> 'evidence a.log lines 5, 7'."""
    by_file: Dict[str, List[str]] = {}
    for r in refs:
        f, _, n = r.rpartition(":")
        by_file.setdefault(f, []).append(n)
    parts = []
    for f, nums in by_file.items():
        more = f" +{len(nums) - per_file} more" if len(nums) > per_file else ""
        parts.append(f"{f} line{'s' if len(nums) > 1 else ''} {', '.join(nums[:per_file])}{more}")
    return "evidence " + "; ".join(parts)


def render_terminal(term: Term, r: ScanResult, show_suppressed: bool = False, limit: int = 0) -> None:
    w = term.width
    rule = term.dim(term.g("─", "-") * w)
    s = r.stats
    term.say(term.bold(f"hexsentry {__version__}") + term.dim(f"  {term.g('·', '|')}  explainable SSH login anomaly detection"))
    term.say(rule)
    files = ", ".join(f["path"] for f in s.files) or "-"
    term.say(f"{term.dim('input   ')} {files}  {term.dim(f'({s.lines:,} lines, {s.sshd_lines:,} from sshd)')}")
    if r.span:
        term.say(f"{term.dim('period  ')} {iso(r.span[0])} {term.g('→', '->')} {iso(r.span[1])}")
    term.say(f"{term.dim('events  ')} {s.failures:,} failed, {s.successes:,} successful logins"
             + (term.dim("  · redacted input (hexredact tokens)" if term.uni else "  | redacted input")
                if s.tokens_seen else ""))
    if r.geo.get("sources_total"):
        term.say(f"{term.dim('geo     ')} {r.geo['sources_located']}/{r.geo['sources_total']} sources located")
    term.say(rule)

    shown = r.alerts if show_suppressed else r.visible
    if limit:
        shown = shown[:limit]
    if not shown:
        term.say(term.green("No alerts.") + (term.dim(f"  ({r.suppressed} suppressed as benign)") if r.suppressed else ""))
    for a in shown:
        head = (f"{_sev_badge(term, a.severity)} {term.bold(a.title)}  {term.dim(a.rule)}"
                f"  {term.dim('id')} {term.cyan(a.id)}")
        if a.verdict == "malicious":
            head += "  " + term.red("confirmed")
        elif a.suppressed:
            head += "  " + term.dim("suppressed (marked benign)")
        term.say(head)
        ents = "   ".join(f"{term.dim(k)} {v}" for k, v in a.entities.items())
        when = iso(a.first_seen) if a.first_seen == a.last_seen else f"{iso(a.first_seen)} {term.g('→', '->')} {iso(a.last_seen)}"
        term.say(f"           {ents}")
        term.say(f"           {term.dim('when')} {when}   {term.dim('confidence')} {_bar(term, a.confidence)} {a.confidence:.2f}")
        for ln in wrap(a.reason, w, "           "):
            term.say(ln)
        if a.lines:
            for ln in wrap(_group_refs(a.lines), w, "           "):
                term.say(term.dim(ln))
        term.say()

    term.say(rule)
    counts = Counter(a.severity for a in r.visible)
    colours = {"critical": "1;31", "high": "31", "medium": "33", "low": "36"}
    summary = "  ".join(term.c(colours[s_], f"{counts[s_]} {s_}") for s_ in reversed(SEVERITIES) if counts[s_])
    n = len(r.visible)
    term.say(f"{term.bold(str(n))} alert{'s' if n != 1 else ''}   {summary}"
             + (term.dim(f"   {r.suppressed} suppressed") if r.suppressed else "")
             + term.dim(f"   {r.seconds:.2f}s"))
    tuned = [t for t in r.tuning if t["benign"] or t["malicious"]]
    for t in tuned:
        base = r.thresholds[t["rule"]][t["threshold"]]
        term.say(term.dim(f"tuning  {t['rule']}: {t['threshold']} = {base} "
                          f"(x{t['multiplier']} from {t['benign']} benign / {t['malicious']} malicious marks)"))
    for n in r.notes:
        term.say(term.yellow("note    ") + n)
    if r.visible:
        term.say(term.dim("mark one: hexsentry feedback <id> benign|malicious"))


def to_json(r: ScanResult) -> Dict:
    return {
        "tool": "hexsentry", "version": __version__,
        "generated": iso(r.started),
        "inputs": r.stats.files,
        "period": [iso(r.span[0]), iso(r.span[1])] if r.span else None,
        "stats": {"lines": r.stats.lines, "sshd_lines": r.stats.sshd_lines, "events": r.stats.events,
                  "failures": r.stats.failures, "successes": r.stats.successes,
                  "unrecognised": r.stats.unrecognised, "redacted_input": r.stats.tokens_seen},
        "geo": r.geo,
        "thresholds": r.thresholds,
        "tuning": r.tuning,
        "summary": {"alerts": len(r.visible), "suppressed": r.suppressed,
                    "by_severity": dict(Counter(a.severity for a in r.visible)),
                    "by_rule": dict(Counter(a.rule for a in r.visible))},
        "alerts": [a.to_dict() for a in r.alerts],
        "notes": r.notes,
    }


def write_json(r: ScanResult, fh: TextIO) -> None:
    json.dump(to_json(r), fh, indent=2, ensure_ascii=False, default=str)
    fh.write("\n")


CSV_FIELDS = ["id", "rule", "title", "severity", "confidence", "user", "src", "prev_src",
              "first_seen", "last_seen", "duration_s", "suppressed", "verdict", "reason", "evidence"]


def write_csv(r: ScanResult, fh: TextIO) -> None:
    """One flat row per alert: loads straight into SAS Viya, Excel or pandas."""
    w = csv.DictWriter(fh, fieldnames=CSV_FIELDS, lineterminator="\n")
    w.writeheader()
    for a in r.alerts:
        w.writerow({
            "id": a.id, "rule": a.rule, "title": a.title, "severity": a.severity,
            "confidence": f"{a.confidence:.3f}", "user": a.entities.get("user", ""),
            "src": a.entities.get("src", ""), "prev_src": a.entities.get("prev_src", ""),
            "first_seen": iso(a.first_seen), "last_seen": iso(a.last_seen),
            "duration_s": int((a.last_seen - a.first_seen).total_seconds()),
            "suppressed": int(a.suppressed), "verdict": a.verdict or "", "reason": a.reason,
            "evidence": json.dumps(a.evidence, default=str, separators=(",", ":")),
        })
