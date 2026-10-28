"""One scan, end to end: parse -> locate -> detect -> apply feedback -> audit."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from . import __version__
from .audit import AuditLog
from .geo import GeoDB, Resolver, load_token_geo
from .model import SEV_RANK, Alert
from .parser import ParseStats, load_events
from .rules import DEFAULTS, effective_thresholds, run_rules
from .tuning import FeedbackStore, save_last_alerts


@dataclass
class ScanOptions:
    inputs: Sequence[str]
    geoip: Sequence[str] = ()
    token_geo: Sequence[str] = ()
    tz: timezone = timezone.utc
    year: Optional[int] = None
    rules: Optional[Sequence[str]] = None
    config: Optional[str] = None
    state_dir: Optional[Path] = None          # None: no feedback, no audit, no last_alerts
    use_feedback: bool = True
    min_severity: str = "low"


@dataclass
class ScanResult:
    alerts: List[Alert]
    stats: ParseStats
    thresholds: Dict[str, Dict[str, float]]
    multipliers: Dict[str, float]
    tuning: List[Dict]
    geo: Dict[str, object]
    suppressed: int
    started: datetime
    seconds: float
    span: Optional[tuple] = None
    audit_path: Optional[str] = None
    notes: List[str] = field(default_factory=list)

    @property
    def visible(self) -> List[Alert]:
        return [a for a in self.alerts if not a.suppressed]


class ScanError(Exception):
    pass


def _load_config(path: Optional[str]) -> Dict[str, Dict[str, float]]:
    if not path:
        return {}
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise ScanError(f"cannot read config {path}: {e}") from e
    doc = doc.get("thresholds", doc)
    unknown = [r for r in doc if r not in DEFAULTS]
    if unknown:
        raise ScanError(f"config: unknown rule(s) {', '.join(unknown)}; known: {', '.join(DEFAULTS)}")
    for rule, vals in doc.items():
        bad = [k for k in vals if k not in DEFAULTS[rule]]
        if bad:
            raise ScanError(f"config: {rule} has no setting {', '.join(bad)}; "
                            f"known: {', '.join(DEFAULTS[rule])}")
    return doc


def run_scan(opt: ScanOptions) -> ScanResult:
    t0, started = time.perf_counter(), datetime.now(timezone.utc)
    overrides = _load_config(opt.config)

    db = None
    if opt.geoip:
        db = GeoDB()
        for p in opt.geoip:
            db.load_csv(p)
    tokens: Dict = {}
    for p in opt.token_geo:
        tokens.update(load_token_geo(p))
    resolver = Resolver(db, tokens)

    try:
        events, stats = load_events(opt.inputs, year=opt.year, tz=opt.tz)
    except FileNotFoundError as e:
        raise ScanError(f"input not found: {e.filename}") from e
    except IsADirectoryError as e:
        raise ScanError(f"cannot read {e.filename}") from e

    store = FeedbackStore(opt.state_dir) if (opt.state_dir and opt.use_feedback) else None
    mult = store.multipliers() if store else {r: 1.0 for r in DEFAULTS}
    th = effective_thresholds(mult, overrides)
    alerts = run_rules(events, resolver, opt.tz, th, opt.rules)
    floor = SEV_RANK[opt.min_severity]
    alerts = [a for a in alerts if SEV_RANK[a.severity] >= floor]
    suppressed = store.apply(alerts) if store else 0

    notes: List[str] = []
    if stats.sshd_lines == 0:
        notes.append("no sshd lines found. Is this an auth.log / secure file, or a journalctl -u ssh export?")
    elif stats.events == 0:
        notes.append("sshd lines found, but no login successes or failures in them")
    if resolver.enabled is False:
        notes.append("no --geoip or --token-geo given, so impossible travel is off and sources show no location")
    elif stats.tokens_seen and not tokens:
        notes.append("input contains hexredact tokens but no --token-geo file, so redacted sources "
                     "have no location (see `hexsentry geomap`)")
    if stats.unrecognised:
        notes.append(f"{stats.unrecognised} sshd line(s) were not recognised and were skipped")

    located = sum(1 for s in {e.src for e in events} if resolver.lookup(s))
    geo = {"geoip_files": [Path(p).name for p in opt.geoip], "geoip_ranges": db.ranges if db else 0,
           "token_locations": len(tokens), "sources_located": located,
           "sources_total": len({e.src for e in events})}

    span = (events[0].ts, events[-1].ts) if events else None
    result = ScanResult(alerts, stats, th, mult, store.explain() if store else [], geo, suppressed,
                        started, time.perf_counter() - t0, span, notes=notes)

    if opt.state_dir:
        save_last_alerts(Path(opt.state_dir), alerts)
        audit = AuditLog(Path(opt.state_dir) / "audit.jsonl")
        result.audit_path = str(audit.path)
        audit.append("scan_started", version=__version__, inputs=stats.files,
                     events=stats.events, thresholds=th, multipliers=mult,
                     geo=geo, rules=list(opt.rules or DEFAULTS))
        for a in alerts:
            audit.append("alert_suppressed" if a.suppressed else "alert_raised",
                         id=a.id, rule=a.rule, severity=a.severity, confidence=round(a.confidence, 3),
                         entities=a.entities, reason=a.reason, thresholds=a.thresholds, lines=a.lines,
                         verdict=a.verdict)
        audit.append("scan_finished", alerts=len(alerts), suppressed=suppressed,
                     seconds=round(result.seconds, 3))
    return result
