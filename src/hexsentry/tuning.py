"""Analyst feedback: mark alerts benign or malicious and let the detector adapt.

Two effects, both explainable:

* Suppression. A benign mark on an alert suppresses future alerts with the
  same fingerprint (same rule, same user/source), e.g. the backup server
  that always fails twice before its key loads. Malicious marks are never
  suppressed and are shown as "confirmed".

* Threshold scaling. Each rule's tunable threshold is multiplied by
  0.5 / p, where p = (malicious + 2) / (malicious + benign + 4) is a smoothed
  precision estimate for that rule. No feedback: p = 0.5, multiplier 1.0.
  Mostly-benign marks raise the bar, mostly-malicious marks lower it.
  Clamped to 0.75 to 3.0 so one bad afternoon of clicking can't blind it.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .model import Alert
from .rules import DEFAULTS, TUNABLE

MIN_MULT, MAX_MULT = 0.75, 3.0
VERDICTS = ("benign", "malicious")


def default_state_dir() -> Path:
    env = os.environ.get("HEXSENTRY_HOME")
    return Path(env) if env else Path.home() / ".hexsentry"


class FeedbackStore:
    def __init__(self, state_dir: Path):
        self.dir = Path(state_dir)
        self.path = self.dir / "feedback.json"
        self.doc: Dict = {"version": 1, "verdicts": {}}
        if self.path.is_file():
            try:
                self.doc = json.loads(self.path.read_text(encoding="utf-8"))
            except ValueError:
                raise SystemExit(f"error: {self.path} is not valid JSON; fix or delete it") from None
        self.doc.setdefault("verdicts", {})

    def save(self) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.doc, indent=2), encoding="utf-8")
        os.replace(tmp, self.path)

    # ---- recording ------------------------------------------------------
    def record(self, alert: Dict, verdict: str, note: str = "") -> Dict:
        if verdict not in VERDICTS:
            raise ValueError(f"verdict must be one of {VERDICTS}")
        entry = {"verdict": verdict, "rule": alert["rule"], "fingerprint": alert["fingerprint"],
                 "entities": alert.get("entities", {}), "note": note,
                 "at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
        self.doc["verdicts"][alert["id"]] = entry
        return entry

    def forget(self, alert_id: str) -> Optional[Dict]:
        return self.doc["verdicts"].pop(alert_id, None)

    # ---- effects ----------------------------------------------------------
    def counts(self) -> Dict[str, Tuple[int, int]]:
        out = {r: [0, 0] for r in DEFAULTS}
        for v in self.doc["verdicts"].values():
            if v["rule"] in out:
                out[v["rule"]][0 if v["verdict"] == "benign" else 1] += 1
        return {r: (b, m) for r, (b, m) in out.items()}

    def multipliers(self) -> Dict[str, float]:
        mult = {}
        for rule, (b, m) in self.counts().items():
            p = (m + 2) / (m + b + 4)
            mult[rule] = round(min(MAX_MULT, max(MIN_MULT, 0.5 / p)), 3)
        return mult

    def fingerprints(self) -> Dict[str, str]:
        """fingerprint -> latest verdict."""
        latest: Dict[str, Tuple[str, str]] = {}
        for v in self.doc["verdicts"].values():
            prev = latest.get(v["fingerprint"])
            if prev is None or v["at"] >= prev[0]:
                latest[v["fingerprint"]] = (v["at"], v["verdict"])
        return {fp: verdict for fp, (_, verdict) in latest.items()}

    def apply(self, alerts: List[Alert]) -> int:
        fps = self.fingerprints()
        verdicts = self.doc["verdicts"]
        suppressed = 0
        for a in alerts:
            exact = verdicts.get(a.id)
            v = exact["verdict"] if exact else fps.get(a.fingerprint)
            if v:
                a.verdict = v
                if v == "benign":
                    a.suppressed = True
                    suppressed += 1
        return suppressed

    def explain(self) -> List[Dict]:
        rows = []
        mult = self.multipliers()
        for rule, (b, m) in self.counts().items():
            rows.append({"rule": rule, "threshold": TUNABLE[rule], "benign": b, "malicious": m,
                         "multiplier": mult[rule]})
        return rows


# ---- last scan, so feedback can refer to alert IDs --------------------------

def save_last_alerts(state_dir: Path, alerts: List[Alert]) -> None:
    state_dir.mkdir(parents=True, exist_ok=True)
    doc = {"saved": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "alerts": [a.to_dict() for a in alerts]}
    tmp = state_dir / "last_alerts.tmp"
    tmp.write_text(json.dumps(doc, indent=2, default=str), encoding="utf-8")
    os.replace(tmp, state_dir / "last_alerts.json")


def find_alert(state_dir: Path, alert_id: str, extra: Optional[str] = None) -> Dict:
    """Look an alert up by ID or unique ID prefix, in the last scan or a JSON report."""
    sources = [Path(extra)] if extra else []
    sources.append(state_dir / "last_alerts.json")
    for src in sources:
        if not src.is_file():
            continue
        alerts = json.loads(src.read_text(encoding="utf-8")).get("alerts", [])
        hits = [a for a in alerts if a["id"].startswith(alert_id.lower())]
        if len(hits) == 1:
            return hits[0]
        if len(hits) > 1:
            raise LookupError(f"'{alert_id}' matches {len(hits)} alerts; use more characters")
    raise LookupError(f"no alert '{alert_id}' in the last scan" + (f" or {extra}" if extra else "")
                      + ". Run a scan first, or pass --report with a hexsentry JSON report")
