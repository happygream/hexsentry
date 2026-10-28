"""Core data types shared by the parser, rules and reports."""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# hexredact token shape: <CATEGORY_hexdigest>, e.g. <USER_0547966c40>, <IPV4_PUB_3f9a2c1b07>
TOKEN_RE = re.compile(r"^<([A-Z][A-Z0-9_]*)_([0-9a-f]{6,32})>$")

SEVERITIES = ["low", "medium", "high", "critical"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}


def is_token(value: Optional[str]) -> bool:
    return bool(value) and bool(TOKEN_RE.match(value))


def token_category(value: Optional[str]) -> Optional[str]:
    m = TOKEN_RE.match(value or "")
    return m.group(1) if m else None


def iso(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Event:
    """One authentication outcome from sshd."""
    ts: datetime                 # timezone-aware
    kind: str                    # "fail" | "success"
    user: str
    src: str                     # IP address or hexredact token
    method: str = ""             # password, publickey, keyboard-interactive/pam, none
    invalid_user: bool = False
    host: str = ""
    pid: str = ""
    count: int = 1               # >1 for "message repeated N times"
    file: str = ""
    line: int = 0


@dataclass
class Alert:
    rule: str
    title: str
    severity: str
    confidence: float
    entities: Dict[str, str]
    first_seen: datetime
    last_seen: datetime
    reason: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    thresholds: Dict[str, Any] = field(default_factory=dict)
    lines: List[str] = field(default_factory=list)      # "file:line" references
    suppressed: bool = False
    verdict: Optional[str] = None                       # from analyst feedback

    @property
    def fingerprint(self) -> str:
        """Stable across runs: the rule plus who/what it is about, no timestamps."""
        ents = "|".join(f"{k}={self.entities[k]}" for k in sorted(self.entities))
        return f"{self.rule}|{ents}"

    @property
    def id(self) -> str:
        raw = f"{self.fingerprint}|{iso(self.first_seen)}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d = {"id": self.id, "fingerprint": self.fingerprint, **d}
        d["first_seen"] = iso(self.first_seen)
        d["last_seen"] = iso(self.last_seen)
        d["confidence"] = round(self.confidence, 3)
        return d
