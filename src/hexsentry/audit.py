"""Tamper-evident audit trail: which rule fired, on what data, with which settings.

Append-only JSON Lines. Each record stores the hash of the previous record,
and its own hash covers its content plus that link, so editing, deleting or
reordering any line breaks the chain from that point on. A small head file
(audit.head) records the latest sequence number and hash, so cutting records
off the end is caught too unless both files are rewritten together.

Set HEXSENTRY_AUDIT_KEY to switch from plain SHA-256 to HMAC-SHA256. Without
the key, someone who can rewrite the whole file can also rebuild the chain;
with it, they can't produce valid hashes, and verifying with the key set
rejects any record that isn't keyed. Tamper-evident, not tamper-proof:
ship the file somewhere append-only if that matters.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterator, Optional, Tuple

GENESIS = "0" * 64


class AuditError(Exception):
    pass


def head_path(path: Path) -> Path:
    return Path(path).with_suffix(".head")


def _key() -> Optional[bytes]:
    k = os.environ.get("HEXSENTRY_AUDIT_KEY")
    return k.encode("utf-8") if k else None


def _digest(body: Dict, key: Optional[bytes]) -> str:
    data = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")
    if key:
        return hmac.new(key, data, hashlib.sha256).hexdigest()
    return hashlib.sha256(data).hexdigest()


def _records(path: Path) -> Iterator[Tuple[int, Dict]]:
    with open(path, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            if line.strip():
                try:
                    yield n, json.loads(line)
                except ValueError as e:
                    raise AuditError(f"{path} line {n} is not valid JSON ({e}); "
                                     f"run `hexsentry audit verify`, then move the file aside") from None


class AuditLog:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.key = _key()
        self.prev, self.seq = GENESIS, 0
        if self.path.is_file() and self.path.stat().st_size:
            last = None
            for _, rec in _records(self.path):
                last = rec
            if last:
                self.prev, self.seq = last["hash"], last["seq"]

    def append(self, event: str, **data) -> Dict:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        body = {"seq": self.seq + 1, "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                "event": event, "data": data, "prev": self.prev, "keyed": bool(self.key)}
        rec = {**body, "hash": _digest(body, self.key)}
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
        self.prev, self.seq = rec["hash"], rec["seq"]
        head_path(self.path).write_text(json.dumps({"seq": self.seq, "hash": self.prev}) + "\n", encoding="utf-8")
        return rec


def verify(path: Path) -> Tuple[bool, int, str]:
    """Returns (ok, records_checked, message)."""
    path = Path(path)
    if not path.is_file():
        return False, 0, f"no audit log at {path}"
    key = _key()
    prev, count = GENESIS, 0
    try:
        for n, rec in _records(path):
            count += 1
            h = rec.pop("hash", None)
            if rec.get("prev") != prev:
                return False, count, f"line {n}: chain broken (record does not follow the previous one)"
            if rec.get("seq") != count:
                return False, count, f"line {n}: sequence {rec.get('seq')} expected {count} (record removed or reordered)"
            if rec.get("keyed") and not key:
                return False, count, f"line {n}: written with HEXSENTRY_AUDIT_KEY; set it to verify"
            if key and not rec.get("keyed"):
                return False, count, f"line {n}: not keyed, but HEXSENTRY_AUDIT_KEY is set (record forged or downgraded)"
            if _digest(rec, key if rec.get("keyed") else None) != h:
                return False, count, f"line {n}: hash mismatch (record edited, or wrong key)"
            prev = h
    except AuditError as e:
        return False, count, str(e)
    hp = head_path(path)
    if hp.is_file():
        try:
            head = json.loads(hp.read_text(encoding="utf-8"))
        except ValueError:
            return False, count, f"{hp.name} is not valid JSON"
        if head.get("seq") != count or head.get("hash") != prev:
            return False, count, (f"chain ends at record {count} but {hp.name} says {head.get('seq')}: "
                                  f"records were removed from the end, or the head file was edited")
    else:
        return True, count, f"{count} records, chain intact (no {hp.name}, so truncation can't be checked)"
    return True, count, f"{count} records, chain intact"


def tail(path: Path, n: int = 20):
    path = Path(path)
    if not path.is_file():
        return []
    recs = [r for _, r in _records(path)]
    return recs[-n:]
