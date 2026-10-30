"""Synthetic auth.log with two weeks of normal activity and six planted incidents.

Every address is from the RFC 5737 documentation ranges (192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24) and every name is made up, so the demo is
safe to publish, screenshot and run through hexredact.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Tuple

DEMO_GEOIP = """network,country,city,latitude,longitude
198.51.100.0/25,GB,London,51.5074,-0.1278
198.51.100.128/25,GB,Manchester,53.4808,-2.2426
192.0.2.0/25,US,New York,40.7128,-74.0060
192.0.2.128/25,AU,Sydney,-33.8688,151.2093
203.0.113.0/25,NL,Amsterdam,52.3676,4.9041
203.0.113.128/25,SG,Singapore,1.3521,103.8198
"""

HOST = "web01"
_B64 = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz0123456789"
OFFICE = {"alice": "198.51.100.10", "bob": "198.51.100.11", "carol": "198.51.100.140", "dave": "198.51.100.12"}

# What the demo should find, for the README and the tests.
EXPECTED = {
    "brute_force": {"src": "203.0.113.50", "user": "root"},
    "password_spray": {"src": "203.0.113.77"},
    "distributed_attack": {"user": "admin"},
    "success_after_failures": {"src": "192.0.2.200", "user": "deploy"},
    "impossible_travel": {"user": "alice"},
    "odd_hours": {"user": "bob"},
}


class _Log:
    def __init__(self, seed: int):
        self.rows: List[Tuple[datetime, str]] = []
        self.rng = random.Random(seed)
        self.pid = 4100

    def _p(self) -> int:
        self.pid += self.rng.randint(1, 37)
        return self.pid

    def add(self, ts: datetime, msg: str, pid: int = 0, prog: str = "sshd") -> None:
        self.rows.append((ts, f"{prog}[{pid or self._p()}]: {msg}"))

    def login(self, ts: datetime, user: str, src: str, method: str = "publickey") -> None:
        pid = self._p()
        port = self.rng.randint(40000, 65000)
        if method == "publickey":
            fp = "".join(self.rng.choice(_B64) for _ in range(43))
            self.add(ts, f"Accepted publickey for {user} from {src} port {port} ssh2: ED25519 SHA256:{fp}", pid)
        else:
            self.add(ts, f"Accepted password for {user} from {src} port {port} ssh2", pid)
        self.add(ts, f"pam_unix(sshd:session): session opened for user {user}(uid=1000) by {user}(uid=0)", pid)
        end = ts + timedelta(minutes=self.rng.randint(4, 90))
        self.add(end, f"Disconnected from user {user} {src} port {port}", pid)

    def fail(self, ts: datetime, user: str, src: str, invalid: bool = False, repeat: int = 1) -> None:
        pid = self._p()
        port = self.rng.randint(30000, 65000)
        if invalid:
            self.add(ts, f"Invalid user {user} from {src} port {port}", pid)
            self.add(ts + timedelta(seconds=2), f"Failed password for invalid user {user} from {src} port {port} ssh2", pid)
        else:
            self.add(ts, f"Failed password for {user} from {src} port {port} ssh2", pid)
            if repeat > 1:
                self.add(ts + timedelta(seconds=9),
                         f"message repeated {repeat - 1} times: [ Failed password for {user} from {src} port {port} ssh2]", pid)
        self.add(ts + timedelta(seconds=3), f"Connection closed by {'invalid' if invalid else 'authenticating'} "
                                            f"user {user} {src} port {port} [preauth]", pid)

    def render(self) -> str:
        self.rows.sort(key=lambda r: r[0])
        out = []
        for ts, body in self.rows:
            out.append(f"{ts.strftime('%Y-%m-%dT%H:%M:%S')}.{ts.microsecond:06d}+00:00 {HOST} {body}")
        return "\n".join(out) + "\n"


def generate(seed: int = 7, start: datetime = datetime(2026, 10, 12, tzinfo=timezone.utc)) -> str:
    log = _Log(seed)
    rng = log.rng

    # ---- two weeks of normal weekday logins, plus internet background noise ----
    for day in range(15):
        d = start + timedelta(days=day)
        if d.weekday() < 5:
            for user, src in OFFICE.items():
                for _ in range(rng.choice((1, 2, 2, 3))):
                    t = d + timedelta(hours=rng.uniform(8.5, 17.75))
                    if rng.random() < 0.08:                                    # fat-fingered password
                        log.fail(t - timedelta(seconds=20), user, src)
                    log.login(t.replace(microsecond=rng.randint(0, 999999)), user, src)
        for _ in range(rng.randint(2, 5)):                                    # scanners: a few tries each
            t = d + timedelta(seconds=rng.randint(0, 86399))
            src = f"203.0.113.{rng.randint(130, 250)}"
            for k in range(rng.randint(1, 3)):
                log.fail(t + timedelta(seconds=k * 7), rng.choice(("root", "admin", "test")), src,
                         invalid=rng.random() < 0.5)

    day = start + timedelta(days=15)              # 2026-10-27, incident day

    # 1. brute force on root from one address
    t = day + timedelta(hours=2, minutes=10)
    for k in range(18):
        log.fail(t + timedelta(seconds=k * 13), "root", "203.0.113.50", repeat=3 if k % 4 == 0 else 1)

    # 2. password spray: one address, many usernames, one or two tries each
    names = ["admin", "test", "oracle", "postgres", "ubuntu", "guest", "support", "ftpuser",
             "mysql", "jenkins", "alice", "bob", "git", "backup"]
    t = day + timedelta(hours=4)
    for k, name in enumerate(names):
        for j in range(1 + (k % 2)):
            log.fail(t + timedelta(seconds=k * 70 + j * 11), name,
                     "203.0.113.77", invalid=name not in OFFICE and name != "git")

    # 3. distributed attack on one account from rotating addresses
    t = day + timedelta(hours=5)
    for k in range(9):
        for j in range(2):
            log.fail(t + timedelta(minutes=k * 4, seconds=j * 20), "admin", f"192.0.2.{10 + k}", invalid=True)

    # 4. failures then success: a guessed password on a service account
    t = day + timedelta(hours=13, minutes=5)
    for k in range(8):
        log.fail(t + timedelta(seconds=k * 41), "deploy", "192.0.2.200")
    log.login(t + timedelta(minutes=6, seconds=12), "deploy", "192.0.2.200", method="password")

    # 5. impossible travel: London, then Sydney 29 minutes later
    log.login(day + timedelta(hours=9, minutes=2), "alice", OFFICE["alice"])
    log.login(day + timedelta(hours=9, minutes=31), "alice", "192.0.2.150", method="password")

    # 6. odd hours: bob, who only ever logs in during office hours, at 03:41
    log.login(day + timedelta(hours=3, minutes=41), "bob", OFFICE["bob"])

    # normal day for everyone else so the incidents sit in context
    for user in ("carol", "dave"):
        log.login(day + timedelta(hours=rng.uniform(9, 17)), user, OFFICE[user])

    return log.render()


def write_demo(out_dir: Path, seed: int = 7) -> Tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    log_path, geo_path = out_dir / "demo_auth.log", out_dir / "demo_geoip.csv"
    # bytes, not write_text(newline=...), which needs Python 3.10; keeps LF line endings on Windows
    log_path.write_bytes(generate(seed).encode("utf-8"))
    geo_path.write_bytes(DEMO_GEOIP.encode("utf-8"))
    return log_path, geo_path
