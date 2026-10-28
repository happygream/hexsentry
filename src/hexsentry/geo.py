"""Offline IP geolocation from a CSV file, plus token-level locations for redacted logs.

Two ways to give hexsentry locations:

1. A GeoIP CSV (DB-IP Lite City, a GeoLite2-style 'network' CSV, or any CSV with
   start/end or network columns plus latitude/longitude). Used for raw IPs.
2. A token geo file made by `hexsentry geomap`. The data owner runs it once
   against the hexredact reverse map, so the analysis side only ever sees
   "<IPV4_PUB_ab12…> is roughly London, GB" and never the address itself.
"""

from __future__ import annotations

import bisect
import csv
import ipaddress
import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from .model import is_token, token_category


@dataclass(frozen=True)
class Location:
    country: str = ""
    city: str = ""
    lat: Optional[float] = None
    lon: Optional[float] = None

    @property
    def has_coords(self) -> bool:
        return self.lat is not None and self.lon is not None

    def label(self) -> str:
        parts = [p for p in (self.city, self.country) if p]
        if parts:
            return ", ".join(parts)
        if self.has_coords:
            return f"{self.lat:.1f},{self.lon:.1f}"
        return "unknown"


def haversine_km(a: Location, b: Location) -> float:
    r = 6371.0088
    p1, p2 = math.radians(a.lat), math.radians(b.lat)
    dp, dl = p2 - p1, math.radians(b.lon - a.lon)
    h = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(min(1.0, math.sqrt(h)))


class GeoError(Exception):
    pass


def _f(v: str) -> Optional[float]:
    try:
        return float(v) if v not in ("", None) else None
    except ValueError:
        return None


def _ip_int(v: str) -> Optional[Tuple[int, int]]:
    try:
        ip = ipaddress.ip_address(v.strip())
    except ValueError:
        return None
    if ip.version == 6 and ip.ipv4_mapped:      # ::ffff:203.0.113.5 from dual-stack sshd
        ip = ip.ipv4_mapped
    return ip.version, int(ip)


class GeoDB:
    """Range table with binary search. IPv4 and IPv6 kept in separate tables."""

    def __init__(self) -> None:
        self._rows: Dict[int, List[Tuple[int, int, Location]]] = {4: [], 6: []}
        self._starts: Dict[int, List[int]] = {4: [], 6: []}
        self._maxend: Dict[int, List[int]] = {4: [], 6: []}   # running max of range ends, for overlaps
        self.ranges = 0
        self.sources: List[str] = []

    def add(self, version: int, start: int, end: int, loc: Location) -> None:
        self._rows[version].append((start, end, loc))

    def finish(self) -> None:
        for v in (4, 6):
            self._rows[v].sort(key=lambda r: r[0])
            self._starts[v] = [r[0] for r in self._rows[v]]
            run, out = -1, []
            for r in self._rows[v]:
                run = max(run, r[1])
                out.append(run)
            self._maxend[v] = out
        self.ranges = len(self._rows[4]) + len(self._rows[6])

    def lookup(self, ip: str) -> Optional[Location]:
        parsed = _ip_int(ip)
        if not parsed:
            return None
        v, n = parsed
        i = bisect.bisect_right(self._starts[v], n) - 1
        best: Optional[Tuple[int, Location]] = None
        # Ranges can overlap when several files are combined: walk back while any
        # earlier range could still contain n, and keep the narrowest match.
        while i >= 0 and self._maxend[v][i] >= n:
            start, end, loc = self._rows[v][i]
            if n <= end and (best is None or end - start < best[0]):
                best = (end - start, loc)
            i -= 1
        return best[1] if best else None

    # ---- loading ----------------------------------------------------------
    def load_csv(self, path: str) -> int:
        p = Path(path)
        if not p.is_file():
            raise GeoError(f"GeoIP file not found: {path}")
        before = sum(len(r) for r in self._rows.values())
        with open(p, newline="", encoding="utf-8-sig", errors="replace") as fh:
            rows = csv.reader(fh)
            first = next(rows, None)
            if first is None:
                raise GeoError(f"GeoIP file is empty: {path}")
            if _ip_int(first[0]) or "/" in first[0] and _cidr(first[0]):
                self._load_headless(first, rows)
            else:
                self._load_headed([c.strip().lower() for c in first], rows, path)
        added = sum(len(r) for r in self._rows.values()) - before
        if not added:
            raise GeoError(f"no usable ranges in {path}")
        self.sources.append(p.name)
        self.finish()
        return added

    def _load_headless(self, first: List[str], rows: Iterable[List[str]]) -> None:
        # DB-IP Lite City:    start,end,continent,country,region,city,lat,lon
        # DB-IP Lite Country: start,end,country
        # Minimal custom:     start,end,country,lat,lon   or   network,country,lat,lon
        for row in _chain([first], rows):
            if not row:
                continue
            if "/" in row[0]:
                rng = _cidr(row[0])
                rest = row[1:]
            else:
                a, b = _ip_int(row[0]), _ip_int(row[1]) if len(row) > 1 else None
                rng = (a[0], a[1], b[1]) if a and b and a[0] == b[0] else None
                rest = row[2:]
            if not rng:
                continue
            if len(rest) >= 6:                       # DB-IP city
                loc = Location(rest[1], rest[3], _f(rest[4]), _f(rest[5]))
            elif len(rest) == 3:                     # country,lat,lon
                loc = Location(rest[0], "", _f(rest[1]), _f(rest[2]))
            elif len(rest) >= 1:
                loc = Location(rest[0])
            else:
                continue
            self.add(rng[0], rng[1], rng[2], loc)

    def _load_headed(self, head: List[str], rows: Iterable[List[str]], path: str) -> None:
        def col(*names: str) -> Optional[int]:
            for n in names:
                if n in head:
                    return head.index(n)
            return None
        c_net = col("network", "cidr", "prefix")
        c_start = col("ip_start", "start", "start_ip", "range_start", "from")
        c_end = col("ip_end", "end", "end_ip", "range_end", "to")
        c_lat = col("latitude", "lat")
        c_lon = col("longitude", "lon", "lng", "long")
        c_cc = col("country", "country_code", "country_iso_code", "cc", "registered_country_iso_code")
        c_city = col("city", "city_name")
        if c_net is None and (c_start is None or c_end is None):
            raise GeoError(f"{path}: need a 'network' column or 'start'/'end' columns")
        for row in rows:
            if not row:
                continue

            def g(i: Optional[int]) -> str:
                return row[i].strip() if i is not None and i < len(row) else ""
            if c_net is not None:
                rng = _cidr(g(c_net))
            else:
                a, b = _ip_int(g(c_start)), _ip_int(g(c_end))
                rng = (a[0], a[1], b[1]) if a and b and a[0] == b[0] else None
            if rng:
                self.add(rng[0], rng[1], rng[2], Location(g(c_cc), g(c_city), _f(g(c_lat)), _f(g(c_lon))))


def _chain(*its):
    for it in its:
        yield from it


def _cidr(v: str) -> Optional[Tuple[int, int, int]]:
    try:
        net = ipaddress.ip_network(v.strip(), strict=False)
    except ValueError:
        return None
    return net.version, int(net.network_address), int(net.broadcast_address)


# ---- token locations ------------------------------------------------------

def load_token_geo(path: str) -> Dict[str, Location]:
    out: Dict[str, Location] = {}
    with open(path, newline="", encoding="utf-8-sig") as fh:     # tolerate Excel's BOM
        for row in csv.DictReader(fh):
            tok = (row.get("token") or "").strip()
            if is_token(tok):
                out[tok] = Location(row.get("country", "").strip(), row.get("city", "").strip(),
                                    _f(row.get("lat", "")), _f(row.get("lon", "")))
    if not out:
        raise GeoError(f"no token locations in {path} (expected columns token,country,city,lat,lon)")
    return out


_LAN_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",   # RFC 1918 + carrier-grade NAT
    "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10")]


def _is_lan(ip: str) -> bool:
    """Internal addresses only. Deliberately narrower than ipaddress.is_private,
    which also counts the RFC 5737 documentation ranges used in examples."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if a.version == 6 and a.ipv4_mapped:
        a = a.ipv4_mapped
    return any(a in n for n in _LAN_NETS if n.version == a.version)


class Resolver:
    """Source -> Location, for raw IPs and hexredact tokens alike."""

    def __init__(self, db: Optional[GeoDB] = None, tokens: Optional[Dict[str, Location]] = None):
        self.db = db
        self.tokens = tokens or {}
        self._cache: Dict[str, Optional[Location]] = {}

    @property
    def enabled(self) -> bool:
        return bool(self.db) or bool(self.tokens)

    def is_lan(self, src: str) -> bool:
        cat = token_category(src)
        if cat:
            return cat.endswith("_PRIV") or cat.endswith("_LOOP")
        return _is_lan(src)

    def lookup(self, src: str) -> Optional[Location]:
        if src in self._cache:
            return self._cache[src]
        loc: Optional[Location] = None
        if is_token(src):
            loc = self.tokens.get(src)
        elif self.db and not _is_lan(src):
            loc = self.db.lookup(src)
        self._cache[src] = loc
        return loc


# ---- geomap: hexredact reverse map -> coarse token locations --------------

def _ip_pairs_from_map(doc) -> List[Tuple[str, str]]:
    """Find (token, ip) pairs in a hexredact map, or any JSON that maps tokens to values."""
    pairs: List[Tuple[str, str]] = []

    def ips_in(v) -> List[str]:
        found: List[str] = []
        if isinstance(v, str):
            if _ip_int(v):
                found.append(v.strip())
        elif isinstance(v, dict):
            for k in ("value", "original", "variants", "values"):
                if k in v:
                    found.extend(ips_in(v[k]))
        elif isinstance(v, list):
            for x in v:
                found.extend(ips_in(x))
        return found

    def walk(node) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                if is_token(k):
                    for ip in ips_in(v)[:1]:
                        pairs.append((k, ip))
                elif isinstance(v, str) and is_token(v) and _ip_int(k):
                    pairs.append((v, k.strip()))
                else:
                    walk(v)
            tok = node.get("token")
            if isinstance(tok, str) and is_token(tok):
                for ip in ips_in(node)[:1]:
                    pairs.append((tok, ip))
        elif isinstance(node, list):
            for x in node:
                walk(x)
    walk(doc)
    seen, uniq = set(), []
    for t, ip in pairs:
        if t not in seen:
            seen.add(t)
            uniq.append((t, ip))
    return uniq


def build_token_geo(map_path: str, db: GeoDB, precision: int = 1) -> Tuple[List[Dict[str, str]], Dict[str, int]]:
    """Rows of token,country,city,lat,lon. Coordinates rounded (1 dp is about 11 km)."""
    try:
        doc = json.loads(Path(map_path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise GeoError(f"cannot read map {map_path}: {e}") from e
    if isinstance(doc, dict) and "entries" not in doc and (
            "hexredact_encrypted" in doc or any(k in doc for k in ("ciphertext", "kdf", "tag"))):
        raise GeoError("this map is encrypted (hexredact --encrypt-map). geomap needs the plaintext map; "
                       "re-run the redaction without encryption on the data owner's side, run geomap, "
                       "then delete the plaintext map")
    pairs = _ip_pairs_from_map(doc)
    stats = {"ip_tokens": len(pairs), "located": 0, "lan": 0, "unknown": 0}
    rows: List[Dict[str, str]] = []
    for tok, ip in pairs:
        if _is_lan(ip):
            stats["lan"] += 1
            continue
        loc = db.lookup(ip)
        if not loc:
            stats["unknown"] += 1
            continue
        stats["located"] += 1
        rows.append({
            "token": tok, "country": loc.country, "city": loc.city,
            "lat": "" if loc.lat is None else f"{round(loc.lat, precision):.{precision}f}",
            "lon": "" if loc.lon is None else f"{round(loc.lon, precision):.{precision}f}",
        })
    if not pairs:
        raise GeoError(f"no IP tokens found in {map_path}")
    return rows, stats


def write_token_geo(rows: List[Dict[str, str]], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["token", "country", "city", "lat", "lon"])
        w.writeheader()
        w.writerows(rows)
