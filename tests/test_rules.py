import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from hexsentry.demo import DEMO_GEOIP, EXPECTED, generate
from hexsentry.geo import GeoDB, Location, Resolver, _is_lan, haversine_km
from hexsentry.model import Event
from hexsentry.parser import iter_events
from hexsentry.rules import _bursts, effective_thresholds, run_rules

T0 = datetime(2026, 10, 27, 12, 0, tzinfo=timezone.utc)


def ev(sec, kind, user, src, **kw):
    return Event(T0 + timedelta(seconds=sec), kind, user, src, kw.pop("method", "password"), **kw)


def detect(events, resolver=None, **mult):
    return run_rules(sorted(events, key=lambda e: e.ts), resolver or Resolver(), timezone.utc,
                     effective_thresholds(mult))


def geo_resolver():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "g.csv"
        p.write_text(DEMO_GEOIP)
        db = GeoDB()
        db.load_csv(str(p))
    return Resolver(db)


class BurstTests(unittest.TestCase):
    def test_sum_and_split(self):
        evs = [ev(i * 10, "fail", "root", "a") for i in range(12)] + \
              [ev(5000 + i * 10, "fail", "root", "a") for i in range(12)]
        bursts = list(_bursts(evs, timedelta(minutes=10), 10))
        self.assertEqual(len(bursts), 2)
        self.assertEqual(bursts[0][2], 12)

    def test_counts_respected(self):
        evs = [ev(0, "fail", "root", "a", count=9), ev(5, "fail", "root", "a")]
        self.assertEqual(list(_bursts(evs, timedelta(minutes=1), 10))[0][2], 10)


class RuleTests(unittest.TestCase):
    def test_below_threshold_quiet(self):
        evs = [ev(i * 30, "fail", "root", "203.0.113.9") for i in range(9)]
        self.assertEqual(detect(evs), [])

    def test_brute_force(self):
        evs = [ev(i * 20, "fail", "root", "203.0.113.9") for i in range(15)]
        a = [x for x in detect(evs) if x.rule == "brute_force"]
        self.assertEqual(len(a), 1)
        self.assertEqual(a[0].severity, "high")             # root is privileged
        self.assertIn("limit is 10", a[0].reason)
        self.assertGreater(a[0].confidence, 0.6)

    def test_slow_attempts_spread_out_do_not_trip(self):
        evs = [ev(i * 120, "fail", "carol", "203.0.113.9") for i in range(15)]   # 1 per 2 min
        self.assertFalse([x for x in detect(evs) if x.rule == "brute_force"])

    def test_spray(self):
        evs = [ev(i * 60, "fail", f"user{i}", "203.0.113.9", invalid_user=True) for i in range(8)]
        a = [x for x in detect(evs) if x.rule == "password_spray"]
        self.assertEqual(a[0].title, "Password spraying")
        self.assertIn("8 of the 8 usernames", a[0].reason)

    def test_distributed(self):
        evs = [ev(i * 60, "fail", "admin", f"192.0.2.{i}") for i in range(6)]
        self.assertEqual([x.rule for x in detect(evs)], ["distributed_attack"])

    def test_success_after_failures_critical_for_same_pair(self):
        evs = [ev(i * 30, "fail", "deploy", "192.0.2.200") for i in range(6)]
        evs.append(ev(400, "success", "deploy", "192.0.2.200"))
        a = [x for x in detect(evs) if x.rule == "success_after_failures"]
        self.assertEqual(a[0].severity, "critical")

    def test_success_after_failures_downgraded_for_key_login(self):
        evs = [ev(i * 30, "fail", f"u{i}", "192.0.2.200") for i in range(6)]
        evs.append(ev(400, "success", "alice", "192.0.2.200", method="publickey"))
        a = [x for x in detect(evs) if x.rule == "success_after_failures"]
        self.assertEqual(a[0].severity, "medium")
        self.assertIn("used a key", a[0].reason)

    def test_impossible_travel_and_plausible_travel(self):
        r = geo_resolver()
        far = [ev(0, "success", "alice", "198.51.100.10"), ev(1800, "success", "alice", "192.0.2.150")]
        self.assertEqual([x.rule for x in detect(far, r)], ["impossible_travel"])
        slow = [ev(0, "success", "alice", "198.51.100.10"), ev(3600 * 30, "success", "alice", "192.0.2.150")]
        self.assertEqual(detect(slow, r), [])
        near = [ev(0, "success", "carol", "198.51.100.10"), ev(60, "success", "carol", "198.51.100.140")]
        self.assertEqual(detect(near, r), [])                # London -> Manchester, under min_km

    def test_impossible_travel_off_without_geo(self):
        far = [ev(0, "success", "alice", "198.51.100.10"), ev(1800, "success", "alice", "192.0.2.150")]
        self.assertEqual(detect(far), [])

    def test_odd_hours_with_baseline(self):
        evs = [ev(d * 86400 + 9 * 3600 - 12 * 3600 + 86400, "success", "bob", "198.51.100.11") for d in range(12)]
        evs.append(Event(datetime(2026, 11, 20, 3, 30, tzinfo=timezone.utc), "success", "bob", "198.51.100.11"))
        a = [x for x in detect(evs) if x.rule == "odd_hours"]
        self.assertEqual(len(a), 1)
        self.assertEqual(a[0].first_seen.hour, 3)

    def test_odd_hours_fallback_is_low(self):
        evs = [Event(datetime(2026, 11, 20, 2, 0, tzinfo=timezone.utc), "success", "eve", "198.51.100.11")]
        a = detect(evs)
        self.assertEqual((a[0].rule, a[0].severity), ("odd_hours", "low"))

    def test_tuning_raises_threshold(self):
        evs = [ev(i * 20, "fail", "carol", "203.0.113.9") for i in range(11)]
        self.assertTrue([x for x in detect(evs) if x.rule == "brute_force"])
        self.assertFalse([x for x in detect(evs, brute_force=1.5) if x.rule == "brute_force"])

    def test_ids_stable(self):
        evs = [ev(i * 20, "fail", "root", "203.0.113.9") for i in range(15)]
        self.assertEqual(detect(evs)[0].id, detect(evs)[0].id)


class DemoTests(unittest.TestCase):
    def test_demo_finds_exactly_the_planted_incidents(self):
        evs = sorted(iter_events(generate().splitlines(), "demo"), key=lambda e: e.ts)
        alerts = detect(evs, geo_resolver())
        self.assertEqual(sorted(a.rule for a in alerts), sorted(EXPECTED))
        for a in alerts:
            for k, v in EXPECTED[a.rule].items():
                self.assertEqual(a.entities[k], v, a.rule)


class GeoTests(unittest.TestCase):
    def test_lookup_and_distance(self):
        r = geo_resolver()
        lon, syd = r.lookup("198.51.100.10"), r.lookup("192.0.2.150")
        self.assertEqual((lon.city, syd.city), ("London", "Sydney"))
        self.assertAlmostEqual(haversine_km(lon, syd), 16994, delta=50)
        self.assertIsNone(r.lookup("10.1.2.3"))

    def test_dbip_headless_format(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "dbip.csv"
            p.write_text("203.0.113.0,203.0.113.255,EU,NL,North Holland,Amsterdam,52.37,4.89\n"
                         "2001:db8::,2001:db8::ffff,EU,DE,Berlin,Berlin,52.52,13.40\n")
            db = GeoDB()
            db.load_csv(str(p))
        self.assertEqual(db.lookup("203.0.113.9").city, "Amsterdam")
        self.assertEqual(db.lookup("2001:db8::1").country, "DE")

    def test_lan_excludes_documentation_ranges(self):
        self.assertTrue(_is_lan("192.168.1.5"))
        self.assertTrue(_is_lan("100.64.0.1"))
        self.assertFalse(_is_lan("203.0.113.5"))

    def test_token_lan_category(self):
        self.assertTrue(Resolver().is_lan("<IPV4_PRIV_8fe0eb3abc>"))
        self.assertFalse(Resolver().is_lan("<IPV4_PUB_8fe0eb3abc>"))

    def test_location_label(self):
        self.assertEqual(Location("GB", "London", 51.5, -0.1).label(), "London, GB")


if __name__ == "__main__":
    unittest.main()
