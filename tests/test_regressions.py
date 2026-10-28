"""One test per issue found in review, so none of them can come back."""

import contextlib
import gzip
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from hexsentry.audit import AuditLog, verify
from hexsentry.cli import main
from hexsentry.geo import GeoDB, Location, Resolver, load_token_geo
from hexsentry.model import Event
from hexsentry.parser import ParseStats, iter_events, load_events
from hexsentry.rules import _usual_hours, effective_thresholds, run_rules

NOW = datetime(2026, 10, 28, 12, 0, tzinfo=timezone.utc)
SRC = str(Path(__file__).resolve().parents[1] / "src")


def parse(text, **kw):
    return sorted(iter_events(text.strip().splitlines(), "t", now=kw.pop("now", NOW), **kw), key=lambda e: e.ts)


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = main(list(argv))
    return rc, out.getvalue(), err.getvalue()


class InjectionTests(unittest.TestCase):
    def test_username_cannot_choose_the_source(self):
        evs = parse("Oct 28 03:14:09 h sshd[7]: Failed password for invalid user x from 8.8.8.8 port 1 "
                    "from 6.6.6.1 port 2222 ssh2")
        self.assertEqual((evs[0].user, evs[0].src), ("x from 8.8.8.8 port 1", "6.6.6.1"))

    def test_injected_invalid_user_pair_counted_once(self):
        evs = parse("""
Oct 28 03:14:08 h sshd[7]: Invalid user x from 8.8.8.8 port 1 from 6.6.6.1 port 2222
Oct 28 03:14:09 h sshd[7]: Failed password for invalid user x from 8.8.8.8 port 1 from 6.6.6.1 port 2222 ssh2
""")
        self.assertEqual([(e.src, e.count) for e in evs], [("6.6.6.1", 1)])

    def test_injected_accepted_line(self):
        evs = parse("Oct 28 03:14:09 h sshd[7]: Accepted password for bob from 9.9.9.9 port 1 ssh2: x "
                    "from 6.6.6.1 port 2222 ssh2")
        self.assertEqual(evs[0].src, "6.6.6.1")

    def test_publickey_suffix_and_preauth_still_parse(self):
        evs = parse("""
Oct 28 03:14:09 h sshd[7]: Failed publickey for alice from 203.0.113.4 port 22 ssh2: RSA SHA256:abc
Oct 28 03:14:10 h sshd[8]: Failed none for invalid user zz from 203.0.113.4 port 23 ssh2 [preauth]
""")
        self.assertEqual([(e.user, e.src) for e in evs], [("alice", "203.0.113.4"), ("zz", "203.0.113.4")])


class DuplicateAlertTests(unittest.TestCase):
    def test_repeat_logins_extend_one_alert(self):
        t0 = datetime(2026, 10, 27, 12, tzinfo=timezone.utc)
        evs = [Event(t0 + timedelta(seconds=i * 20), "fail", "deploy", "192.0.2.9") for i in range(6)]
        evs += [Event(t0 + timedelta(minutes=5 + i), "success", "deploy", "192.0.2.9", "password") for i in range(3)]
        a = [x for x in run_rules(evs, Resolver(), timezone.utc, effective_thresholds())
             if x.rule == "success_after_failures"]
        self.assertEqual(len(a), 1)
        self.assertEqual(a[0].evidence["logins"], 3)
        self.assertEqual(a[0].last_seen, t0 + timedelta(minutes=7))


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.p = Path(self.tmp.name) / "audit.jsonl"

    def tearDown(self):
        os.environ.pop("HEXSENTRY_AUDIT_KEY", None)
        self.tmp.cleanup()

    def test_unkeyed_record_rejected_when_key_set(self):
        os.environ["HEXSENTRY_AUDIT_KEY"] = "secret"
        AuditLog(self.p).append("a", x=1)
        # attacker without the key rebuilds the file as an unkeyed chain
        os.environ.pop("HEXSENTRY_AUDIT_KEY")
        self.p.unlink()
        AuditLog(self.p).append("a", x=999)
        os.environ["HEXSENTRY_AUDIT_KEY"] = "secret"
        ok, _, msg = verify(self.p)
        self.assertFalse(ok)
        self.assertIn("not keyed", msg)

    def test_truncation_detected(self):
        log = AuditLog(self.p)
        for i in range(4):
            log.append("e", i=i)
        lines = self.p.read_text().splitlines()
        self.p.write_text("\n".join(lines[:2]) + "\n")
        ok, _, msg = verify(self.p)
        self.assertFalse(ok)
        self.assertIn("removed from the end", msg)

    def test_corrupt_log_is_an_error_not_a_traceback(self):
        self.p.write_text("{not json\n")
        rc, _, err = run("audit", "verify", "--file", str(self.p))
        self.assertEqual(rc, 1)
        rc, _, err = run("scan", str(Path(__file__)), "--state", self.tmp.name)
        self.assertEqual(rc, 1)
        self.assertIn("not valid JSON", err)


class OutputTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)
        from hexsentry.demo import write_demo
        self.log, self.geo = write_demo(self.d)

    def tearDown(self):
        self.tmp.cleanup()

    def test_csv_on_stdout_is_pure_csv(self):
        rc, out, err = run("scan", str(self.log), "--no-state", "--csv", "-", "--json", str(self.d / "r.json"))
        self.assertTrue(out.startswith("id,rule,"), out[:80])
        self.assertIn("json ", err)

    def test_json_on_stdout_is_pure_json(self):
        rc, out, err = run("scan", str(self.log), "--no-state", "--json", "-", "--csv", str(self.d / "r.csv"))
        json.loads(out)
        self.assertIn("csv ", err)

    def test_stdout_is_utf8_on_cp1252_consoles(self):
        p = self.d / "odd.log"
        p.write_bytes(b"Oct 28 03:14:07 h sshd[1]: Failed password for invalid user \xff\xfe from 203.0.113.9 port 1 ssh2\n")
        env = dict(os.environ, PYTHONPATH=SRC, PYTHONIOENCODING="cp1252")
        r = subprocess.run([sys.executable, "-m", "hexsentry", "scan", str(p), "--no-state", "--json", "-"],
                           capture_output=True, env=env)
        self.assertEqual(r.returncode, 0, r.stderr.decode(errors="replace"))
        self.assertEqual(json.loads(r.stdout.decode("utf-8"))["stats"]["failures"], 1)


class HashTests(unittest.TestCase):
    def test_sha256_matches_file_bytes_crlf_and_gz(self):
        with tempfile.TemporaryDirectory() as d:
            raw = b"Oct 28 03:14:07 h sshd[1]: Failed password for root from 203.0.113.9 port 1 ssh2\r\n" * 3
            p = Path(d) / "crlf.log"
            p.write_bytes(raw)
            g = Path(d) / "x.log.gz"
            g.write_bytes(gzip.compress(raw))
            evs, st = load_events([str(p), str(g)], now=NOW)
            self.assertEqual(st.files[0]["sha256"], hashlib.sha256(raw).hexdigest())
            self.assertEqual(st.files[1]["sha256"], hashlib.sha256(g.read_bytes()).hexdigest())
            self.assertEqual(len(evs), 6)

    def test_stdin_listed_twice_reads_once(self):
        env = dict(os.environ, PYTHONPATH=SRC)
        line = b"Oct 28 03:14:07 h sshd[1]: Failed password for root from 203.0.113.9 port 1 ssh2\n"
        r = subprocess.run([sys.executable, "-m", "hexsentry", "scan", "-", "-", "--no-state", "--json", "-"],
                           input=line, capture_output=True, env=env)
        self.assertEqual(r.returncode, 0, r.stderr.decode())
        self.assertEqual(json.loads(r.stdout)["stats"]["failures"], 1)


class GeoTests(unittest.TestCase):
    def test_ipv4_mapped_source_located(self):
        db = GeoDB()
        db.add(4, 0xCB007100, 0xCB0071FF, Location("NL", "Amsterdam", 52.4, 4.9))
        db.finish()
        self.assertEqual(Resolver(db).lookup("::ffff:203.0.113.5").city, "Amsterdam")

    def test_overlapping_ranges_prefer_narrowest(self):
        db = GeoDB()
        db.add(4, 0, 100, Location("A"))
        db.add(4, 10, 20, Location("B"))
        db.finish()
        self.assertEqual(db.lookup("0.0.0.50").country, "A")
        self.assertEqual(db.lookup("0.0.0.15").country, "B")

    def test_excel_bom(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "g.csv"
            p.write_text("network,country,city,latitude,longitude\n203.0.113.0/24,NL,Amsterdam,52.4,4.9\n",
                         encoding="utf-8-sig")
            db = GeoDB()
            db.load_csv(str(p))
            self.assertEqual(db.lookup("203.0.113.1").city, "Amsterdam")
            t = Path(d) / "t.csv"
            t.write_text("token,country,city,lat,lon\n<IPV4_PUB_0123456789>,GB,London,51.5,-0.1\n",
                         encoding="utf-8-sig")
            self.assertEqual(len(load_token_geo(str(t))), 1)


class ParserEdgeTests(unittest.TestCase):
    def test_first_line_ahead_of_now_is_last_year(self):
        evs = parse("Nov  2 10:00:00 h sshd[1]: Failed password for root from 203.0.113.1 port 1 ssh2")
        self.assertEqual(evs[0].ts.year, 2025)

    def test_new_years_eve_is_not_pushed_back(self):
        nye = datetime(2026, 12, 31, 23, 0, tzinfo=timezone.utc)
        evs = parse("Dec 31 22:00:00 h sshd[1]: Failed password for root from 203.0.113.1 port 1 ssh2", now=nye)
        self.assertEqual(evs[0].ts.year, 2026)

    def test_feb29_in_non_leap_year_is_counted(self):
        st = ParseStats()
        list(iter_events(["Feb 29 10:00:00 h sshd[1]: Failed password for root from 203.0.113.1 port 1 ssh2"],
                         year=2025, stats=st))
        self.assertEqual(st.unrecognised, 1)

    def test_windows_style_glob(self):
        from hexsentry.parser import expand_inputs
        with tempfile.TemporaryDirectory() as d:
            for n in ("auth.log", "auth.log.1"):
                (Path(d) / n).write_text("")
            self.assertEqual(len(expand_inputs([str(Path(d) / "auth.log*")])), 2)


class WordingTests(unittest.TestCase):
    def test_usual_hours(self):
        self.assertEqual(_usual_hours([9, 10, 17]), "usually log in between 09:00 and 18:00")
        self.assertEqual(_usual_hours([23, 23]), "usually log in between 23:00 and 00:00")
        self.assertEqual(_usual_hours([22, 23, 0, 1, 5]), "usually log in between 22:00 and 06:00")

    def test_threshold_override_of_one_kept(self):
        self.assertEqual(effective_thresholds(overrides={"brute_force": {"failures": 1}})["brute_force"]["failures"], 1)


if __name__ == "__main__":
    unittest.main()
