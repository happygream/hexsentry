import contextlib
import csv
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

from hexsentry.audit import AuditLog, verify
from hexsentry.cli import main
from hexsentry.demo import EXPECTED, write_demo
from hexsentry.geo import GeoDB, build_token_geo


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = main(list(argv))
    return rc, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)
        self.log, self.geo = write_demo(self.d / "demo")
        self.state = str(self.d / "state")

    def tearDown(self):
        self.tmp.cleanup()

    def scan(self, *extra):
        return run("scan", str(self.log), "--geoip", str(self.geo), "--state", self.state, "--no-color", *extra)

    def test_scan_terminal_json_csv(self):
        rc, out, _ = self.scan("--json", str(self.d / "r.json"), "--csv", str(self.d / "r.csv"))
        self.assertEqual(rc, 0)
        self.assertIn("6 alerts", out)
        doc = json.loads((self.d / "r.json").read_text())
        self.assertEqual(sorted(doc["summary"]["by_rule"]), sorted(EXPECTED))
        with open(self.d / "r.csv", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        self.assertEqual(len(rows), 6)
        self.assertTrue(all(r["reason"] for r in rows))

    def test_json_to_stdout_keeps_stdout_clean(self):
        rc, out, err = self.scan("--json", "-")
        self.assertEqual(json.loads(out)["tool"], "hexsentry")
        self.assertIn("alerts", err)

    def test_fail_on(self):
        self.assertEqual(self.scan("-q", "--fail-on", "critical")[0], 3)
        self.assertEqual(self.scan("-q", "--fail-on", "critical", "--rules", "brute_force")[0], 0)

    def test_feedback_suppresses_and_tunes(self):
        _, out, _ = self.scan("--json", str(self.d / "r.json"))
        doc = json.loads((self.d / "r.json").read_text())
        odd = next(a for a in doc["alerts"] if a["rule"] == "odd_hours")
        rc, out, _ = run("feedback", odd["id"][:6], "benign", "--state", self.state, "--no-color")
        self.assertEqual(rc, 0)
        self.assertIn("rare_share", out)
        _, out, _ = self.scan()
        self.assertIn("5 alerts", out)
        self.assertIn("1 suppressed", out)
        rc, _, _ = run("feedback", odd["id"], "--undo", "--state", self.state)
        self.assertEqual(rc, 0)
        self.assertIn("6 alerts", self.scan()[1])

    def test_feedback_unknown_id(self):
        self.scan()
        rc, _, err = run("feedback", "ffffffffffff", "benign", "--state", self.state)
        self.assertEqual(rc, 1)
        self.assertIn("no alert", err)

    def test_audit_chain(self):
        self.scan()
        rc, out, _ = run("audit", "verify", "--state", self.state, "--no-color")
        self.assertEqual(rc, 0, out)
        p = Path(self.state) / "audit.jsonl"
        lines = p.read_text().splitlines()
        lines[1] = lines[1].replace('"high"', '"low"').replace('"critical"', '"low"')
        p.write_text("\n".join(lines) + "\n")
        self.assertEqual(run("audit", "verify", "--state", self.state)[0], 1)

    def test_rules_listing(self):
        rc, out, _ = run("rules", "--state", self.state, "--no-color")
        self.assertEqual(rc, 0)
        self.assertIn("Impossible travel", out)

    def test_bad_rule_name(self):
        self.assertEqual(self.scan("--rules", "nope")[0], 2)

    def test_config_override(self):
        cfg = self.d / "c.json"
        cfg.write_text(json.dumps({"brute_force": {"failures": 100}}))
        _, out, _ = self.scan("--config", str(cfg))
        self.assertNotIn("Brute force", out)
        cfg.write_text(json.dumps({"brute_force": {"nope": 1}}))
        self.assertEqual(self.scan("--config", str(cfg))[0], 1)

    def test_no_sshd_lines_note(self):
        p = self.d / "empty.log"
        p.write_text("Oct 28 10:00:00 h CRON[1]: hello\n")
        _, out, _ = run("scan", str(p), "--no-state", "--no-color")
        self.assertIn("no sshd lines", out)


class PipelineTests(unittest.TestCase):
    """Redacted input: tokens in the log, locations from a geomap file, never an IP on the analysis side."""

    def test_geomap_and_scan_redacted(self):
        from hexsentry.demo import generate
        import hashlib
        import re

        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            _, geo = write_demo(d)
            entries = {}

            def tok(cat, value):
                t = f"<{cat}_{hashlib.sha256((cat + value).encode()).hexdigest()[:10]}>"
                entries[t] = {"category": cat, "value": value, "count": 1}
                return t
            text = generate()
            text = re.sub(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", lambda m: tok("IPV4_PUB", m.group(1)), text)
            text = re.sub(r"(for (?:invalid user )?|user )(alice|bob|carol|dave|deploy)\b",
                          lambda m: m.group(1) + tok("USER", m.group(2)), text)
            (d / "red.log").write_text(text)
            (d / "map.json").write_text(json.dumps({"tool": "hexredact", "entries": entries}))

            db = GeoDB()
            db.load_csv(str(geo))
            rows, stats = build_token_geo(str(d / "map.json"), db)
            self.assertEqual(stats["located"], stats["ip_tokens"])
            self.assertFalse(any(re.search(r"\d+\.\d+\.\d+\.\d+", ",".join(r.values())) for r in rows))

            rc, out, _ = run("geomap", str(d / "map.json"), "--geoip", str(geo), "-o", str(d / "tg.csv"))
            self.assertEqual(rc, 0)
            rc, out, _ = run("scan", str(d / "red.log"), "--token-geo", str(d / "tg.csv"), "--no-state",
                             "--no-color", "--json", str(d / "r.json"))
            doc = json.loads((d / "r.json").read_text())
            self.assertEqual(sorted(doc["summary"]["by_rule"]), sorted(EXPECTED))
            self.assertTrue(doc["stats"]["redacted_input"])
            self.assertNotRegex(json.dumps(doc["alerts"]), r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")

    def test_encrypted_map_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "m.json"
            p.write_text(json.dumps({"hexredact_encrypted": 1, "data": "x"}))
            rc, _, err = run("geomap", str(p), "--geoip", str(p))
            self.assertEqual(rc, 1)


class AuditUnitTests(unittest.TestCase):
    def test_keyed_chain(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "a.jsonl"
            os.environ["HEXSENTRY_AUDIT_KEY"] = "k1"
            try:
                log = AuditLog(p)
                log.append("x", a=1)
                AuditLog(p).append("y", b=2)                  # reopen continues the chain
                self.assertEqual(verify(p)[:2], (True, 2))
                os.environ["HEXSENTRY_AUDIT_KEY"] = "wrong"
                self.assertFalse(verify(p)[0])
            finally:
                os.environ.pop("HEXSENTRY_AUDIT_KEY", None)
            self.assertFalse(verify(p)[0])                  # keyed log, no key


if __name__ == "__main__":
    unittest.main()
