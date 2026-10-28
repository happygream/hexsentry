import unittest
from datetime import datetime, timezone

from hexsentry.parser import iter_events, parse_tz, ParseStats

NOW = datetime(2026, 10, 28, 12, 0, tzinfo=timezone.utc)


def parse(text, **kw):
    stats = ParseStats()
    evs = sorted(iter_events(text.strip().splitlines(), "t.log", now=NOW, stats=stats, **kw),
                 key=lambda e: (e.ts, e.line))
    return evs, stats


class ParserTests(unittest.TestCase):
    def test_classic_syslog_failure_and_success(self):
        evs, st = parse("""
Oct 28 03:14:07 web01 sshd[2211]: Failed password for root from 203.0.113.50 port 51122 ssh2
Oct 28 03:14:10 web01 sshd[2212]: Accepted publickey for alice from 198.51.100.10 port 50122 ssh2: ED25519 SHA256:abc
""")
        self.assertEqual([(e.kind, e.user, e.src, e.method) for e in evs],
                         [("fail", "root", "203.0.113.50", "password"),
                          ("success", "alice", "198.51.100.10", "publickey")])
        self.assertEqual(evs[0].ts, datetime(2026, 10, 28, 3, 14, 7, tzinfo=timezone.utc))
        self.assertEqual(st.unrecognised, 0)

    def test_iso_timestamps_and_sshd_session(self):
        evs, _ = parse("2026-10-28T03:14:12.123456+01:00 web01 sshd-session[2214]: "
                       "Failed password for bob from 10.0.0.12 port 4422 ssh2")
        self.assertEqual(evs[0].ts.utcoffset().total_seconds(), 3600)
        self.assertEqual(evs[0].user, "bob")

    def test_message_repeated_counts(self):
        evs, _ = parse("Oct 28 03:14:11 web01 sshd[2213]: message repeated 3 times: "
                       "[ Failed password for root from 203.0.113.50 port 4422 ssh2]")
        self.assertEqual(evs[0].count, 3)

    def test_invalid_user_not_double_counted(self):
        evs, _ = parse("""
Oct 28 03:14:07 web01 sshd[2211]: Invalid user oracle from 203.0.113.77 port 51122
Oct 28 03:14:09 web01 sshd[2211]: Failed password for invalid user oracle from 203.0.113.77 port 51122 ssh2
""")
        self.assertEqual(len(evs), 1)
        self.assertTrue(evs[0].invalid_user)

    def test_invalid_user_alone_still_counts(self):
        evs, _ = parse("Oct 28 03:14:07 web01 sshd[2211]: Invalid user oracle from 203.0.113.77 port 51122")
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0].kind, "fail")

    def test_hexredact_tokens(self):
        evs, st = parse("Oct 28 03:14:07 <HOST_947240476d> sshd[2211]: Failed password for invalid user "
                        "<USER_0547966c40> from <IPV4_PUB_3bf6c6d8de> port 51122 ssh2")
        self.assertEqual(evs[0].user, "<USER_0547966c40>")
        self.assertEqual(evs[0].src, "<IPV4_PUB_3bf6c6d8de>")
        self.assertTrue(st.tokens_seen)

    def test_year_rollover(self):
        evs, _ = parse("""
Dec 31 23:59:58 h sshd[1]: Failed password for root from 203.0.113.1 port 1 ssh2
Jan  1 00:00:02 h sshd[2]: Failed password for root from 203.0.113.1 port 1 ssh2
""", year=2025)
        self.assertEqual([e.ts.year for e in evs], [2025, 2026])

    def test_future_month_means_last_year(self):
        evs, _ = parse("Dec 30 10:00:00 h sshd[1]: Failed password for root from 203.0.113.1 port 1 ssh2")
        self.assertEqual(evs[0].ts.year, 2025)      # NOW is October 2026

    def test_noise_ignored_unknown_counted(self):
        _, st = parse("""
Oct 28 03:14:13 web01 sshd[2214]: Connection closed by authenticating user bob 10.0.0.12 port 4422 [preauth]
Oct 28 03:14:13 web01 sshd[2214]: pam_unix(sshd:auth): authentication failure; logname= uid=0
Oct 28 03:14:13 web01 sshd[2214]: Something brand new
Oct 28 03:14:13 web01 CRON[99]: pam_unix(cron:session): session opened
""")
        self.assertEqual(st.sshd_lines, 3)
        self.assertEqual(st.unrecognised, 1)

    def test_parse_tz(self):
        self.assertEqual(parse_tz("+01:00").utcoffset(None).total_seconds(), 3600)
        self.assertEqual(parse_tz("-0530").utcoffset(None).total_seconds(), -19800)
        with self.assertRaises(ValueError):
            parse_tz("Europe/London")


if __name__ == "__main__":
    unittest.main()
