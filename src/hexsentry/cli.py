"""Command line and interactive menu."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__
from .audit import AuditError, AuditLog, tail, verify
from .geo import GeoDB, GeoError, build_token_geo, write_token_geo
from .model import SEVERITIES, SEV_RANK
from .parser import parse_tz
from .report import render_terminal, write_csv, write_json
from .rules import DEFAULTS, RULE_INFO, TUNABLE, effective_thresholds
from .scan import ScanError, ScanOptions, run_scan
from .tuning import VERDICTS, FeedbackStore, default_state_dir, find_alert
from . import ui

EXIT_OK, EXIT_ERR, EXIT_USAGE, EXIT_ALERTS = 0, 1, 2, 3


def _state(args) -> Optional[Path]:
    if getattr(args, "no_state", False):
        return None
    return Path(args.state) if getattr(args, "state", None) else default_state_dir()


# ---- scan -------------------------------------------------------------------

def _open_out(path: str):
    if path == "-":
        import contextlib
        try:
            sys.stdout.reconfigure(encoding="utf-8")   # Windows redirects default to cp1252
        except (AttributeError, ValueError):
            pass
        return contextlib.nullcontext(sys.stdout)      # never close stdout
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    return open(path, "w", encoding="utf-8", newline="")


def cmd_scan(args, term: ui.Term) -> int:
    inputs = args.paths or []
    if not inputs:
        if sys.stdin.isatty():
            term.err("give a log file or directory, or pipe one in (e.g. hexredact redact - --map m.json < auth.log | hexsentry scan)")
            return EXIT_USAGE
        inputs = ["-"]
    if "-" in (args.json, args.csv) and args.json == args.csv:
        term.err("--json and --csv can't both write to stdout")
        return EXIT_USAGE
    rules = None
    if args.rules:
        rules = [r.strip() for r in args.rules.split(",") if r.strip()]
        bad = [r for r in rules if r not in DEFAULTS]
        if bad:
            term.err(f"unknown rule(s): {', '.join(bad)}. Known: {', '.join(DEFAULTS)}")
            return EXIT_USAGE
    try:
        tz = parse_tz(args.tz)
    except ValueError as e:
        term.err(str(e))
        return EXIT_USAGE
    opt = ScanOptions(inputs, args.geoip or [], args.token_geo or [], tz, args.year, rules, args.config,
                      _state(args), not args.no_feedback, args.min_severity)
    try:
        result = run_scan(opt)
    except (ScanError, GeoError, AuditError) as e:
        term.err(str(e))
        return EXIT_ERR

    machine_on_stdout = "-" in (args.json, args.csv)
    # with JSON or CSV on stdout, every human-readable line goes to stderr
    view = ui.Term(sys.stderr, color=False if args.no_color else None) if machine_on_stdout else term
    if not args.quiet:
        render_terminal(view, result, args.show_suppressed, args.limit)
    if args.json:
        with _open_out(args.json) as fh:
            write_json(result, fh)
        if args.json != "-" and not args.quiet:
            view.say(view.dim(f"json    {args.json}"))
    if args.csv:
        with _open_out(args.csv) as fh:
            write_csv(result, fh)
        if args.csv != "-" and not args.quiet:
            view.say(view.dim(f"csv     {args.csv}"))
    if args.fail_on:
        floor = SEV_RANK[args.fail_on]
        if any(SEV_RANK[a.severity] >= floor for a in result.visible):
            return EXIT_ALERTS
    return EXIT_OK


# ---- feedback ---------------------------------------------------------------

def cmd_feedback(args, term: ui.Term) -> int:
    state = _state(args) or default_state_dir()
    store = FeedbackStore(state)
    if args.undo:
        gone = store.forget(args.alert_id)
        if not gone:
            hits = [k for k in store.doc["verdicts"] if k.startswith(args.alert_id)]
            gone = store.forget(hits[0]) if len(hits) == 1 else None
        if not gone:
            term.err(f"no feedback recorded for '{args.alert_id}'")
            return EXIT_ERR
        store.save()
        AuditLog(state / "audit.jsonl").append("feedback_removed", **gone)
        term.say(f"removed {gone['verdict']} mark on {gone['rule']} ({gone['fingerprint']})")
        return EXIT_OK
    if not args.verdict:
        term.err("give a verdict: benign or malicious (or --undo)")
        return EXIT_USAGE
    try:
        alert = find_alert(state, args.alert_id, args.report)
    except LookupError as e:
        term.err(str(e))
        return EXIT_ERR
    before = store.multipliers()[alert["rule"]]
    entry = store.record(alert, args.verdict, args.note or "")
    store.save()
    after = store.multipliers()[alert["rule"]]
    AuditLog(state / "audit.jsonl").append("feedback_recorded", id=alert["id"], **entry,
                                           multiplier_before=before, multiplier_after=after)
    _say_feedback(term, alert, args.verdict, before, after)
    return EXIT_OK


def _say_feedback(term: ui.Term, alert: dict, verdict: str, before: float, after: float) -> None:
    colour = term.green if verdict == "benign" else term.red
    term.say(f"marked {term.cyan(alert['id'])} {colour(verdict)}: {alert['title']} {term.dim(str(alert['entities']))}")
    if verdict == "benign":
        term.say(term.dim("  future alerts with the same rule and user/source will be suppressed"))
    k = TUNABLE[alert["rule"]]
    base = DEFAULTS[alert["rule"]][k]
    if before != after:
        new = effective_thresholds({alert["rule"]: after})[alert["rule"]][k]
        old = effective_thresholds({alert["rule"]: before})[alert["rule"]][k]
        if old != new:
            term.say(term.dim(f"  {alert['rule']}.{k}: {old} -> {new} (default {base}, multiplier x{before} -> x{after})"))
        else:
            term.say(term.dim(f"  {alert['rule']} multiplier x{before} -> x{after}; {k} stays {new} until more feedback"))


# ---- rules ------------------------------------------------------------------

def cmd_rules(args, term: ui.Term) -> int:
    state = _state(args)
    store = FeedbackStore(state) if state else None
    mult = store.multipliers() if store else {}
    th = effective_thresholds(mult)
    counts = store.counts() if store else {}
    if args.json:
        print(json.dumps({"defaults": DEFAULTS, "effective": th, "multipliers": mult}, indent=2))
        return EXIT_OK
    for rule, (title, desc) in RULE_INFO.items():
        term.say(f"{term.bold(title)}  {term.dim(rule)}")
        for ln in ui.wrap(desc, term.width, "  "):
            term.say(term.dim(ln))
        parts = []
        for k, v in th[rule].items():
            base = DEFAULTS[rule][k]
            s = f"{k}={v}"
            if v != base:
                s = term.yellow(s) + term.dim(f" (default {base})")
            parts.append(s)
        term.say("  " + "  ".join(parts))
        b, m = counts.get(rule, (0, 0))
        if b or m:
            term.say(term.dim(f"  feedback: {b} benign, {m} malicious -> x{mult[rule]} on {TUNABLE[rule]}"))
        term.say()
    return EXIT_OK


# ---- geomap -----------------------------------------------------------------

def cmd_geomap(args, term: ui.Term) -> int:
    try:
        db = GeoDB()
        for p in args.geoip:
            db.load_csv(p)
        rows, stats = build_token_geo(args.map, db, args.precision)
    except GeoError as e:
        term.err(str(e))
        return EXIT_ERR
    out = args.output or str(Path(args.map).with_name("token_geo.csv"))
    write_token_geo(rows, out)
    term.say(f"{stats['ip_tokens']} IP tokens in the map: {stats['located']} located, "
             f"{stats['lan']} internal (skipped), {stats['unknown']} not in the GeoIP data")
    term.say(f"wrote {out}  {term.dim(f'(coordinates rounded to {args.precision} dp, no IP addresses)')}")
    term.say(term.dim("give it to the analysis side with: hexsentry scan <redacted log> --token-geo " + out))
    return EXIT_OK


# ---- audit ------------------------------------------------------------------

def cmd_audit(args, term: ui.Term) -> int:
    state = _state(args) or default_state_dir()
    path = Path(args.file) if args.file else state / "audit.jsonl"
    if args.action == "verify":
        ok, n, msg = verify(path)
        term.say((term.green("ok   ") if ok else term.red("FAIL ")) + msg + term.dim(f"  ({path})"))
        return EXIT_OK if ok else EXIT_ERR
    recs = tail(path, args.n)
    if not recs:
        term.say(f"no audit records at {path}")
        return EXIT_OK
    for r in recs:
        d = r["data"]
        detail = ""
        if r["event"] in ("alert_raised", "alert_suppressed"):
            detail = f"{d['id']} {d['rule']} {d['severity']} {d['entities']}"
        elif r["event"].startswith("feedback"):
            detail = f"{d.get('id', '')} {d['verdict']} {d['rule']}"
        elif r["event"] == "scan_started":
            detail = ", ".join(f["path"] for f in d.get("inputs", [])) + f"  {d.get('events')} events"
        elif r["event"] == "scan_finished":
            detail = f"{d['alerts']} alerts, {d['suppressed']} suppressed"
        term.say(f"{term.dim(str(r['seq']).rjust(5))} {r['ts'][:19]}Z  {r['event']:<17} {detail}")
    return EXIT_OK


# ---- demo -------------------------------------------------------------------

def cmd_demo(args, term: ui.Term) -> int:
    from .demo import write_demo
    out = Path(args.dir)
    log_path, geo_path = write_demo(out)
    term.say(term.dim(f"wrote {log_path} and {geo_path} (synthetic data, RFC 5737 addresses)"))
    term.say()
    ns = _scan_ns(paths=[str(log_path)], geoip=[str(geo_path)], state=str(out / ".hexsentry"),
                  json=str(out / "demo_report.json"), csv=str(out / "demo_alerts.csv"))
    rc = cmd_scan(ns, term)
    term.say()
    term.say(term.dim("try:  hexsentry feedback <id> benign --state " + str(out / ".hexsentry")))
    term.say(term.dim("then run the demo again to see suppression and threshold tuning."))
    return rc


def _scan_ns(**kw) -> argparse.Namespace:
    d = dict(paths=[], geoip=[], token_geo=[], tz="UTC", year=None, rules=None, config=None, state=None,
             no_state=False, no_feedback=False, json=None, csv=None, min_severity="low",
             show_suppressed=False, limit=0, fail_on=None, quiet=False, no_color=False)
    d.update(kw)
    return argparse.Namespace(**d)


# ---- interactive menu ---------------------------------------------------------

def _ask_path(term: ui.Term, prompt: str, must_exist: bool = True, optional: bool = False) -> Optional[str]:
    while True:
        v = ui.ask(term, prompt + (" (optional, enter to skip)" if optional else ""))
        if not v:
            if optional:
                return None
            return None
        if not must_exist or Path(v).exists():
            return v
        term.err(f"not found: {v}")


def menu(term: ui.Term, state: Path) -> int:
    term.say(term.bold(f"hexsentry {__version__}") + term.dim("  explainable SSH login anomaly detection"))
    term.say()
    items = [("Scan a log file", "auth.log, secure, or hexredact output"),
             ("Run the demo", "synthetic log with six planted incidents"),
             ("Mark an alert", "benign or malicious; tunes future scans"),
             ("Rules and thresholds", "what each rule checks, current tuning"),
             ("Build a token geo map", "hexredact map + GeoIP CSV -> token_geo.csv"),
             ("Audit log", "verify the hash chain, show recent records"),
             ("Quit", "")]
    while True:
        i = ui.select(term, "What would you like to do?", [a for a, _ in items], [b for _, b in items])
        term.say()
        if i is None or i == 6:
            return EXIT_OK
        try:
            if i == 0:
                path = _ask_path(term, "Log file or folder")
                if not path:
                    continue
                geoip = _ask_path(term, "GeoIP CSV", optional=True)
                tgeo = _ask_path(term, "Token geo CSV from geomap", optional=True)
                save = ui.confirm(term, "Also save JSON and CSV reports next to the log?", False)
                base = Path(path)
                stem = base.name if base.is_dir() else base.stem
                ns = _scan_ns(paths=[path], geoip=[geoip] if geoip else [], token_geo=[tgeo] if tgeo else [],
                              state=str(state),
                              json=str(base.parent / f"{stem}_hexsentry.json") if save else None,
                              csv=str(base.parent / f"{stem}_hexsentry.csv") if save else None)
                term.say()
                cmd_scan(ns, term)
            elif i == 1:
                d = ui.ask(term, "Folder for the demo files", "hexsentry-demo")
                term.say()
                cmd_demo(argparse.Namespace(dir=d), term)
                state = Path(d) / ".hexsentry"
                term.say(term.dim(f"(menu now uses the demo's state folder: {state})"))
            elif i == 2:
                _menu_feedback(term, state)
            elif i == 3:
                cmd_rules(argparse.Namespace(state=str(state), no_state=False, json=False), term)
            elif i == 4:
                m = _ask_path(term, "hexredact reverse map (JSON)")
                g = _ask_path(term, "GeoIP CSV") if m else None
                if m and g:
                    cmd_geomap(argparse.Namespace(map=m, geoip=[g], output=None, precision=1), term)
            elif i == 5:
                cmd_audit(argparse.Namespace(state=str(state), no_state=False, file=None, action="verify", n=0), term)
                cmd_audit(argparse.Namespace(state=str(state), no_state=False, file=None, action="show", n=15), term)
        except ui.Aborted:
            term.say()
        term.say()


def _menu_feedback(term: ui.Term, state: Path) -> None:
    p = state / "last_alerts.json"
    if not p.is_file():
        term.say("No scan yet in " + str(state) + ". Run a scan first.")
        return
    alerts = json.loads(p.read_text(encoding="utf-8")).get("alerts", [])
    if not alerts:
        term.say("The last scan had no alerts.")
        return
    labels = [f"{a['severity'].upper():<8} {a['title']:<22} {a['id']}" for a in alerts]
    hints = [" ".join(f"{v}" for v in a["entities"].values())[:48] + (f"  [{a['verdict']}]" if a.get("verdict") else "")
             for a in alerts]
    i = ui.select(term, "Which alert?", labels, hints)
    if i is None:
        return
    j = ui.select(term, "Verdict", ["benign (false positive)", "malicious (true positive)"])
    if j is None:
        return
    note = ui.ask(term, "Note (optional)")
    cmd_feedback(argparse.Namespace(alert_id=alerts[i]["id"], verdict=VERDICTS[j], note=note, report=None,
                                    undo=False, state=str(state), no_state=False), term)


# ---- argparse ---------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="hexsentry",
        description="Explainable SSH login anomaly detection. Runs on raw auth.log or on hexredact output, "
                    "so analysis never needs the real usernames or addresses.",
        epilog="Run with no arguments for the interactive menu.")
    ap.add_argument("--version", action="version", version=f"hexsentry {__version__}")
    ap.add_argument("--no-color", action="store_true", help="disable colour (NO_COLOR is also honoured)")
    ap.add_argument("--state", metavar="DIR", help="feedback, audit log and last scan (default ~/.hexsentry or $HEXSENTRY_HOME)")
    ap.add_argument("--pause", action="store_true", help=argparse.SUPPRESS)
    sub = ap.add_subparsers(dest="cmd")
    # the same global flags are accepted after the subcommand too
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--state", metavar="DIR", default=argparse.SUPPRESS, help="state folder (see top-level help)")
    common.add_argument("--no-color", action="store_true", default=argparse.SUPPRESS, help="disable colour")

    p = sub.add_parser("scan", parents=[common], help="analyse log files, a directory, or stdin")
    p.add_argument("paths", nargs="*", help="files or directories; '-' or a pipe for stdin. .gz is fine")
    p.add_argument("--geoip", action="append", metavar="CSV", help="offline GeoIP CSV (DB-IP Lite, GeoLite2-style, "
                   "or network/start,end + lat/lon)")
    p.add_argument("--token-geo", action="append", metavar="CSV", help="token locations from `hexsentry geomap` (for redacted input)")
    p.add_argument("--tz", default="UTC", help="offset for timestamps without one, and for odd-hours checks "
                   "(e.g. +01:00). Default UTC")
    p.add_argument("--year", type=int, help="year for classic syslog lines that have none (default: inferred)")
    p.add_argument("--rules", help=f"comma-separated subset of: {','.join(DEFAULTS)}")
    p.add_argument("--config", metavar="JSON", help='threshold overrides, e.g. {"brute_force": {"failures": 20}}')
    p.add_argument("--no-state", action="store_true", help="no feedback, no audit log, no last-scan file")
    p.add_argument("--no-feedback", action="store_true", help="ignore recorded feedback (raw rule output)")
    p.add_argument("--json", metavar="PATH", help="write the full JSON report ('-' for stdout)")
    p.add_argument("--csv", metavar="PATH", help="write a flat alert table, e.g. for SAS Viya ('-' for stdout)")
    p.add_argument("--min-severity", choices=SEVERITIES, default="low")
    p.add_argument("--show-suppressed", action="store_true", help="also list alerts suppressed by benign feedback")
    p.add_argument("--limit", type=int, default=0, help="show at most N alerts in the terminal")
    p.add_argument("--fail-on", choices=SEVERITIES, help="exit 3 if any alert is at or above this severity")
    p.add_argument("-q", "--quiet", action="store_true", help="no terminal report")

    p = sub.add_parser("feedback", parents=[common], help="mark an alert benign or malicious")
    p.add_argument("alert_id", help="alert ID or unique prefix, from the last scan")
    p.add_argument("verdict", nargs="?", choices=VERDICTS)
    p.add_argument("--note", help="why, for the audit trail")
    p.add_argument("--report", metavar="JSON", help="look the ID up in this report instead of the last scan")
    p.add_argument("--undo", action="store_true", help="remove the mark for this alert ID")

    p = sub.add_parser("rules", parents=[common], help="list rules with current thresholds and tuning")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("geomap", parents=[common], help="hexredact reverse map + GeoIP CSV -> coarse token locations")
    p.add_argument("map", help="hexredact *_redaction_map.json (plaintext)")
    p.add_argument("--geoip", action="append", required=True, metavar="CSV")
    p.add_argument("-o", "--output", help="default: token_geo.csv next to the map")
    p.add_argument("--precision", type=int, default=1, choices=range(0, 5), metavar="DP",
                   help="decimal places kept on coordinates (default 1, about 11 km)")

    p = sub.add_parser("audit", parents=[common], help="verify or show the tamper-evident audit log")
    p.add_argument("action", choices=["verify", "show"], nargs="?", default="verify")
    p.add_argument("--file", help="audit file (default: <state>/audit.jsonl)")
    p.add_argument("-n", type=int, default=20, help="records to show")

    p = sub.add_parser("demo", parents=[common], help="write a synthetic log with planted incidents and scan it")
    p.add_argument("--dir", default="hexsentry-demo", help="output folder (default ./hexsentry-demo)")

    sub.add_parser("menu", parents=[common], help="interactive menu (the default with no arguments)")
    return ap


def main(argv: Optional[List[str]] = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    ap = build_parser()
    args = ap.parse_args(argv)
    term = ui.Term(color=False if args.no_color else None)
    handlers = {"scan": cmd_scan, "feedback": cmd_feedback, "rules": cmd_rules, "geomap": cmd_geomap,
                "audit": cmd_audit, "demo": cmd_demo}
    try:
        if args.cmd in handlers:
            return handlers[args.cmd](args, term)
        if args.cmd is None and not sys.stdin.isatty() and not args.pause:
            return cmd_scan(_scan_ns(state=args.state, no_color=args.no_color), term)   # piped input
        return menu(term, Path(args.state) if args.state else default_state_dir())
    except AuditError as e:
        term.err(str(e))
        return EXIT_ERR
    except (KeyboardInterrupt, EOFError):
        term.say()
        return 130
    except BrokenPipeError:
        try:
            sys.stdout = open(os.devnull, "w")
        except OSError:
            pass
        return EXIT_OK
    finally:
        if args.pause:
            try:
                input("\npress Enter to close...")
            except (EOFError, KeyboardInterrupt):
                pass
