# Changelog

## 0.1.0 (unreleased)

First release.

- OpenSSH auth log parser: syslog and ISO timestamps, `sshd-session`, repeated messages, rotated and gzipped files, stdin
- Works on hexredact output: tokens are treated as opaque, consistent identifiers
- Six explainable rules with plain-English reasons, confidence scores and evidence line references
- Offline GeoIP (DB-IP Lite, GeoLite2-style, custom CSV) and `geomap` for coarse token locations
- Analyst feedback: benign suppression and per-rule threshold scaling
- Hash-chained audit log with a head file for truncation checks, optionally HMAC-keyed, with `audit verify`
- Log-injection safe: the source is always the last `from <addr> port N` on the line
- Input SHA-256 matches `sha256sum` of the file as stored
- Terminal, JSON and CSV output; `--fail-on` exit code; arrow-key menu; synthetic demo
