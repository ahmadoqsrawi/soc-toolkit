# SOC Toolkit

![CI](https://github.com/ahmadoqsrawi/soc-toolkit/actions/workflows/ci.yml/badge.svg)

## Problem

SOC analysts spend a significant part of their shift manually grepping through auth logs looking for signs of credential attacks. The patterns are well-known — repeated failed logins from one IP, logins spread across many accounts, a successful auth after a burst of failures, a sudo command that spawns a shell — but connecting them across time in a single pass is tedious and error-prone at scale.

Most SIEM tools require paid licenses, cloud connectivity, or heavyweight infrastructure. Analysts working on isolated networks, doing triage on exported logs, or building detection skills outside a vendor platform have no lightweight option.

This toolkit fills that gap. It runs offline, processes files of any size, and produces structured findings you can drop directly into a ticket or incident report.

## SOC Use Case

Target environment: Linux servers and Windows endpoints where SSH, RDP, and sudo activity is logged.

Typical analyst workflow:

1. Export auth logs from the affected host.
2. Run `soc-detect --input auth.log` to get a ranked finding list in under a second.
3. Review correlated attack chains that link brute force through successful login through privilege escalation in one view.
4. Export an evidence bundle containing Markdown, HTML, and JSON reports plus raw evidence lines and attach it to the IR ticket.

Supported formats: syslog/auth.log, Windows Security Event Log XML, CEF, LEEF, JSON, JSON-lines, CSV, TSV, and compressed variants (.gz, .bz2, .xz).

## Dataset

The toolkit ships with a synthetic sample log corpus covering all detectors:

| File | Content |
|------|---------|
| `samples/auth.log.sample` | SSH brute force from two IPs, backdoor account creation, sudo shell spawn |
| `samples/events.json.sample` | Mixed severity JSON-lines with failed and successful auth events |
| `samples/security.xml.sample` | Windows Security Event Log XML with logon failures and privilege use |
| `samples/events.cef.sample` | CEF and LEEF format events covering auth and escalation patterns |

Running against `samples/auth.log.sample` produces 7 findings: 3 CRITICAL correlated attack chains, 1 privilege escalation, brute force from two source IPs, a backdoor account creation, and a password spray.

For real-world use, point `--input` at any exported log file. The parser auto-selects the right format by file extension.

## Detection Logic

Five detectors, each consuming a stream of normalized events and emitting structured findings.

**BruteForceDetector** — fires when a single IP generates N or more failed authentication attempts within a sliding time window.

| Severity | Condition |
|----------|-----------|
| CRITICAL | Burst count >= 3x threshold in window |
| HIGH | Burst count >= threshold in window |
| MEDIUM | Total >= threshold, no tight burst |

Default: 5 attempts / 30-minute window. Configurable via `brute_force_threshold` and `brute_force_window_sec`.

**PasswordSprayDetector** — fires when a single IP targets many distinct usernames. Differs from brute force by unique account count rather than raw attempt volume. Default: 10 distinct usernames / 5-minute window.

**EnumerationDetector** — fires when an IP probes for non-existent usernames. Reconnaissance, not a direct attack. Threshold: 5 distinct invalid usernames.

**PrivEscDetector** — fires on privilege escalation patterns:

- sudo spawning a shell, reading `/etc/shadow`, running `useradd` or `visudo` → CRITICAL
- sudo other commands → MEDIUM
- repeated failed sudo auth → HIGH
- `su` to root → HIGH
- new user creation via `useradd` → HIGH
- group changes via `groupadd`/`usermod` → HIGH

**AuthSuccessDetector** — fires on every successful login (INFO severity). Required for correlation rules to trigger on real logs.

**Correlation Engine** — links findings into attack chains using a sliding time window.

| Rule | Conditions | Window | Severity |
|------|-----------|--------|----------|
| `brute_then_success` | brute_force or spray then auth_success | 10 min | CRITICAL |
| `success_then_priv_esc` | auth_success then priv_esc | 30 min | CRITICAL |
| `full_attack_chain` | brute/spray then success then priv_esc | 1 hour | CRITICAL |
| `enum_then_brute` | enumeration then brute_force or spray | 30 min | HIGH |
| `persistent_recon` | enumeration then enumeration | 1 hour | HIGH |

## AI/ML Method

Detection is currently rule-based and threshold-driven. Thresholds are tuned to match common attacker patterns — 5 failures per 30 minutes sits below most account lockout policies, which is the range attackers typically operate in. The correlation engine uses a sliding window evaluator, not a probabilistic model.

The GeoIP enricher adds country and ASN context to every finding using the MaxMind GeoLite2 offline database with no API call required.

Planned for the next phase:

- Per-user login behavior baseline with deviation flagging.
- Time-of-day and geo-velocity heuristics built on top of the existing GeoIP enricher.
- A scoring model to rank findings by true positive likelihood.

## MITRE ATT&CK Mapping

| Detector | Technique | ID |
|----------|-----------|-----|
| BruteForceDetector | Brute Force: Password Guessing | T1110.001 |
| PasswordSprayDetector | Brute Force: Password Spraying | T1110.003 |
| EnumerationDetector | Account Discovery: Local Account | T1087.001 |
| PrivEscDetector (sudo) | Abuse Elevation Control Mechanism: Sudo | T1548.003 |
| PrivEscDetector (su) | Use Alternate Authentication Material | T1550 |
| PrivEscDetector (useradd) | Create Account: Local Account | T1136.001 |
| AuthSuccessDetector | Valid Accounts | T1078 |
| brute_then_success | Credential Access then Initial Access | T1110 → T1078 |
| full_attack_chain | Credential Access then Persistence then Privilege Escalation | T1110 → T1078 → T1548 |

## Screenshots

Sample terminal output against the included log:

```
$ soc-detect --input samples/auth.log.sample

[CRITICAL] full_attack_chain     192.168.1.105 brute forced 23 times, succeeded as admin, then ran sudo /bin/bash
[CRITICAL] brute_then_success    10.0.0.44 spray across 14 accounts, successful login as root 4 min later
[CRITICAL] success_then_priv_esc admin logged in at 03:14, ran useradd backdoor at 03:17
[HIGH]     brute_force           192.168.1.105: 23 failed attempts in 8 min window
[HIGH]     priv_esc              sudo /bin/bash executed by admin
[HIGH]     priv_esc              useradd backdoor executed by admin
[MEDIUM]   password_spray        10.0.0.44: 14 distinct accounts targeted in 4 min
```

## How to Run

Requirements: Python 3.10+, pip

```bash
git clone https://github.com/ahmadoqsrawi/soc-toolkit.git
cd soc-toolkit
python3 -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -e .
```

Run against the sample log:

```bash
soc-detect --input samples/auth.log.sample
```

Common options:

```bash
soc-detect --input auth.log --format json --output findings.json
soc-detect --input auth.log --severity HIGH
soc-detect --input auth.log --rule brute_force
soc-detect --input auth.log --config config/my_config.yaml
soc-detect --input /var/log/auth.log
```

Run tests:

```bash
python -m pytest tests/ -v
```

Expected: 119 tests, 0 failures.

## Limitations

- No live tail or real-time streaming. Processes files, not open log handles.
- No built-in log collection. You export the log file and point the tool at it.
- Windows EVTX parser reads exported XML (`wevtutil qe Security /f:XML`), not binary `.evtx` files.
- GeoIP enrichment requires downloading the MaxMind GeoLite2 database separately. Without it the enricher skips silently.
- No web UI. Output is terminal text, Markdown, HTML, or JSON.
- Correlation rules use fixed time windows. Slow attackers operating over hours or days will not trigger chain rules.
- Detection thresholds are global. Per-host or per-user baselines are not supported yet.
- No native SIEM push connector.

## Future Improvements

- Live tail mode to watch a log file in real time and emit findings as they occur.
- Per-user behavioral baseline to flag logins outside normal hours or from unusual locations.
- Geo-velocity alerting for logins from two countries within an impossible travel window.
- Web UI with filtering and timeline drill-down.
- REST API to accept log submissions over HTTP and return structured findings.
- Docker image with the GeoIP database bundled.
- SIEM connectors for Splunk HEC, Elastic, and generic syslog targets.
- ATT&CK Navigator layer export from any finding set.
- Saved investigations to track an incident across multiple log files over time.
