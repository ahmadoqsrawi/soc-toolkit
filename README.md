# SOC Toolkit

A modular, SOC-grade log analysis and threat detection toolkit built in Python 3.12+. Parses Linux auth logs, JSON, and CSV formats. Detects brute force attacks, password spray, account enumeration, and privilege escalation. Correlates findings into attack chains and generates analyst-ready reports.

Built for daily SOC work, triage, detection, incident response, and evidence collection.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Detection Rules](#detection-rules)
- [Correlation Rules](#correlation-rules)
- [Configuration](#configuration)
- [Report Formats](#report-formats)
- [Running Tests](#running-tests)
- [Project Structure](#project-structure)
- [Roadmap](#roadmap)

---

## Features

- Multi-format log parsing - syslog/auth.log, JSON, JSON-lines, CSV, TSV
- Compressed file support - .gz, .bz2, .xz handled transparently
- Five detectors - brute force, password spray, enumeration, privilege escalation, allowlist suppression
- Correlation engine - links findings into attack chains with a sliding time window
- Five built-in correlation rules - brute-then-success, success-then-privesc, full attack chain, enum-then-brute, persistent recon
- Four report formats - terminal text, Markdown, HTML (self-contained), JSON
- Evidence bundle - ZIP with all report formats plus raw evidence log plus manifest
- Streaming design - processes files of any size without loading into memory
- Fully tested - 70 tests across parsers, detectors, correlators, and exporters
- CI enforced - GitHub Actions runs the full test suite on every push

---

## Architecture

```
Log File
    |
    v
parsers/          <- SyslogParser, JsonParser, CsvParser
    |  Iterator[Event]
    v
detectors/        <- BruteForce, PasswordSpray, Enumeration, PrivEsc
    |  Iterator[Finding]
    v
correlators/      <- CorrelationEngine + 5 built-in rules
    |  Iterator[Finding] (original + correlated)
    v
exporters/        <- Markdown, HTML, JSON, Bundle
```

Each layer consumes the output of the previous one. Nothing is loaded into memory in bulk - every parser yields one Event at a time.

---

## Requirements

- Python 3.10 or higher
- pip

---

## Installation

### Linux (Ubuntu / Debian)

```bash
git clone https://github.com/ahmadoqsrawi/soc-toolkit.git
cd soc-toolkit

python3 -m venv venv
source venv/bin/activate

pip install -e .
```

### macOS

```bash
git clone https://github.com/ahmadoqsrawi/soc-toolkit.git
cd soc-toolkit

python3 -m venv venv
source venv/bin/activate

pip install -e .
```

### Windows

```powershell
git clone https://github.com/ahmadoqsrawi/soc-toolkit.git
cd soc-toolkit

python -m venv venv
venv\Scripts\activate

pip install -e .
```

After installation the following commands are available in your terminal:

```
soc-parse     parse and filter log files
soc-detect    run all detectors and produce findings
```

---

## Quick Start

Activate your virtual environment first:

```bash
# Linux / macOS
source venv/bin/activate

# Windows
venv\Scripts\activate
```

Run the detector against the included sample log:

```bash
soc-detect --input samples/auth.log.sample
```

Expected output: 5 findings including a CRITICAL privilege escalation, two HIGH brute force attacks, a HIGH backdoor account creation, and a MEDIUM password spray.

Generate a full evidence bundle:

```bash
python3 - << 'EOF'
from pathlib import Path
from soc_toolkit.parsers.router     import get_parser
from soc_toolkit.config.loader      import Config
from soc_toolkit.detectors          import (BruteForceDetector, PasswordSprayDetector,
                                            EnumerationDetector, PrivEscDetector,
                                            DetectionPipeline)
from soc_toolkit.correlators.engine import CorrelationEngine
from soc_toolkit.correlators.rules  import ALL_RULES
from soc_toolkit.exporters.bundle   import create_bundle

sample   = Path('samples/auth.log.sample')
config   = Config()
events   = list(get_parser(sample).parse(sample))

pipeline = DetectionPipeline(config)
for det in [BruteForceDetector(config), PasswordSprayDetector(config),
            EnumerationDetector(config), PrivEscDetector(config)]:
    pipeline.add_detector(det)

findings   = list(pipeline.run(iter(events)))
engine     = CorrelationEngine(ALL_RULES)
all_output = list(engine.correlate(iter(findings)))

create_bundle(iter(all_output), Path('report.zip'))
print(f"Done - {len(all_output)} findings - open report.zip")
EOF
```

This produces report.zip containing report.md, report.html, findings.json, evidence.log, and manifest.txt.

---

## Usage

### Parse logs

```bash
# Parse a syslog file and output as text
soc-parse --input /var/log/auth.log

# Filter by severity
soc-parse --input auth.log --severity ERROR

# Filter by keyword
soc-parse --input auth.log --keyword "Failed password"

# Export to CSV
soc-parse --input auth.log --format csv --output events.csv

# Parse a JSON log
soc-parse --input events.json --format json
```

### Run detectors

```bash
# Run all detectors, text output
soc-detect --input auth.log

# JSON output for pipeline use
soc-detect --input auth.log --format json --output findings.json

# Only show HIGH and above
soc-detect --input auth.log --severity HIGH

# Run a single rule only
soc-detect --input auth.log --rule brute_force

# Use a custom config file
soc-detect --input auth.log --config config/default.yaml

# Point at a live system log (Linux)
soc-detect --input /var/log/auth.log
```

### All CLI flags

Both soc-parse and soc-detect share the same base flags:

| Flag | Short | Description |
|------|-------|-------------|
| --input | -i | Log file to process (required) |
| --output | -o | Output file (default: stdout) |
| --format | -f | text, json, or csv |
| --config | -c | YAML config file |
| --verbose | -v | Verbose/debug output |

Additional flags for soc-detect:

| Flag | Description |
|------|-------------|
| --severity | Minimum severity to report (CRITICAL, HIGH, MEDIUM, LOW) |
| --rule | Run only this rule ID |

---

## Detection Rules

### brute_force

Fires when a single IP generates N or more failed authentication attempts within a time window.

| Severity | Condition |
|----------|-----------|
| CRITICAL | Burst count >= 3x threshold |
| HIGH | Burst count >= threshold |
| MEDIUM | Total >= threshold, no tight burst |

Default threshold: 5 attempts / 30-minute window. Configurable via brute_force_threshold and brute_force_window_sec.

### password_spray

Fires when a single IP targets many distinct usernames. Distinguished from brute force by the number of unique accounts targeted rather than raw attempt count.

Default threshold: 10 distinct usernames / 5-minute window. Configurable via spray_threshold and spray_window_sec.

### enumeration

Fires when an IP probes for non-existent usernames. This is reconnaissance, not a direct attack. Threshold: 5 distinct invalid usernames.

### priv_esc

Fires on privilege escalation patterns. Produces separate findings for each sub-pattern:

- High-risk sudo - shell spawns, reading /etc/shadow, useradd, visudo -> CRITICAL
- Normal sudo - other commands -> MEDIUM
- Failed sudo auth - repeated failures -> HIGH (threshold: 3)
- su switching - especially to root -> HIGH
- User creation - new accounts via useradd -> HIGH
- Group changes - groupadd, usermod -> HIGH

---

## Correlation Rules

The correlation engine links findings into higher-level attack narratives. All rules run over a sliding time window.

| Rule ID | Conditions | Window | Severity |
|---------|-----------|--------|----------|
| brute_then_success | brute_force/spray -> auth_success | 10 min | CRITICAL |
| success_then_priv_esc | auth_success -> priv_esc | 30 min | CRITICAL |
| full_attack_chain | brute/spray -> success -> priv_esc | 1 hour | CRITICAL |
| enum_then_brute | enumeration -> brute_force/spray | 30 min | HIGH |
| persistent_recon | enumeration -> enumeration | 1 hour | HIGH |

Correlated findings are marked with is_correlated: true in JSON output.

---

## Configuration

Copy config/default.yaml and pass it with --config:

```yaml
# Detection thresholds
brute_force_threshold:  5
brute_force_window_sec: 1800

spray_threshold:        10
spray_window_sec:       300

# Allowlist
allowed_ips:
  - 10.0.0.1
  - 192.168.1.100

allowed_users:
  - nagios
  - prometheus
```

```bash
soc-detect --input auth.log --config my_config.yaml
```

---

## Report Formats

### Text

Color-coded findings with severity, timestamps, source IPs, targeted accounts, description, and recommendation. Designed for terminal triage.

### Markdown

Structured incident report with executive summary, attack timeline, per-finding detail with collapsible evidence, and deduplicated action list. Ready to paste into a ticket, wiki, or IR document.

### HTML

Same content as Markdown, self-contained with inline CSS. No external dependencies works offline and can be emailed or attached to tickets.

### JSON

Full structured output including summary statistics, all findings with evidence arrays, and a unified timeline. Suitable for SIEM ingestion or pipeline consumption.

### Evidence Bundle (ZIP)

```
report.zip
|- report.md        Markdown incident report
|- report.html      Self-contained HTML report
|- findings.json    Full structured JSON output
|- evidence.log     Raw log lines from all evidence events
|- manifest.txt     Bundle metadata and summary
```

---

## Running Tests

```bash
# Activate your virtual environment first
source venv/bin/activate      # Linux / macOS
venv\Scripts\activate         # Windows

# Run full test suite
python -m pytest tests/ -v
```

Expected: 70 tests, 0 failures.

Test coverage by layer:

| Layer | Tests | File |
|-------|-------|------|
| Models | 5 | tests/test_models.py |
| Syslog parser | 9 | tests/parsers/test_syslog.py |
| JSON parser | 4 | tests/parsers/test_json.py |
| Brute force | 8 | tests/detectors/test_brute_force.py |
| Password spray | 5 | tests/detectors/test_password_spray.py |
| Enumeration | 5 | tests/detectors/test_enumeration.py |
| Privilege escalation | 8 | tests/detectors/test_priv_esc.py |
| Allowlist + pipeline | 4 | tests/detectors/test_allowlist.py |
| Correlation engine | 6 | tests/correlators/test_engine.py |
| Correlation rules | 6 | tests/correlators/test_rules.py |
| Exporters + timeline | 10 | tests/test_exporters.py |

---

## Project Structure

```
soc_toolkit/
|- models/
|   |- event.py           Event dataclass - normalized log event schema
|   |- finding.py         Finding dataclass - structured detection result
|- parsers/
|   |- base.py            BaseParser - streaming Iterator[Event] contract
|   |- syslog.py          Linux auth.log / syslog parser
|   |- json_.py           JSON and JSON-lines parser
|   |- csv_.py            CSV and TSV parser
|   |- router.py          Auto-selects parser by file extension
|- detectors/
|   |- base.py            BaseDetector - Iterator[Event] to Iterator[Finding]
|   |- brute_force.py     BruteForceDetector
|   |- password_spray.py  PasswordSprayDetector
|   |- enumeration.py     EnumerationDetector
|   |- priv_esc.py        PrivEscDetector
|   |- allowlist.py       AllowlistEngine + DetectionPipeline
|- correlators/
|   |- base.py            BaseCorrelator + CorrelationRule dataclass
|   |- engine.py          CorrelationEngine - sliding window evaluator
|   |- rules.py           5 built-in correlation rules
|- exporters/
|   |- base.py            BaseExporter contract
|   |- timeline.py        Unified timeline builder
|   |- markdown.py        MarkdownExporter
|   |- html_report.py     HtmlExporter (self-contained)
|   |- json_export.py     JsonExporter
|   |- bundle.py          Evidence ZIP bundle generator
|- cli/
|   |- base.py            Shared CLI argument contract
|   |- log_parser.py      soc-parse entry point
|   |- detector.py        soc-detect entry point
|- config/
|   |- loader.py          Config dataclass + YAML loader
|   |- default.yaml       Default configuration
|- samples/
|   |- auth.log.sample    Synthetic SSH brute force + sudo abuse scenario
|   |- events.json.sample Mixed severity JSON-lines sample
|- tests/
    |- test_models.py
    |- test_exporters.py
    |- parsers/
    |- detectors/
    |- correlators/
```

---

## Roadmap

| Phase | Status | Description |
|-------|--------|-------------|
| Phase 1 - Core architecture | Complete | Event/Finding models, parsers, base contracts, CLI, config, tests |
| Phase 2 - Detection engine | Complete | 5 detectors, allowlist engine, detection pipeline |
| Phase 3 - Correlation + reporting | Complete | Correlation engine, 5 rules, 4 report formats, evidence bundle |
| Phase 4 - Source expansion | Planned | Windows Event Log, CEF/LEEF, GeoIP enrichment, compressed input |
| Phase 5 - Analyst experience | Planned | Live tail mode, web UI, saved investigations |
| Phase 6 - Ecosystem integration | Planned | REST API, Docker, SIEM integration, MITRE ATT&CK mapping |

---

## Author

Ahmad Ismail - Security Architect

Built as part of a structured SOC tooling development programme, following a phased roadmap from foundation architecture through detection, correlation, and reporting.

---

## License

MIT License, free to use, modify, and distribute with attribution.
