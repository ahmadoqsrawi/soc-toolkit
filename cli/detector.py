"""
cli/detector.py
---------------
Entry point: soc-detect
Runs all detectors, optional correlation, and outputs findings in any format.

Usage:
    soc-detect --input auth.log
    soc-detect --input auth.log --format json --output findings.json
    soc-detect --input auth.log --format md   --output report.md
    soc-detect --input auth.log --format html --output report.html
    soc-detect --input auth.log --format bundle --output case.zip
    soc-detect --input auth.log --no-correlate
    soc-detect --input auth.log --config config.yaml --severity HIGH
"""

from __future__ import annotations

import sys
from pathlib import Path

from .base import build_base_parser, resolve_output, validate_input
from soc_toolkit.parsers.router  import get_parser
from soc_toolkit.config.loader   import load_config
from soc_toolkit.detectors       import (
    BruteForceDetector, PasswordSprayDetector,
    EnumerationDetector, PrivEscDetector,
    AuthSuccessDetector, DetectionPipeline,
)
from soc_toolkit.correlators     import CorrelationEngine, ALL_RULES
from soc_toolkit.exporters       import (
    MarkdownExporter, HtmlExporter, JsonExporter, create_bundle
)
from soc_toolkit.models.event    import Severity


_SEV_RANK  = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4,
               'ERROR': 1, 'WARNING': 2, 'UNKNOWN': 5}


def main():
    p = build_base_parser(
        "SOC Detector — detect, correlate, and report on log-based threats",
        extra_formats=['md', 'html', 'bundle'],
    )
    p.add_argument('--severity', '-s',
        help='Minimum severity to include (CRITICAL, HIGH, MEDIUM, LOW)')
    p.add_argument('--rule', '-r',
        help='Run only this detector (brute_force, password_spray, enumeration, priv_esc)')
    p.add_argument('--no-correlate', action='store_true',
        help='Skip correlation engine (output raw detector findings only)')
    args = p.parse_args()

    path   = validate_input(args)
    config = load_config(args.config)
    parser = get_parser(path)

    if args.verbose:
        print(f"[INFO] Parser:    {parser.__class__.__name__}", file=sys.stderr)
        print(f"[INFO] File:      {path}", file=sys.stderr)

    events = list(parser.parse(path))
    if args.verbose:
        print(f"[INFO] Events:    {len(events)}", file=sys.stderr)

    # ── Detection ─────────────────────────────────────────────────────────
    pipeline = DetectionPipeline(config)
    all_detectors = [
        BruteForceDetector(config),
        PasswordSprayDetector(config),
        EnumerationDetector(config),
        PrivEscDetector(config),
        AuthSuccessDetector(config),
    ]
    for det in all_detectors:
        if not args.rule or det.rule_id == args.rule:
            pipeline.add_detector(det)

    raw_findings = list(pipeline.run(iter(events)))
    if args.verbose:
        print(f"[INFO] Raw findings: {len(raw_findings)}", file=sys.stderr)

    # ── Correlation ────────────────────────────────────────────────────────
    if not args.no_correlate:
        engine   = CorrelationEngine(ALL_RULES, window_sec=3600)
        findings = list(engine.correlate(iter(raw_findings)))
    else:
        findings = raw_findings

    # ── Severity filter ────────────────────────────────────────────────────
    if args.severity:
        min_rank = _SEV_RANK.get(args.severity.upper(), 5)
        findings = [f for f in findings
                    if _SEV_RANK.get(f.severity.value, 9) <= min_rank]

    # Remove INFO findings from default text output (they're correlation fuel)
    if args.format == 'text' and not args.severity:
        findings = [f for f in findings if f.severity.value != 'INFO']

    # Sort: CRITICAL first
    findings.sort(key=lambda f: _SEV_RANK.get(f.severity.value, 9))

    if args.verbose:
        print(f"[INFO] Final findings: {len(findings)}", file=sys.stderr)

    # ── Output ────────────────────────────────────────────────────────────
    if args.format == 'bundle':
        out_path = Path(args.output) if args.output else Path('soc_report.zip')
        result   = create_bundle(iter(findings), out_path)
        print(f"[OK] Evidence bundle written to: {result}", file=sys.stderr)
        return

    if args.format == 'md':
        with resolve_output(args) as out:
            MarkdownExporter().export(iter(findings), out)
        return

    if args.format == 'html':
        with resolve_output(args) as out:
            HtmlExporter().export(iter(findings), out)
        return

    if args.format == 'json':
        with resolve_output(args) as out:
            JsonExporter().export(iter(findings), out)
        return

    if args.format == 'csv':
        import csv
        with resolve_output(args) as out:
            writer = csv.writer(out)
            writer.writerow(['rule_id','title','severity','confidence',
                             'first_seen','last_seen','event_count',
                             'source_ips','users','is_correlated'])
            for f in findings:
                writer.writerow([
                    f.rule_id, f.title, f.severity.value, f.confidence.value,
                    f.first_seen, f.last_seen, f.event_count,
                    ';'.join(f.source_ips), ';'.join(f.users),
                    f.metadata.get('is_correlated', False),
                ])
        return

    # ── Text (default) ─────────────────────────────────────────────────────
    _print_text_report(findings, sys.stdout)


def _print_text_report(findings, out):
    from colorama import Fore, Style, init
    init(autoreset=True)

    SEV_COLOR = {
        'CRITICAL': Fore.RED + Style.BRIGHT,
        'HIGH':     Fore.RED,
        'MEDIUM':   Fore.YELLOW,
        'LOW':      Fore.CYAN,
        'INFO':     Fore.WHITE,
    }

    print(f"\n{Fore.CYAN}{'─'*64}", file=out)
    print(f"{Fore.CYAN}  SOC Detector — Findings Report", file=out)
    print(f"{Fore.CYAN}{'─'*64}\n", file=out)

    if not findings:
        print(f"  {Fore.GREEN}No findings.", file=out)
        return

    correlated = [f for f in findings if f.metadata.get('is_correlated')]
    if correlated:
        print(f"  {Fore.MAGENTA + Style.BRIGHT}⚡ Correlated findings: {len(correlated)}\n", file=out)

    for i, f in enumerate(findings, 1):
        color  = SEV_COLOR.get(f.severity.value, Fore.WHITE)
        marker = "⚡ " if f.metadata.get('is_correlated') else "   "
        print(f"{color}{marker}[{i}] {f.title}", file=out)
        print(f"      {f.severity.value} | {f.confidence.value} confidence | "
              f"{f.event_count} events", file=out)
        if f.first_seen:
            print(f"      {f.first_seen} → {f.last_seen}", file=out)
        if f.source_ips:
            print(f"      IPs:   {', '.join(f.source_ips)}", file=out)
        if f.users:
            print(f"      Users: {', '.join(f.users[:5])}", file=out)
        print(f"\n      {Fore.WHITE}{f.description}", file=out)
        print(f"\n      {Fore.YELLOW}→ {f.recommendation}", file=out)
        print(f"\n{Fore.CYAN}  {'─'*60}\n", file=out)

    print(f"  Total: {Fore.YELLOW}{len(findings)} finding(s) "
          f"({len(correlated)} correlated)", file=out)


if __name__ == '__main__':
    main()
