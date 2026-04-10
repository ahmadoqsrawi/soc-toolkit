"""
cli/log_parser.py
-----------------
Entry point: soc-parse
Parses any supported log format and outputs normalized events.

Usage:
    soc-parse --input auth.log --format json
    soc-parse --input events.json --format text --severity ERROR
    soc-parse --input access.csv --format csv --output results.csv
"""

from __future__ import annotations

import json
import sys

from .base import build_base_parser, resolve_output, validate_input
from soc_toolkit.parsers.router import get_parser
from soc_toolkit.models.event   import Severity


def _severity_from_str(s: str) -> Severity | None:
    try:
        return Severity(s.upper())
    except ValueError:
        return None


def main():
    p = build_base_parser("SOC Log Parser — normalize syslog, JSON, and CSV logs")
    p.add_argument('--severity', '-s',
        help='Filter by severity (CRITICAL, HIGH, ERROR, WARNING, INFO, DEBUG)')
    p.add_argument('--keyword', '-k',
        help='Filter by keyword in message (case-insensitive)')
    p.add_argument('--event-type', '-e',
        help='Filter by event type (auth_failure, sudo, su, etc.)')
    p.add_argument('--limit', '-l', type=int,
        help='Limit number of output events')
    args = p.parse_args()

    path   = validate_input(args)
    parser = get_parser(path)

    if args.verbose:
        print(f"[INFO] Parser: {parser.__class__.__name__}", file=sys.stderr)
        print(f"[INFO] File:   {path}", file=sys.stderr)

    events = parser.parse(path)

    # Apply filters
    sev_filter  = _severity_from_str(args.severity) if args.severity else None
    kw_filter   = args.keyword.lower() if args.keyword else None
    et_filter   = args.event_type.lower() if args.event_type else None

    filtered = []
    for event in events:
        if sev_filter  and event.severity   != sev_filter:
            continue
        if kw_filter   and kw_filter not in event.message.lower():
            continue
        if et_filter   and event.event_type.value != et_filter:
            continue
        filtered.append(event)
        if args.limit and len(filtered) >= args.limit:
            break

    with resolve_output(args) as out:
        if args.format == 'json':
            records = []
            for e in filtered:
                records.append({
                    'event_type': e.event_type.value,
                    'severity':   e.severity.value,
                    'timestamp':  str(e.timestamp) if e.timestamp else None,
                    'host':       e.host,
                    'process':    e.process,
                    'user':       e.user,
                    'ip':         e.ip,
                    'message':    e.message,
                    'source':     e.source,
                })
            json.dump(records, out, indent=2)
            out.write('\n')

        elif args.format == 'csv':
            import csv
            writer = csv.writer(out)
            writer.writerow(['timestamp','event_type','severity','host','process','user','ip','message'])
            for e in filtered:
                writer.writerow([
                    e.timestamp, e.event_type.value, e.severity.value,
                    e.host, e.process, e.user, e.ip, e.message,
                ])

        else:  # text
            from colorama import Fore, Style, init
            init(autoreset=True)
            SEV_COLOR = {
                'CRITICAL': Fore.RED + Style.BRIGHT,
                'HIGH':     Fore.RED,
                'ERROR':    Fore.RED,
                'WARNING':  Fore.YELLOW,
                'INFO':     Fore.CYAN,
                'DEBUG':    Fore.WHITE,
                'UNKNOWN':  Fore.WHITE,
            }
            for e in filtered:
                color = SEV_COLOR.get(e.severity.value, Fore.WHITE)
                ts    = str(e.timestamp)[:19] if e.timestamp else '---'
                print(
                    f"{Fore.WHITE}{ts}  "
                    f"{color}[{e.severity.value:<8}]  "
                    f"{Fore.WHITE}[{e.event_type.value}]  "
                    f"{e.message[:120]}",
                    file=out,
                )
            print(f"\n{Fore.CYAN}Total: {len(filtered)} event(s)", file=sys.stderr)


if __name__ == '__main__':
    main()
