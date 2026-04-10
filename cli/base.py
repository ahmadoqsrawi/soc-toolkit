"""
cli/base.py
-----------
The CLI contract. Every script in the toolkit calls build_base_parser()
and adds its own flags on top. This guarantees identical flag behavior
across all entry points.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def build_base_parser(
    description: str,
    extra_formats: list[str] | None = None,
) -> argparse.ArgumentParser:
    """
    Return an ArgumentParser pre-loaded with the standard flags.
    Pass extra_formats to extend the --format choices beyond the defaults.
    """
    formats = ['text', 'json', 'csv']
    if extra_formats:
        formats = formats + [f for f in extra_formats if f not in formats]

    p = argparse.ArgumentParser(
        description=description,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument('--input',   '-i', required=True, type=Path,
                   metavar='FILE', help='Log file to process')
    p.add_argument('--output',  '-o', default=None,  type=Path,
                   metavar='FILE', help='Output file (default: stdout)')
    p.add_argument('--format',  '-f', choices=formats, default='text',
                   help=f'Output format (default: text)')
    p.add_argument('--config',  '-c', default=None, type=Path,
                   metavar='FILE', help='YAML config file')
    p.add_argument('--verbose', '-v', action='store_true',
                   help='Enable verbose output')
    return p


def resolve_output(args: argparse.Namespace):
    if args.output:
        return open(args.output, 'w')
    return sys.stdout


def validate_input(args: argparse.Namespace) -> Path:
    path = Path(args.input)
    if not path.exists():
        print(f"[ERROR] Input file not found: {path}", file=sys.stderr)
        sys.exit(1)
    return path
