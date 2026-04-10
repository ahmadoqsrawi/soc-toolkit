"""
parsers/router.py
-----------------
Auto-selects the right parser for a given file.
Tries each registered parser in order, returns the first match.
"""

from __future__ import annotations

from pathlib import Path

from .base   import BaseParser
from .syslog import SyslogParser
from .json_  import JsonParser
from .csv_   import CsvParser


_REGISTRY: list[BaseParser] = [
    JsonParser(),
    CsvParser(),
    SyslogParser(),    # syslog last — its can_parse is broad
]


def get_parser(path: Path) -> BaseParser:
    """Return the appropriate parser for the given file path."""
    for parser in _REGISTRY:
        if parser.can_parse(path):
            return parser
    # syslog is a reasonable last-resort fallback for unknown text files
    return SyslogParser()
