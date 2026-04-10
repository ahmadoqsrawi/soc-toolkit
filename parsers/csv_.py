"""
parsers/csv_.py
---------------
Parses CSV log exports. Auto-detects common field name variants.
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing  import Iterator

from .base import BaseParser
from soc_toolkit.models.event import Event, EventType, Severity


def _col(row: dict, *keys: str, default: str = '') -> str:
    for k in keys:
        if k in row:
            return str(row[k])
    return default


class CsvParser(BaseParser):

    def can_parse(self, path: Path) -> bool:
        return path.suffix.lower() in ('.csv', '.tsv')

    def parse(self, path: Path) -> Iterator[Event]:
        with self.open(path) as f:
            delimiter = '\t' if path.suffix.lower() == '.tsv' else ','
            reader = csv.DictReader(f, delimiter=delimiter)
            for i, row in enumerate(reader, 1):
                message = _col(row, 'message', 'msg', 'event', 'description') \
                          or ' '.join(str(v) for v in row.values())
                yield Event(
                    event_type = EventType.GENERIC,
                    severity   = Severity.UNKNOWN,
                    timestamp  = None,
                    source     = str(path),
                    host       = _col(row, 'host', 'hostname', 'src'),
                    process    = _col(row, 'process', 'service'),
                    pid        = _col(row, 'pid') or None,
                    user       = _col(row, 'user', 'username') or None,
                    ip         = _col(row, 'ip', 'src_ip', 'remote_ip') or None,
                    message    = message,
                    raw        = ','.join(str(v) for v in row.values()),
                    metadata   = {'line_number': i, 'columns': list(row.keys())},
                )
