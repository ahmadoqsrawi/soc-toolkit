"""
parsers/json_.py
----------------
Parses JSON and JSON-lines log files.
Handles both array-of-objects and newline-delimited formats.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib  import Path
from typing   import Iterator, Any, Optional

from .base import BaseParser
from soc_toolkit.models.event import Event, EventType, Severity


_SEV_MAP = {
    'critical': Severity.CRITICAL,
    'fatal':    Severity.CRITICAL,
    'error':    Severity.ERROR,
    'err':      Severity.ERROR,
    'warning':  Severity.WARNING,
    'warn':     Severity.WARNING,
    'info':     Severity.INFO,
    'notice':   Severity.INFO,
    'debug':    Severity.DEBUG,
}

# Try each format in order — NO slicing, pass full string each time
_TS_FORMATS = [
    '%Y-%m-%dT%H:%M:%S.%fZ',
    '%Y-%m-%dT%H:%M:%SZ',
    '%Y-%m-%dT%H:%M:%S.%f',
    '%Y-%m-%dT%H:%M:%S',
    '%Y-%m-%d %H:%M:%S',
]


def _get(obj: dict, *keys: str, default: Any = '') -> Any:
    for k in keys:
        if k in obj:
            return obj[k]
    return default


def _parse_severity(obj: dict) -> Severity:
    raw = str(_get(obj, 'level', 'severity', 'loglevel', 'log_level', default=''))
    return _SEV_MAP.get(raw.lower(), Severity.UNKNOWN)


def _parse_timestamp(obj: dict) -> Optional[datetime]:
    raw = str(_get(obj, 'timestamp', 'time', '@timestamp', 'date', default=''))
    if not raw:
        return None
    for fmt in _TS_FORMATS:
        try:
            return datetime.strptime(raw, fmt)
        except ValueError:
            continue
    return None


class JsonParser(BaseParser):

    def can_parse(self, path: Path) -> bool:
        return path.suffix.lower() in ('.json', '.jsonl', '.ndjson')

    def parse(self, path: Path) -> Iterator[Event]:
        with self.open(path) as f:
            content = f.read()

        # Try full JSON array first, fall back to JSON-lines
        try:
            records = json.loads(content)
            if isinstance(records, dict):
                records = [records]
        except json.JSONDecodeError:
            records = []
            for line in content.splitlines():
                line = line.strip()
                if line:
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass

        for i, obj in enumerate(records, 1):
            if not isinstance(obj, dict):
                continue

            message = str(_get(obj, 'message', 'msg', 'event', default=str(obj)))

            yield Event(
                event_type = EventType.GENERIC,
                severity   = _parse_severity(obj),
                timestamp  = _parse_timestamp(obj),
                source     = str(path),
                host       = str(_get(obj, 'host', 'hostname', default='')),
                process    = str(_get(obj, 'process', 'service', 'app', default='')),
                pid        = str(_get(obj, 'pid', default='')) or None,
                user       = str(_get(obj, 'user', 'username', default='')) or None,
                ip         = str(_get(obj, 'ip', 'src_ip', 'remote_ip', default='')) or None,
                message    = message,
                raw        = json.dumps(obj),
                metadata   = {'line_number': i},
            )
