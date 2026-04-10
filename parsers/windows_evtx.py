"""
parsers/windows_evtx.py
-----------------------
Parses Windows Security Event Log XML exports (.xml or .evtx exported to XML).

Targets the most security-relevant Event IDs:
  4624 - Successful logon
  4625 - Failed logon
  4688 - Process creation
  4720 - User account created
  4732 - Member added to security-enabled local group
  4776 - Credential validation (failed = brute force indicator)

Usage:
  Export from Event Viewer: Save Filtered Log File As -> XML
  Then: soc-parse --input security.xml --format text

For raw .evtx files install python-evtx:
  pip install python-evtx
  Then export to XML first or use evtx_dump.py
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib  import Path
from typing   import Iterator, Optional

from .base import BaseParser
from soc_toolkit.models.event import Event, EventType, Severity

# Windows XML namespace
_NS = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}

# Event ID to EventType + Severity mapping
_EVENT_MAP: dict[int, tuple[EventType, Severity]] = {
    4624: (EventType.AUTH_SUCCESS, Severity.INFO),
    4625: (EventType.AUTH_FAILURE, Severity.ERROR),
    4688: (EventType.GENERIC,      Severity.INFO),
    4720: (EventType.USER_CREATED, Severity.WARNING),
    4732: (EventType.GROUP_CHANGE, Severity.WARNING),
    4776: (EventType.AUTH_FAILURE, Severity.ERROR),
}

_LOGON_TYPE = {
    '2':  'Interactive',
    '3':  'Network',
    '4':  'Batch',
    '5':  'Service',
    '7':  'Unlock',
    '8':  'NetworkCleartext',
    '9':  'NewCredentials',
    '10': 'RemoteInteractive',
    '11': 'CachedInteractive',
}


def _get_data(event_elem, name: str) -> str:
    """Extract a named EventData field."""
    el = event_elem.find(
        f'.//e:EventData/e:Data[@Name="{name}"]', _NS
    )
    return (el.text or '').strip() if el is not None else ''


def _parse_ts(ts_str: str) -> Optional[datetime]:
    if not ts_str:
        return None
    # Format: 2024-04-09T08:03:44.123456789Z
    ts_str = re.sub(r'\.\d+Z?$', '', ts_str).replace('T', ' ')
    try:
        return datetime.strptime(ts_str, '%Y-%m-%d %H:%M:%S')
    except ValueError:
        return None


class WindowsEvtxParser(BaseParser):

    def can_parse(self, path: Path) -> bool:
        return path.suffix.lower() in ('.xml', '.evtx_xml')

    def parse(self, path: Path) -> Iterator[Event]:
        with self.open(path) as f:
            content = f.read()

        # Handle both single <Event> and <Events> wrapper
        if '<Events>' not in content and '<Event ' in content:
            content = f'<Events>{content}</Events>'

        try:
            root = ET.fromstring(content)
        except ET.ParseError:
            return

        # Root might be <Events> or a single <Event>
        events_iter = (
            root.findall('e:Event', _NS)
            if root.tag.endswith('Events')
            else [root]
        )

        for elem in events_iter:
            yield from self._parse_event(elem, str(path))

    def _parse_event(self, elem, source: str) -> Iterator[Event]:
        sys_el = elem.find('e:System', _NS)
        if sys_el is None:
            return

        event_id_el = sys_el.find('e:EventID', _NS)
        if event_id_el is None:
            return

        try:
            event_id = int(event_id_el.text or '0')
        except ValueError:
            return

        etype, esev = _EVENT_MAP.get(event_id, (EventType.GENERIC, Severity.UNKNOWN))

        ts_str = ''
        ts_el  = sys_el.find('e:TimeCreated', _NS)
        if ts_el is not None:
            ts_str = ts_el.get('SystemTime', '')

        computer_el = sys_el.find('e:Computer', _NS)
        host = (computer_el.text or '').strip() if computer_el is not None else ''

        # Extract user and IP based on event ID
        user = ''
        ip   = ''

        if event_id in (4624, 4625, 4776):
            user = (
                _get_data(elem, 'TargetUserName') or
                _get_data(elem, 'SubjectUserName')
            )
            ip = (
                _get_data(elem, 'IpAddress') or
                _get_data(elem, 'WorkstationName')
            )
            logon_type = _LOGON_TYPE.get(
                _get_data(elem, 'LogonType'), ''
            )
            status = _get_data(elem, 'Status')
            message = (
                f"EventID {event_id}: "
                f"{'Failed' if event_id == 4625 else 'Successful'} logon "
                f"for {user or 'unknown'} from {ip or 'unknown'}"
                f"{' [' + logon_type + ']' if logon_type else ''}"
                f"{' Status=' + status if status else ''}"
            )

        elif event_id == 4688:
            user    = _get_data(elem, 'SubjectUserName')
            process = _get_data(elem, 'NewProcessName')
            cmdline = _get_data(elem, 'CommandLine')
            message = (
                f"EventID 4688: Process created by {user or 'unknown'}: "
                f"{process}"
                f"{' | CMD: ' + cmdline if cmdline else ''}"
            )

        elif event_id == 4720:
            user        = _get_data(elem, 'TargetUserName')
            created_by  = _get_data(elem, 'SubjectUserName')
            message = (
                f"EventID 4720: User account created: {user or 'unknown'} "
                f"by {created_by or 'unknown'}"
            )

        elif event_id == 4732:
            user    = _get_data(elem, 'MemberName')
            group   = _get_data(elem, 'TargetUserName')
            message = (
                f"EventID 4732: {user or 'unknown'} added to group "
                f"{group or 'unknown'}"
            )

        else:
            message = f"EventID {event_id}"

        # Clean up placeholder values Windows uses
        for placeholder in ('-', '-\\-', 'N/A', 'NULL SID'):
            if user == placeholder:
                user = ''
            if ip == placeholder:
                ip = ''

        # Skip machine accounts (end with $) for auth events
        if user and user.endswith('$') and event_id in (4624, 4625):
            return

        yield Event(
            event_type = etype,
            severity   = esev,
            timestamp  = _parse_ts(ts_str),
            source     = source,
            host       = host,
            process    = f"EventID-{event_id}",
            pid        = None,
            user       = user or None,
            ip         = ip or None,
            message    = message,
            raw        = ET.tostring(elem, encoding='unicode'),
            metadata   = {'event_id': event_id},
        )
