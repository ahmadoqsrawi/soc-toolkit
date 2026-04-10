"""
parsers/cef.py
--------------
Parses CEF (Common Event Format) and LEEF (Log Event Extended Format) logs.

CEF is used by ArcSight, many firewalls, and IDS/IPS systems.
LEEF is used by IBM QRadar.

CEF format:
  CEF:Version|Device Vendor|Device Product|Device Version|SignatureID|Name|Severity|Extension

LEEF format:
  LEEF:Version|Vendor|Product|Version|EventID|key=value\tkey=value

Both are widely used in enterprise SOC environments for forwarding
security events from network devices, firewalls, and endpoint tools.
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib  import Path
from typing   import Iterator, Optional

from .base import BaseParser
from soc_toolkit.models.event import Event, EventType, Severity

# CEF severity (0-10) to our Severity enum
def _cef_severity(sev_str: str) -> Severity:
    try:
        sev = int(sev_str)
    except (ValueError, TypeError):
        sev_lower = str(sev_str).lower()
        if sev_lower in ('high', 'critical', 'emergency'):
            return Severity.ERROR
        if sev_lower in ('medium', 'warning'):
            return Severity.WARNING
        return Severity.UNKNOWN

    if sev >= 9:  return Severity.CRITICAL
    if sev >= 7:  return Severity.ERROR
    if sev >= 4:  return Severity.WARNING
    if sev >= 1:  return Severity.INFO
    return Severity.DEBUG


def _parse_cef_extension(ext: str) -> dict:
    """Parse CEF extension key=value pairs, handling escaped characters."""
    result = {}
    # CEF extension: key=value pairs, value ends at next unescaped key= or end
    pattern = re.compile(r'(\w+)=((?:[^\\=]|\\.)*?)(?=\s+\w+=|$)')
    for m in pattern.finditer(ext):
        key = m.group(1)
        val = m.group(2).replace('\\=', '=').replace('\\n', '\n').strip()
        result[key] = val
    return result


def _extract_ip_from_cef(ext: dict) -> Optional[str]:
    for key in ('src', 'sourceAddress', 'dst', 'destinationAddress',
                'shost', 'dhost'):
        val = ext.get(key, '')
        if val and re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', val):
            return val
    return None


def _extract_user_from_cef(ext: dict) -> Optional[str]:
    for key in ('suser', 'duser', 'sourceUserName', 'destinationUserName',
                'act', 'spriv'):
        val = ext.get(key, '')
        if val:
            return val
    return None


def _infer_event_type_cef(name: str, sig_id: str, ext: dict) -> EventType:
    name_lower = name.lower()
    sig_lower  = sig_id.lower()
    combined   = name_lower + ' ' + sig_lower

    if any(w in combined for w in ('login fail', 'logon fail',
                                   'auth fail', 'invalid', 'denied')):
        return EventType.AUTH_FAILURE
    if any(w in combined for w in ('login success', 'logon success',
                                   'auth success', 'accepted')):
        return EventType.AUTH_SUCCESS
    if any(w in combined for w in ('sudo', 'privilege', 'escalat')):
        return EventType.SUDO
    if any(w in combined for w in ('user creat', 'useradd', 'account creat')):
        return EventType.USER_CREATED
    return EventType.GENERIC


# ── CEF Parser ──────────────────────────────────────────────────────────────

_CEF_HEADER = re.compile(
    r'^CEF:(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)$'
)

_LEEF_HEADER = re.compile(
    r'^LEEF:([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)$'
)

# Syslog prefix before CEF/LEEF payload
_SYSLOG_PREFIX = re.compile(
    r'^(?:\w{3}\s+\d+\s+[\d:]+\s+\S+\s+)?(?:CEF:|LEEF:)'
)


class CefParser(BaseParser):

    def can_parse(self, path: Path) -> bool:
        name = path.name.lower()
        return (
            name.endswith('.cef') or
            name.endswith('.leef') or
            'cef' in name or
            'leef' in name
        )

    def parse(self, path: Path) -> Iterator[Event]:
        with self.open(path) as f:
            for line_num, raw_line in enumerate(f, 1):
                line = raw_line.strip()
                if not line:
                    continue

                # Strip syslog header if present
                cef_start = line.find('CEF:')
                leef_start = line.find('LEEF:')

                if cef_start != -1:
                    event = self._parse_cef(line[cef_start:], str(path), line)
                elif leef_start != -1:
                    event = self._parse_leef(line[leef_start:], str(path), line)
                else:
                    continue

                if event:
                    yield event

    def _parse_cef(self, line: str, source: str, raw: str) -> Optional[Event]:
        m = _CEF_HEADER.match(line)
        if not m:
            return None

        vendor, product, version, sig_id, name, severity, ext_str = (
            m.group(2), m.group(3), m.group(4),
            m.group(5), m.group(6), m.group(7), m.group(8)
        )

        ext    = _parse_cef_extension(ext_str)
        esev   = _cef_severity(severity)
        etype  = _infer_event_type_cef(name, sig_id, ext)
        ip     = _extract_ip_from_cef(ext)
        user   = _extract_user_from_cef(ext)

        # Timestamp from extension field rt (receipt time) or end
        ts = None
        for ts_key in ('rt', 'end', 'start', 'deviceReceiptTime'):
            ts_val = ext.get(ts_key, '')
            if ts_val:
                try:
                    ts = datetime.fromtimestamp(int(ts_val) / 1000)
                    break
                except (ValueError, OSError):
                    pass

        message = (
            f"[CEF] {vendor}/{product} | {name} | SigID={sig_id}"
            + (f" | src={ip}" if ip else '')
            + (f" | user={user}" if user else '')
        )

        return Event(
            event_type = etype,
            severity   = esev,
            timestamp  = ts,
            source     = source,
            host       = ext.get('dhost', ext.get('shost', '')),
            process    = f"{vendor}/{product}",
            pid        = None,
            user       = user,
            ip         = ip,
            message    = message,
            raw        = raw,
            metadata   = {
                'format':   'CEF',
                'vendor':   vendor,
                'product':  product,
                'sig_id':   sig_id,
                'cef_name': name,
                'ext':      ext,
            },
        )

    def _parse_leef(self, line: str, source: str, raw: str) -> Optional[Event]:
        m = _LEEF_HEADER.match(line)
        if not m:
            return None

        vendor, product, version, event_id, attr_str = (
            m.group(2), m.group(3), m.group(4), m.group(5), m.group(6)
        )

        # LEEF attributes are tab-separated key=value pairs
        attrs = {}
        for pair in re.split(r'\t', attr_str):
            if '=' in pair:
                k, _, v = pair.partition('=')
                attrs[k.strip()] = v.strip()

        sev_str = attrs.get('sev', attrs.get('severity', '5'))
        esev    = _cef_severity(sev_str)
        ip      = attrs.get('src', attrs.get('srcIP', None))
        user    = attrs.get('usrName', attrs.get('suser', None))

        message = (
            f"[LEEF] {vendor}/{product} | EventID={event_id}"
            + (f" | src={ip}"   if ip   else '')
            + (f" | user={user}" if user else '')
        )

        return Event(
            event_type = EventType.GENERIC,
            severity   = esev,
            timestamp  = None,
            source     = source,
            host       = attrs.get('dst', ''),
            process    = f"{vendor}/{product}",
            pid        = None,
            user       = user,
            ip         = ip,
            message    = message,
            raw        = raw,
            metadata   = {
                'format':   'LEEF',
                'vendor':   vendor,
                'product':  product,
                'event_id': event_id,
                'attrs':    attrs,
            },
        )
