"""Tests for CefParser (CEF and LEEF formats)."""
from pathlib import Path
from soc_toolkit.parsers.cef  import CefParser
from soc_toolkit.models.event import Severity

SAMPLE = Path(__file__).parent.parent.parent / 'samples' / 'events.cef.sample'


def get_events():
    return list(CefParser().parse(SAMPLE))

def test_parser_yields_events():
    assert len(get_events()) >= 4

def test_parser_can_parse_cef():
    assert CefParser().can_parse(Path('events.cef'))
    assert CefParser().can_parse(Path('firewall.leef'))

def test_cef_severity_mapped():
    events = get_events()
    sevs = [e.severity for e in events]
    assert Severity.ERROR in sevs or Severity.CRITICAL in sevs

def test_ip_extracted_from_cef():
    events = get_events()
    ips = [e.ip for e in events if e.ip]
    assert len(ips) > 0

def test_leef_parsed():
    events = get_events()
    leef_events = [e for e in events if e.metadata.get('format') == 'LEEF']
    assert len(leef_events) >= 1

def test_cef_format_in_metadata():
    events = get_events()
    cef_events = [e for e in events if e.metadata.get('format') == 'CEF']
    assert len(cef_events) >= 1

def test_vendor_in_metadata():
    events = get_events()
    vendors = [e.metadata.get('vendor', '') for e in events]
    assert any(v in ('Cisco', 'Fortinet', 'Microsoft') for v in vendors)
