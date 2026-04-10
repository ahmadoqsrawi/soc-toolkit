"""Tests for WindowsEvtxParser."""
from pathlib import Path
from soc_toolkit.parsers.windows_evtx import WindowsEvtxParser
from soc_toolkit.models.event         import EventType

SAMPLE = Path(__file__).parent.parent.parent / 'samples' / 'security.xml.sample'


def get_events():
    return list(WindowsEvtxParser().parse(SAMPLE))

def test_parser_yields_events():
    assert len(get_events()) > 0

def test_parser_can_parse_xml():
    assert WindowsEvtxParser().can_parse(Path('security.xml'))
    assert not WindowsEvtxParser().can_parse(Path('auth.log'))

def test_failed_logon_detected():
    failures = [e for e in get_events() if e.event_type == EventType.AUTH_FAILURE]
    assert len(failures) >= 2

def test_successful_logon_detected():
    success = [e for e in get_events() if e.event_type == EventType.AUTH_SUCCESS]
    assert len(success) >= 1

def test_user_created_detected():
    created = [e for e in get_events() if e.event_type == EventType.USER_CREATED]
    assert len(created) >= 1

def test_ip_extracted():
    events = get_events()
    ips = [e.ip for e in events if e.ip]
    assert '45.33.32.156' in ips

def test_user_extracted():
    events = get_events()
    users = [e.user for e in events if e.user]
    assert 'Administrator' in users or 'deploy' in users

def test_host_extracted():
    events = get_events()
    assert any(e.host == 'WINSERVER01' for e in events)

def test_event_id_in_metadata():
    events = get_events()
    ids = [e.metadata.get('event_id') for e in events]
    assert 4625 in ids
    assert 4624 in ids
