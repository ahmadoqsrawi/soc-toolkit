"""
Tests for SyslogParser.
Every test uses the sample corpus in samples/ — no inline log strings.
"""

import pytest
from pathlib import Path
from soc_toolkit.parsers.syslog import SyslogParser
from soc_toolkit.models.event   import EventType, Severity

SAMPLE = Path(__file__).parent.parent.parent / 'samples' / 'auth.log.sample'


@pytest.fixture
def events():
    parser = SyslogParser()
    return list(parser.parse(SAMPLE))


def test_parser_yields_events(events):
    assert len(events) > 0


def test_all_events_have_required_fields(events):
    for e in events:
        assert e.source != ''
        assert e.message != ''
        assert e.raw != ''
        assert e.event_type is not None
        assert e.severity is not None


def test_auth_failure_detected(events):
    failures = [e for e in events if e.event_type == EventType.AUTH_FAILURE]
    assert len(failures) >= 10


def test_auth_success_detected(events):
    successes = [e for e in events if e.event_type == EventType.AUTH_SUCCESS]
    assert len(successes) >= 1


def test_sudo_detected(events):
    sudos = [e for e in events if e.event_type == EventType.SUDO]
    assert len(sudos) >= 2


def test_user_created_detected(events):
    created = [e for e in events if e.event_type == EventType.USER_CREATED]
    assert len(created) >= 1
    assert any(e.user == 'backdoor' for e in created)


def test_ip_extracted_from_failure(events):
    failures = [e for e in events if e.event_type == EventType.AUTH_FAILURE and e.ip]
    assert len(failures) > 0
    assert any(e.ip == '45.33.32.156' for e in failures)


def test_timestamp_parsed(events):
    timed = [e for e in events if e.timestamp is not None]
    assert len(timed) > 0


def test_session_events_detected(events):
    sessions = [e for e in events if e.event_type in
                (EventType.SESSION_OPEN, EventType.SESSION_CLOSE)]
    assert len(sessions) >= 1


def test_parser_can_parse_sample(tmp_path):
    parser = SyslogParser()
    assert parser.can_parse(SAMPLE)
    assert not parser.can_parse(tmp_path / 'data.json')
