"""
Tests for Event and Finding models.
These validate the contract — not parser behavior.
"""

import pytest
from datetime import datetime
from soc_toolkit.models.event   import Event, EventType, Severity
from soc_toolkit.models.finding import Finding, Confidence


def make_event(**kwargs):
    defaults = dict(
        event_type = EventType.AUTH_FAILURE,
        severity   = Severity.ERROR,
        timestamp  = datetime(2024, 4, 9, 8, 3, 44),
        source     = 'test',
        host       = 'webserver',
        process    = 'sshd',
        pid        = '1234',
        user       = 'root',
        ip         = '1.2.3.4',
        message    = 'Failed password for root from 1.2.3.4',
        raw        = 'Apr  9 08:03:44 webserver sshd[1234]: Failed password for root from 1.2.3.4',
    )
    defaults.update(kwargs)
    return Event(**defaults)


def test_event_string_severity_coerced():
    e = make_event(severity='error')
    assert e.severity == Severity.ERROR


def test_event_string_event_type_coerced():
    e = make_event(event_type='auth_failure')
    assert e.event_type == EventType.AUTH_FAILURE


def test_finding_derives_timing_from_events():
    e1 = make_event(timestamp=datetime(2024, 4, 9, 8, 0, 0))
    e2 = make_event(timestamp=datetime(2024, 4, 9, 8, 5, 0))
    f = Finding(
        rule_id        = 'brute_force',
        title          = 'Brute force',
        severity       = Severity.HIGH,
        confidence     = Confidence.HIGH,
        description    = 'Test',
        recommendation = 'Block IP',
        events         = [e1, e2],
    )
    assert f.first_seen == datetime(2024, 4, 9, 8, 0, 0)
    assert f.last_seen  == datetime(2024, 4, 9, 8, 5, 0)


def test_finding_source_ips():
    e1 = make_event(ip='1.2.3.4')
    e2 = make_event(ip='5.6.7.8')
    e3 = make_event(ip='1.2.3.4')
    f = Finding(
        rule_id='test', title='t', severity=Severity.ERROR,
        confidence=Confidence.LOW, description='d',
        recommendation='r', events=[e1, e2, e3],
    )
    assert set(f.source_ips) == {'1.2.3.4', '5.6.7.8'}


def test_finding_event_count():
    events = [make_event() for _ in range(7)]
    f = Finding(
        rule_id='test', title='t', severity=Severity.ERROR,
        confidence=Confidence.LOW, description='d',
        recommendation='r', events=events,
    )
    assert f.event_count == 7
