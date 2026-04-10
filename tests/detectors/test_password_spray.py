"""Tests for PasswordSprayDetector."""

import pytest
from datetime import datetime
from soc_toolkit.detectors.password_spray import PasswordSprayDetector
from soc_toolkit.models.event             import Event, EventType, Severity
from soc_toolkit.config.loader            import Config


def _fail(ip='1.2.3.4', user='root', i=0):
    return Event(
        event_type=EventType.AUTH_FAILURE, severity=Severity.ERROR,
        timestamp=datetime(2024, 4, 9, 8, 0, i),
        source='test', host='srv', process='sshd', pid=None,
        user=user, ip=ip,
        message=f'Failed password for {user} from {ip}', raw='',
    )


def _spray_events(ip='5.5.5.5', n_users=12):
    return [_fail(ip=ip, user=f'user{i:03d}', i=i) for i in range(n_users)]


def _detect(events, **cfg_kwargs):
    cfg = Config(**cfg_kwargs)
    return list(PasswordSprayDetector(cfg).analyze(iter(events)))


def test_detects_spray():
    findings = _detect(_spray_events(), spray_threshold=10)
    assert len(findings) == 1
    assert findings[0].rule_id == 'password_spray'


def test_distinct_user_count_in_metadata():
    findings = _detect(_spray_events(n_users=15), spray_threshold=10)
    assert findings[0].metadata['distinct_users'] == 15


def test_spray_not_triggered_few_users():
    events   = [_fail(user='root', i=i) for i in range(20)]
    findings = _detect(events, spray_threshold=10)
    assert findings == []


def test_allowlisted_ip_suppressed():
    events   = _spray_events(ip='10.0.0.1')
    findings = _detect(events, spray_threshold=10, allowed_ips=['10.0.0.1'])
    assert findings == []


def test_finding_has_all_required_fields():
    findings = _detect(_spray_events(), spray_threshold=10)
    f = findings[0]
    assert f.rule_id and f.title and f.severity and f.confidence
    assert f.description and f.recommendation and f.events


def test_no_user_events_not_counted():
    events = []
    for i in range(15):
        e = _fail(user=f'u{i}', i=i)
        e.user = None
        events.append(e)
    findings = _detect(events, spray_threshold=10)
    assert findings == []
