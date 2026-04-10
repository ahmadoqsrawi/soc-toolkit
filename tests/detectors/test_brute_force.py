"""Tests for BruteForceDetector."""

import pytest
from datetime import datetime
from soc_toolkit.detectors.brute_force import BruteForceDetector
from soc_toolkit.models.event          import Event, EventType, Severity
from soc_toolkit.config.loader         import Config


def _fail(ip='1.2.3.4', user='root', ts=None, i=0):
    return Event(
        event_type=EventType.AUTH_FAILURE, severity=Severity.ERROR,
        timestamp=datetime(2024, 4, 9, 8, 0, i) if ts is None else ts,
        source='test', host='srv', process='sshd', pid=None,
        user=user, ip=ip, message=f'Failed password for {user} from {ip}', raw='',
    )


def _detect(events, **cfg_kwargs):
    cfg = Config(**cfg_kwargs)
    return list(BruteForceDetector(cfg).analyze(iter(events)))


# ── True-positive tests ────────────────────────────────────────────────────

def test_detects_basic_brute_force():
    events = [_fail(i=i) for i in range(10)]
    findings = _detect(events, brute_force_threshold=5)
    assert len(findings) == 1
    assert findings[0].rule_id == 'brute_force'
    assert '1.2.3.4' in findings[0].title


def test_finding_has_required_fields():
    events   = [_fail(i=i) for i in range(6)]
    findings = _detect(events, brute_force_threshold=5)
    f = findings[0]
    assert f.rule_id
    assert f.title
    assert f.severity
    assert f.confidence
    assert f.description
    assert f.recommendation
    assert f.events


def test_severity_critical_on_high_volume():
    events   = [_fail(i=i) for i in range(20)]
    findings = _detect(events, brute_force_threshold=5)
    assert findings[0].severity == Severity.CRITICAL


def test_severity_high_on_burst():
    events   = [_fail(i=i) for i in range(6)]
    findings = _detect(events, brute_force_threshold=5)
    assert findings[0].severity in (Severity.HIGH, Severity.CRITICAL)


def test_multiple_ips_produce_multiple_findings():
    events = [_fail(ip='1.1.1.1', i=i) for i in range(6)] + \
             [_fail(ip='2.2.2.2', i=i) for i in range(6)]
    findings = _detect(events, brute_force_threshold=5)
    assert len(findings) == 2
    ips = {f.metadata['ip'] for f in findings}
    assert ips == {'1.1.1.1', '2.2.2.2'}


def test_targeted_users_in_metadata():
    events = [_fail(user='root', i=i) for i in range(3)] + \
             [_fail(user='admin', i=i+3) for i in range(3)]
    findings = _detect(events, brute_force_threshold=5)
    assert len(findings) == 1
    assert 'root'  in findings[0].metadata['targeted_users']
    assert 'admin' in findings[0].metadata['targeted_users']


def test_first_and_last_seen_set():
    events   = [_fail(i=i) for i in range(6)]
    findings = _detect(events, brute_force_threshold=5)
    f = findings[0]
    assert f.first_seen is not None
    assert f.last_seen  is not None
    assert f.first_seen <= f.last_seen


# ── True-negative tests ────────────────────────────────────────────────────

def test_below_threshold_no_finding():
    events   = [_fail(i=i) for i in range(4)]
    findings = _detect(events, brute_force_threshold=5)
    assert findings == []


def test_allowlisted_ip_suppressed():
    events   = [_fail(ip='10.0.0.1', i=i) for i in range(10)]
    findings = _detect(events, brute_force_threshold=5, allowed_ips=['10.0.0.1'])
    assert findings == []


def test_events_without_ip_ignored():
    events = []
    for i in range(10):
        e = _fail(i=i)
        e.ip = None
        events.append(e)
    findings = _detect(events, brute_force_threshold=5)
    assert findings == []


def test_non_auth_failure_events_ignored():
    events   = [Event(
        event_type=EventType.AUTH_SUCCESS, severity=Severity.INFO,
        timestamp=datetime(2024,4,9,8,0,i), source='test', host='srv',
        process='sshd', pid=None, user='root', ip='1.2.3.4',
        message='Accepted password', raw='',
    ) for i in range(10)]
    findings = _detect(events, brute_force_threshold=5)
    assert findings == []
