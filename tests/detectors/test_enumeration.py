"""Tests for EnumerationDetector."""

import pytest
from datetime import datetime
from soc_toolkit.detectors.enumeration import EnumerationDetector
from soc_toolkit.models.event          import Event, EventType, Severity
from soc_toolkit.config.loader         import Config


def _invalid(ip='9.9.9.9', user='ghost', i=0):
    return Event(
        event_type=EventType.AUTH_FAILURE, severity=Severity.WARNING,
        timestamp=datetime(2024, 4, 9, 8, 0, i),
        source='test', host='srv', process='sshd', pid=None,
        user=user, ip=ip,
        message=f'Invalid user {user} from {ip}', raw='',
    )


def _valid_fail(ip='9.9.9.9', user='root', i=0):
    return Event(
        event_type=EventType.AUTH_FAILURE, severity=Severity.ERROR,
        timestamp=datetime(2024, 4, 9, 8, 0, i),
        source='test', host='srv', process='sshd', pid=None,
        user=user, ip=ip,
        message=f'Failed password for {user} from {ip}', raw='',
    )


def _detect(events):
    return list(EnumerationDetector(Config()).analyze(iter(events)))


def test_detects_enumeration():
    events   = [_invalid(user=f'ghost{i}', i=i) for i in range(8)]
    findings = _detect(events)
    assert len(findings) == 1
    assert findings[0].rule_id == 'enumeration'


def test_below_threshold_no_finding():
    events   = [_invalid(user=f'ghost{i}', i=i) for i in range(3)]
    findings = _detect(events)
    assert findings == []


def test_valid_failures_not_counted_as_enumeration():
    # Normal brute force against 'root' should NOT trigger enumeration
    events   = [_valid_fail(user='root', i=i) for i in range(20)]
    findings = _detect(events)
    assert findings == []


def test_finding_lists_probed_users():
    events   = [_invalid(user=f'svc{i}', i=i) for i in range(6)]
    findings = _detect(events)
    assert 'svc0' in findings[0].metadata['invalid_users']


def test_allowlisted_ip_suppressed():
    events   = [_invalid(ip='10.0.0.5', user=f'u{i}', i=i) for i in range(8)]
    cfg      = Config(allowed_ips=['10.0.0.5'])
    findings = list(EnumerationDetector(cfg).analyze(iter(events)))
    assert findings == []
