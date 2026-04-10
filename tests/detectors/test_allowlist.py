"""Tests for AllowlistEngine and DetectionPipeline."""

import pytest
from datetime import datetime
from soc_toolkit.detectors.allowlist import AllowlistEngine, DetectionPipeline
from soc_toolkit.detectors.brute_force import BruteForceDetector
from soc_toolkit.models.event          import Event, EventType, Severity
from soc_toolkit.models.finding        import Finding, Confidence
from soc_toolkit.config.loader         import Config


def _finding(ips=None, users=None):
    events = [Event(
        event_type=EventType.AUTH_FAILURE, severity=Severity.ERROR,
        timestamp=datetime(2024,4,9,8,0,0), source='t', host='h',
        process='sshd', pid=None, user=(users or ['root'])[0],
        ip=(ips or ['1.2.3.4'])[0], message='fail', raw='',
    )]
    return Finding(
        rule_id='test', title='Test', severity=Severity.HIGH,
        confidence=Confidence.HIGH, description='d', recommendation='r',
        events=events,
    )


def test_allowlisted_ip_suppressed():
    cfg     = Config(allowed_ips=['1.2.3.4'])
    engine  = AllowlistEngine(cfg)
    finding = _finding(ips=['1.2.3.4'])
    result  = list(engine.filter(iter([finding])))
    assert result == []


def test_non_allowlisted_ip_passes():
    cfg     = Config(allowed_ips=['10.0.0.1'])
    engine  = AllowlistEngine(cfg)
    finding = _finding(ips=['1.2.3.4'])
    result  = list(engine.filter(iter([finding])))
    assert len(result) == 1


def test_allowlisted_user_suppressed():
    cfg     = Config(allowed_users=['nagios'])
    engine  = AllowlistEngine(cfg)
    finding = _finding(users=['nagios'])
    result  = list(engine.filter(iter([finding])))
    assert result == []


def test_mixed_ips_not_suppressed():
    """If only SOME IPs are allowlisted, finding should still pass."""
    cfg    = Config(allowed_ips=['10.0.0.1'])
    engine = AllowlistEngine(cfg)
    # Create finding with two events: one allowed IP, one not
    e1 = Event(event_type=EventType.AUTH_FAILURE, severity=Severity.ERROR,
               timestamp=datetime(2024,4,9,8,0,0), source='t', host='h',
               process='sshd', pid=None, user='root', ip='10.0.0.1',
               message='fail', raw='')
    e2 = Event(event_type=EventType.AUTH_FAILURE, severity=Severity.ERROR,
               timestamp=datetime(2024,4,9,8,0,1), source='t', host='h',
               process='sshd', pid=None, user='root', ip='5.5.5.5',
               message='fail', raw='')
    finding = Finding(rule_id='test', title='T', severity=Severity.HIGH,
                      confidence=Confidence.HIGH, description='d',
                      recommendation='r', events=[e1, e2])
    result = list(engine.filter(iter([finding])))
    assert len(result) == 1


def test_pipeline_runs_all_detectors():
    events = [Event(
        event_type=EventType.AUTH_FAILURE, severity=Severity.ERROR,
        timestamp=datetime(2024,4,9,8,0,i), source='t', host='h',
        process='sshd', pid=None, user='root', ip='9.9.9.9',
        message='Failed password for root from 9.9.9.9', raw='',
    ) for i in range(10)]
    cfg      = Config(brute_force_threshold=5)
    pipeline = DetectionPipeline(cfg)
    pipeline.add_detector(BruteForceDetector(cfg))
    findings = list(pipeline.run(iter(events)))
    assert len(findings) >= 1
