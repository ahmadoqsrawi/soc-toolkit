"""Tests for PrivEscDetector."""

import pytest
from datetime import datetime
from soc_toolkit.detectors.priv_esc import PrivEscDetector
from soc_toolkit.models.event       import Event, EventType, Severity
from soc_toolkit.config.loader      import Config


def _sudo(user='deploy', command='/bin/bash', i=0):
    return Event(
        event_type=EventType.SUDO, severity=Severity.INFO,
        timestamp=datetime(2024, 4, 9, 8, 5, i),
        source='test', host='srv', process='sudo', pid=None,
        user=user, ip=None,
        message=f'{user} : TTY=pts/0 ; USER=root ; COMMAND={command}',
        raw='',
    )


def _failed_sudo(user='deploy', i=0):
    return Event(
        event_type=EventType.SUDO, severity=Severity.WARNING,
        timestamp=datetime(2024, 4, 9, 8, 5, i),
        source='test', host='srv', process='sudo', pid=None,
        user=user, ip=None,
        message=f'pam_unix(sudo:auth): authentication failure; user={user}',
        raw='',
    )


def _user_created(user='backdoor', i=0):
    return Event(
        event_type=EventType.USER_CREATED, severity=Severity.WARNING,
        timestamp=datetime(2024, 4, 9, 8, 6, i),
        source='test', host='srv', process='useradd', pid=None,
        user=user, ip=None,
        message=f'new user: name={user}, UID=1337',
        raw='',
    )


def _detect(events):
    return list(PrivEscDetector(Config()).analyze(iter(events)))


def test_detects_high_risk_sudo():
    findings = _detect([_sudo(command='/bin/bash')])
    titles   = [f.title for f in findings]
    assert any('high-risk' in t.lower() for t in titles)


def test_high_risk_sudo_is_critical():
    findings = _detect([_sudo(command='/bin/bash')])
    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(critical) >= 1


def test_detects_user_creation():
    findings = _detect([_user_created('backdoor')])
    assert any('backdoor' in f.title for f in findings)


def test_user_creation_is_high_severity():
    findings = _detect([_user_created()])
    creation = [f for f in findings if 'created' in f.title.lower()]
    assert creation[0].severity == Severity.HIGH


def test_failed_sudo_threshold():
    events   = [_failed_sudo(i=i) for i in range(5)]
    findings = _detect(events)
    failed   = [f for f in findings if 'failed sudo' in f.title.lower()]
    assert len(failed) == 1


def test_failed_sudo_below_threshold_no_finding():
    events   = [_failed_sudo(i=i) for i in range(2)]
    findings = _detect(events)
    failed   = [f for f in findings if 'failed sudo' in f.title.lower()]
    assert failed == []


def test_allowed_user_suppressed():
    cfg      = Config(allowed_users=['deploy'])
    findings = list(PrivEscDetector(cfg).analyze(iter([_sudo(user='deploy')])))
    assert findings == []


def test_normal_sudo_is_medium():
    findings = _detect([_sudo(command='/usr/bin/systemctl')])
    normal   = [f for f in findings if 'high-risk' not in f.title.lower()
                and 'sudo' in f.title.lower()]
    if normal:
        assert normal[0].severity == Severity.MEDIUM


def test_all_findings_have_required_fields():
    events   = [_sudo(), _user_created()]
    findings = _detect(events)
    for f in findings:
        assert f.rule_id and f.title and f.severity
        assert f.confidence and f.description and f.recommendation
