"""Tests for AuthSuccessDetector."""
from datetime import datetime
from soc_toolkit.detectors.auth_success import AuthSuccessDetector
from soc_toolkit.models.event           import Event, EventType, Severity
from soc_toolkit.config.loader          import Config


def _success(ip='1.2.3.4', user='deploy', i=0):
    return Event(
        event_type=EventType.AUTH_SUCCESS, severity=Severity.INFO,
        timestamp=datetime(2024,4,9,8,4,i), source='test', host='srv',
        process='sshd', pid=None, user=user, ip=ip,
        message=f'Accepted password for {user} from {ip}', raw='',
    )

def _fail(ip='1.2.3.4', user='root', i=0):
    return Event(
        event_type=EventType.AUTH_FAILURE, severity=Severity.ERROR,
        timestamp=datetime(2024,4,9,8,3,i), source='test', host='srv',
        process='sshd', pid=None, user=user, ip=ip,
        message=f'Failed password for {user} from {ip}', raw='',
    )

def _detect(events, **kw):
    return list(AuthSuccessDetector(Config(**kw)).analyze(iter(events)))


def test_detects_successful_login():
    findings = _detect([_success()])
    assert len(findings) == 1
    assert findings[0].rule_id == 'auth_success'

def test_finding_is_info_severity():
    findings = _detect([_success()])
    assert findings[0].severity == Severity.INFO

def test_finding_has_required_fields():
    f = _detect([_success()])[0]
    assert f.rule_id and f.title and f.severity
    assert f.confidence and f.description and f.recommendation
    assert f.events

def test_multiple_logins_produce_multiple_findings():
    events = [_success(user='alice'), _success(user='bob')]
    assert len(_detect(events)) == 2

def test_auth_failure_not_detected():
    assert _detect([_fail()]) == []

def test_allowlisted_ip_suppressed():
    assert _detect([_success(ip='10.0.0.1')],
                   allowed_ips=['10.0.0.1']) == []

def test_allowlisted_user_suppressed():
    assert _detect([_success(user='nagios')],
                   allowed_users=['nagios']) == []

def test_ip_in_metadata():
    f = _detect([_success(ip='5.5.5.5')])[0]
    assert f.metadata['ip'] == '5.5.5.5'

def test_user_in_metadata():
    f = _detect([_success(user='deploy')])[0]
    assert f.metadata['user'] == 'deploy'
