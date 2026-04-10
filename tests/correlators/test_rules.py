"""Tests for built-in correlation rules against realistic finding sequences."""

import pytest
from datetime import datetime
from soc_toolkit.correlators.engine import CorrelationEngine
from soc_toolkit.correlators.rules  import (
    BRUTE_THEN_SUCCESS, SUCCESS_THEN_PRIV_ESC,
    FULL_ATTACK_CHAIN, ENUM_THEN_BRUTE, ALL_RULES,
)
from soc_toolkit.models.finding import Finding, Confidence
from soc_toolkit.models.event   import Event, EventType, Severity


def _ev(ts_min=0, ip='5.5.5.5', user='root', etype=EventType.AUTH_FAILURE):
    from datetime import timedelta
    return Event(
        event_type=etype, severity=Severity.ERROR,
        timestamp=datetime(2024, 4, 9, 8, 0, 0) + timedelta(minutes=ts_min),
        source='test', host='srv', process='sshd', pid=None,
        user=user, ip=ip, message='test', raw='',
    )


def _f(rule_id, ts_sec=0, ip='5.5.5.5', user='root', sev=Severity.HIGH):
    return Finding(
        rule_id=rule_id, title=rule_id, severity=sev,
        confidence=Confidence.HIGH, description='d', recommendation='r',
        events=[_ev(ts_min=ts_sec, ip=ip, user=user)],
    )


def _run(rules, findings):
    engine = CorrelationEngine(rules, window_sec=7200)
    return list(engine.correlate(iter(findings)))


# ── BRUTE_THEN_SUCCESS ────────────────────────────────────────────────────

def test_brute_then_success_fires():
    findings = [_f('brute_force', ts_sec=0), _f('auth_success', ts_sec=30)]
    results  = _run([BRUTE_THEN_SUCCESS], findings)
    assert any(r.rule_id == 'brute_then_success' for r in results)


def test_brute_then_success_is_critical():
    findings = [_f('brute_force'), _f('auth_success', ts_sec=10)]
    results  = _run([BRUTE_THEN_SUCCESS], findings)
    hit = next(r for r in results if r.rule_id == 'brute_then_success')
    assert hit.severity == Severity.CRITICAL


def test_spray_then_success_also_fires():
    findings = [_f('password_spray'), _f('auth_success', ts_sec=10)]
    results  = _run([BRUTE_THEN_SUCCESS], findings)
    assert any(r.rule_id == 'brute_then_success' for r in results)


def test_brute_alone_does_not_trigger_success_rule():
    findings = [_f('brute_force'), _f('brute_force', ts_sec=10)]
    results  = _run([BRUTE_THEN_SUCCESS], findings)
    assert not any(r.rule_id == 'brute_then_success' for r in results)


# ── SUCCESS_THEN_PRIV_ESC ─────────────────────────────────────────────────

def test_success_then_priv_esc_fires():
    findings = [_f('auth_success'), _f('priv_esc', ts_sec=60)]
    results  = _run([SUCCESS_THEN_PRIV_ESC], findings)
    assert any(r.rule_id == 'success_then_priv_esc' for r in results)


def test_priv_esc_without_login_does_not_fire():
    findings = [_f('priv_esc')]
    results  = _run([SUCCESS_THEN_PRIV_ESC], findings)
    assert not any(r.rule_id == 'success_then_priv_esc' for r in results)


# ── ENUM_THEN_BRUTE ───────────────────────────────────────────────────────

def test_enum_then_brute_fires():
    findings = [_f('enumeration', ts_sec=0), _f('brute_force', ts_sec=120)]
    results  = _run([ENUM_THEN_BRUTE], findings)
    assert any(r.rule_id == 'enum_then_brute' for r in results)


# ── ALL_RULES integration ─────────────────────────────────────────────────

def test_all_rules_do_not_error_on_empty():
    results = _run(ALL_RULES, [])
    assert results == []


def test_all_rules_pass_through_unmatched_findings():
    findings = [_f('brute_force')]
    results  = _run(ALL_RULES, findings)
    assert any(r.rule_id == 'brute_force' for r in results)


def test_full_pipeline_produces_correlated_findings():
    """End-to-end: brute → success → priv_esc should generate correlated findings."""
    findings = [
        _f('brute_force',  ts_sec=0),
        _f('auth_success', ts_sec=30),
        _f('priv_esc',     ts_sec=90),
    ]
    results    = _run(ALL_RULES, findings)
    correlated = [r for r in results if r.metadata.get('is_correlated')]
    assert len(correlated) >= 1
