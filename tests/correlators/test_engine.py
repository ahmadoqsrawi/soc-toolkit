"""Tests for CorrelationEngine."""

import pytest
from datetime import datetime
from soc_toolkit.correlators.engine import CorrelationEngine
from soc_toolkit.correlators.base   import CorrelationRule
from soc_toolkit.models.finding     import Finding, Confidence
from soc_toolkit.models.event       import Event, EventType, Severity


def _event(ts_sec=0, ip='1.2.3.4', user='root', etype=EventType.AUTH_FAILURE):
    return Event(
        event_type=etype, severity=Severity.ERROR,
        timestamp=datetime(2024, 4, 9, 8, 0, ts_sec),
        source='test', host='srv', process='sshd', pid=None,
        user=user, ip=ip, message='test', raw='',
    )


def _finding(rule_id, ts_sec=0, ip='1.2.3.4', user='root', severity=Severity.HIGH):
    ev = _event(ts_sec=ts_sec, ip=ip, user=user)
    return Finding(
        rule_id=rule_id, title=rule_id, severity=severity,
        confidence=Confidence.HIGH, description='d', recommendation='r',
        events=[ev],
    )


def _rule(name, conds, window=600):
    return CorrelationRule(
        rule_id=name, name=name, description='d',
        window_sec=window, conditions=conds,
        severity=Severity.CRITICAL, confidence=Confidence.HIGH,
        recommendation='r',
    )


# ── Engine fires on matched conditions ────────────────────────────────────

def test_rule_fires_when_conditions_match():
    rule = _rule('chain', [
        lambda f: f.rule_id == 'step1',
        lambda f: f.rule_id == 'step2',
    ])
    engine   = CorrelationEngine([rule])
    findings = [_finding('step1', ts_sec=0), _finding('step2', ts_sec=10)]
    results  = list(engine.correlate(iter(findings)))
    correlated = [r for r in results if r.rule_id == 'chain']
    assert len(correlated) == 1


def test_correlated_finding_is_critical():
    rule = _rule('chain', [
        lambda f: f.rule_id == 'a',
        lambda f: f.rule_id == 'b',
    ])
    engine   = CorrelationEngine([rule])
    findings = [_finding('a', ts_sec=0), _finding('b', ts_sec=5)]
    results  = list(engine.correlate(iter(findings)))
    correlated = [r for r in results if r.rule_id == 'chain']
    assert correlated[0].severity == Severity.CRITICAL


def test_original_findings_preserved():
    rule = _rule('chain', [
        lambda f: f.rule_id == 'a',
        lambda f: f.rule_id == 'b',
    ])
    engine   = CorrelationEngine([rule])
    findings = [_finding('a'), _finding('b')]
    results  = list(engine.correlate(iter(findings)))
    rule_ids = [r.rule_id for r in results]
    assert 'a'     in rule_ids
    assert 'b'     in rule_ids
    assert 'chain' in rule_ids


def test_rule_does_not_fire_on_partial_match():
    rule = _rule('chain', [
        lambda f: f.rule_id == 'a',
        lambda f: f.rule_id == 'b',
    ])
    engine   = CorrelationEngine([rule])
    findings = [_finding('a'), _finding('c')]  # 'b' never arrives
    results  = list(engine.correlate(iter(findings)))
    correlated = [r for r in results if r.rule_id == 'chain']
    assert correlated == []


def test_rule_deduplicates():
    """Same rule should not fire twice for the same IP combination."""
    rule = _rule('chain', [
        lambda f: f.rule_id == 'a',
        lambda f: f.rule_id == 'b',
    ])
    engine = CorrelationEngine([rule])
    findings = [
        _finding('a', ts_sec=0),
        _finding('b', ts_sec=5),
        _finding('a', ts_sec=10),
        _finding('b', ts_sec=15),
    ]
    results = list(engine.correlate(iter(findings)))
    correlated = [r for r in results if r.rule_id == 'chain']
    assert len(correlated) == 1


def test_correlated_finding_has_is_correlated_flag():
    rule = _rule('chain', [
        lambda f: f.rule_id == 'a',
        lambda f: f.rule_id == 'b',
    ])
    engine   = CorrelationEngine([rule])
    findings = [_finding('a'), _finding('b')]
    results  = list(engine.correlate(iter(findings)))
    correlated = [r for r in results if r.rule_id == 'chain']
    assert correlated[0].metadata.get('is_correlated') is True


def test_no_findings_no_correlation():
    rule    = _rule('chain', [lambda f: f.rule_id == 'a'])
    engine  = CorrelationEngine([rule])
    results = list(engine.correlate(iter([])))
    assert results == []
