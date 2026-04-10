"""Tests for all exporters and the timeline engine."""

import io, json, zipfile
import pytest
from datetime import datetime
from pathlib  import Path

from soc_toolkit.exporters.timeline    import build_timeline
from soc_toolkit.exporters.markdown    import MarkdownExporter
from soc_toolkit.exporters.html_report import HtmlExporter
from soc_toolkit.exporters.json_export import JsonExporter
from soc_toolkit.exporters.bundle      import create_bundle
from soc_toolkit.models.finding        import Finding, Confidence
from soc_toolkit.models.event          import Event, EventType, Severity


def _ev(ts_sec=0, ip='1.2.3.4', user='root'):
    return Event(
        event_type=EventType.AUTH_FAILURE, severity=Severity.ERROR,
        timestamp=datetime(2024, 4, 9, 8, 0, ts_sec),
        source='/var/log/auth.log', host='srv', process='sshd',
        pid=None, user=user, ip=ip,
        message=f'Failed password for {user} from {ip}',
        raw=f'Apr  9 08:00:{ts_sec:02d} srv sshd: Failed password for {user}',
    )


def _finding(rule_id='brute_force', n_events=5):
    events = [_ev(ts_sec=i) for i in range(n_events)]
    return Finding(
        rule_id=rule_id, title=f'Test finding: {rule_id}',
        severity=Severity.HIGH, confidence=Confidence.HIGH,
        description='Test description.', recommendation='Test recommendation.',
        events=events,
    )


# ── Timeline ──────────────────────────────────────────────────────────────

def test_timeline_builds_from_findings():
    findings = [_finding(), _finding('priv_esc')]
    timeline = build_timeline(findings)
    assert len(timeline) > 0


def test_timeline_is_chronological():
    findings = [_finding()]
    timeline = build_timeline(findings)
    timed    = [e for e in timeline if e.timestamp]
    for i in range(len(timed) - 1):
        assert timed[i].timestamp <= timed[i+1].timestamp


def test_timeline_deduplicates_shared_events():
    """Shared event objects (same timestamp+raw) should appear only once."""
    f1 = _finding()
    f2 = _finding('priv_esc')
    # Share the exact same event objects so they have identical raw lines
    shared_events = f1.events[:2]
    f2.events = shared_events + [_ev(ts_sec=10, ip='9.9.9.9')]
    timeline  = build_timeline([f1, f2])
    event_entries = [e for e in timeline if e.kind == 'event']
    # The 2 shared events should appear once each, not twice
    raw_keys = [(e.timestamp, e.source, e.detail[:80]) for e in event_entries]
    assert len(raw_keys) == len(set(raw_keys))


# ── Markdown ──────────────────────────────────────────────────────────────

def test_markdown_output_is_non_empty():
    buf = io.StringIO()
    MarkdownExporter().export(iter([_finding()]), buf)
    assert len(buf.getvalue()) > 100


def test_markdown_contains_required_sections():
    buf = io.StringIO()
    MarkdownExporter().export(iter([_finding()]), buf)
    md  = buf.getvalue()
    for section in ['# SOC Investigation Report', '## Executive Summary',
                    '## Attack Timeline', '## Findings', '## Recommended Actions']:
        assert section in md, f"Missing section: {section}"


def test_markdown_contains_finding_title():
    buf = io.StringIO()
    MarkdownExporter().export(iter([_finding()]), buf)
    assert 'Test finding: brute_force' in buf.getvalue()


def test_markdown_empty_findings():
    buf = io.StringIO()
    MarkdownExporter().export(iter([]), buf)
    assert '0' in buf.getvalue()


# ── HTML ──────────────────────────────────────────────────────────────────

def test_html_is_valid_document():
    buf = io.StringIO()
    HtmlExporter().export(iter([_finding()]), buf)
    html = buf.getvalue()
    assert html.startswith('<!DOCTYPE html>')
    assert '</html>' in html


def test_html_contains_finding_title():
    buf = io.StringIO()
    HtmlExporter().export(iter([_finding()]), buf)
    assert 'Test finding: brute_force' in buf.getvalue()


def test_html_contains_severity_badge():
    buf = io.StringIO()
    HtmlExporter().export(iter([_finding()]), buf)
    assert 'HIGH' in buf.getvalue()


# ── JSON ──────────────────────────────────────────────────────────────────

def test_json_is_parseable():
    buf = io.StringIO()
    JsonExporter().export(iter([_finding()]), buf)
    data = json.loads(buf.getvalue())
    assert 'findings' in data
    assert 'summary'  in data
    assert 'timeline' in data


def test_json_summary_counts_correct():
    findings = [_finding('brute_force'), _finding('priv_esc')]
    buf      = io.StringIO()
    JsonExporter().export(iter(findings), buf)
    data = json.loads(buf.getvalue())
    assert data['summary']['total_findings'] == 2
    assert data['summary']['high'] == 2


def test_json_findings_have_evidence():
    buf = io.StringIO()
    JsonExporter().export(iter([_finding(n_events=3)]), buf)
    data = json.loads(buf.getvalue())
    assert len(data['findings'][0]['evidence']) == 3


# ── Bundle ────────────────────────────────────────────────────────────────

def test_bundle_creates_zip(tmp_path):
    out = tmp_path / 'report.zip'
    create_bundle(iter([_finding()]), out)
    assert out.exists()
    assert zipfile.is_zipfile(out)


def test_bundle_contains_required_files(tmp_path):
    out = tmp_path / 'report.zip'
    create_bundle(iter([_finding()]), out)
    with zipfile.ZipFile(out) as zf:
        names = zf.namelist()
    for required in ['report.md', 'report.html', 'findings.json',
                     'evidence.log', 'manifest.txt']:
        assert required in names, f"Missing: {required}"


def test_bundle_evidence_log_contains_raw_lines(tmp_path):
    out = tmp_path / 'report.zip'
    create_bundle(iter([_finding()]), out)
    with zipfile.ZipFile(out) as zf:
        evidence = zf.read('evidence.log').decode()
    assert 'Failed password' in evidence


def test_bundle_manifest_has_summary(tmp_path):
    out = tmp_path / 'report.zip'
    create_bundle(iter([_finding()]), out)
    with zipfile.ZipFile(out) as zf:
        manifest = zf.read('manifest.txt').decode()
    assert 'Total findings' in manifest
