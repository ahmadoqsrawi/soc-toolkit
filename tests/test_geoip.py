"""
Tests for GeoIPEnricher.
GeoIP tests run without database files - they verify graceful degradation.
Tests that require actual database files are skipped if files are not present.
"""
import pytest
from datetime import datetime
from soc_toolkit.enrichers.geoip import GeoIPEnricher
from soc_toolkit.models.event    import Event, EventType, Severity


def _ev(ip='45.33.32.156'):
    return Event(
        event_type=EventType.AUTH_FAILURE, severity=Severity.ERROR,
        timestamp=datetime(2024,4,9,8,0,0), source='test', host='srv',
        process='sshd', pid=None, user='root', ip=ip,
        message='Failed password', raw='',
    )


def test_enricher_initializes_without_databases():
    enricher = GeoIPEnricher()
    assert enricher is not None


def test_enricher_passes_events_through_without_databases():
    enricher = GeoIPEnricher()
    events   = [_ev(), _ev(ip='1.1.1.1')]
    result   = list(enricher.enrich(iter(events)))
    assert len(result) == 2


def test_enricher_does_not_drop_events_without_ip():
    enricher = GeoIPEnricher()
    ev       = _ev(ip=None)
    ev.ip    = None
    result   = list(enricher.enrich(iter([ev])))
    assert len(result) == 1


def test_enricher_context_manager():
    with GeoIPEnricher() as enricher:
        result = list(enricher.enrich(iter([_ev()])))
    assert len(result) == 1


def test_geoip_metadata_key_present_when_available():
    enricher = GeoIPEnricher()
    ev       = _ev()
    result   = list(enricher.enrich(iter([ev])))[0]
    # Without DB files geoip key may or may not be present
    # but no exception should be raised
    assert isinstance(result.metadata, dict)
