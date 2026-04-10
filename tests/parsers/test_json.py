import pytest
from pathlib import Path
from soc_toolkit.parsers.json_ import JsonParser
from soc_toolkit.models.event  import Severity

SAMPLE = Path(__file__).parent.parent.parent / 'samples' / 'events.json.sample'


@pytest.fixture
def events():
    return list(JsonParser().parse(SAMPLE))


def test_yields_correct_count(events):
    assert len(events) == 5


def test_severity_parsed(events):
    sevs = [e.severity for e in events]
    assert Severity.ERROR in sevs
    assert Severity.CRITICAL in sevs


def test_ip_extracted(events):
    ips = [e.ip for e in events if e.ip]
    assert '45.33.32.156' in ips


def test_timestamp_parsed(events):
    assert all(e.timestamp is not None for e in events)
