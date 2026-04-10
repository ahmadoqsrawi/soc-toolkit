"""
enrichers/geoip.py
------------------
GeoIP enrichment using MaxMind GeoLite2 local databases.
Adds country and ASN context to every Event that has an IP address.

Requires:
  pip install geoip2

Database files (download free from maxmind.com):
  GeoLite2-City.mmdb
  GeoLite2-ASN.mmdb

Point to them in config/default.yaml:
  geoip_city_db: config/geoip/GeoLite2-City.mmdb
  geoip_asn_db:  config/geoip/GeoLite2-ASN.mmdb

If the database files are not found, enrichment is skipped silently
and events pass through unchanged. This means GeoIP is optional -
the toolkit works without it.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing  import Iterator, Optional

from .base import BaseEnricher
from soc_toolkit.models.event import Event

try:
    import geoip2.database
    import geoip2.errors
    _GEOIP2_AVAILABLE = True
except ImportError:
    _GEOIP2_AVAILABLE = False


class GeoIPEnricher(BaseEnricher):

    def __init__(
        self,
        city_db_path: Optional[Path] = None,
        asn_db_path:  Optional[Path] = None,
    ):
        self._city_reader = None
        self._asn_reader  = None
        self._available   = False

        if not _GEOIP2_AVAILABLE:
            print(
                "[GeoIP] geoip2 library not installed. "
                "Run: pip install geoip2",
                file=sys.stderr,
            )
            return

        city_ok = city_db_path and Path(city_db_path).exists()
        asn_ok  = asn_db_path  and Path(asn_db_path).exists()

        if not city_ok and not asn_ok:
            print(
                "[GeoIP] No database files found. "
                "Download GeoLite2-City.mmdb and GeoLite2-ASN.mmdb "
                "from maxmind.com and set geoip_city_db / geoip_asn_db "
                "in your config file.",
                file=sys.stderr,
            )
            return

        if city_ok:
            self._city_reader = geoip2.database.Reader(str(city_db_path))
        if asn_ok:
            self._asn_reader  = geoip2.database.Reader(str(asn_db_path))

        self._available = True

    def enrich(self, events: Iterator[Event]) -> Iterator[Event]:
        for event in events:
            if self._available and event.ip:
                event.metadata["geoip"] = self._lookup(event.ip)
            yield event

    def _lookup(self, ip: str) -> dict:
        result = {}

        if self._city_reader:
            try:
                city = self._city_reader.city(ip)
                result["country"]      = city.country.iso_code or ""
                result["country_name"] = city.country.name or ""
                result["city"]         = city.city.name or ""
                result["latitude"]     = city.location.latitude
                result["longitude"]    = city.location.longitude
            except Exception:
                pass

        if self._asn_reader:
            try:
                asn = self._asn_reader.asn(ip)
                result["asn"]     = asn.autonomous_system_number
                result["asn_org"] = asn.autonomous_system_organization or ""
            except Exception:
                pass

        return result

    def close(self):
        if self._city_reader:
            self._city_reader.close()
        if self._asn_reader:
            self._asn_reader.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
