"""
enrichers/base.py
-----------------
Enrichers add context to Events without changing their structure.
All enrichment goes into event.metadata under a namespaced key.
"""

from __future__ import annotations

from abc    import ABC, abstractmethod
from typing import Iterator

from soc_toolkit.models.event import Event


class BaseEnricher(ABC):

    @abstractmethod
    def enrich(self, events: Iterator[Event]) -> Iterator[Event]:
        """
        Yield the same events with metadata populated.
        Must not drop events — even if enrichment fails for a given
        event, yield it unchanged.
        """
        ...
