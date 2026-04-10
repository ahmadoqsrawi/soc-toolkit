"""
detectors/base.py
-----------------
The detector contract. Every detection rule is a BaseDetector subclass.
Detectors consume an iterator of Events and yield Findings.
They never touch files, never call parsers directly.
"""

from __future__ import annotations

from abc     import ABC, abstractmethod
from typing  import Iterator

from soc_toolkit.models.event   import Event
from soc_toolkit.models.finding import Finding


class BaseDetector(ABC):

    @property
    @abstractmethod
    def rule_id(self) -> str:
        """Unique snake_case identifier. Used in Finding.rule_id."""
        ...

    @abstractmethod
    def analyze(self, events: Iterator[Event]) -> Iterator[Finding]:
        """
        Consume events, yield zero or more Findings.
        Must not accumulate unbounded memory — use bounded buffers or
        streaming aggregation.
        """
        ...
