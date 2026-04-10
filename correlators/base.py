"""
correlators/base.py
-------------------
The correlation contract. Correlators consume a stream of Findings
and emit new Findings when a chain of conditions is satisfied within
a time window.
"""

from __future__ import annotations

from abc        import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass, field
from datetime   import timedelta
from typing     import Callable, Iterator, List

from soc_toolkit.models.finding import Finding
from soc_toolkit.models.event   import Severity
from soc_toolkit.models.finding import Confidence


@dataclass
class CorrelationRule:
    """
    A named rule that fires when all conditions match in sequence
    within window_sec seconds.
    """
    rule_id:     str
    name:        str
    description: str
    window_sec:  int
    conditions:  List[Callable[[Finding], bool]]
    severity:    Severity
    confidence:  Confidence
    recommendation: str = ''


class BaseCorrelator(ABC):

    def __init__(self, rules: list[CorrelationRule], window_sec: int = 300):
        self.rules      = rules
        self.window_sec = window_sec
        # Sliding window — bounded deque, not a list.
        # Max size prevents unbounded memory growth on high-volume streams.
        self._window: deque[Finding] = deque(maxlen=10_000)

    @abstractmethod
    def correlate(self, findings: Iterator[Finding]) -> Iterator[Finding]:
        """Consume findings, emit correlated findings when rules fire."""
        ...

    def _expire_window(self, current_ts):
        """Remove findings older than window_sec from the sliding window."""
        if current_ts is None:
            return
        cutoff = current_ts - timedelta(seconds=self.window_sec)
        while self._window and self._window[0].first_seen and \
              self._window[0].first_seen < cutoff:
            self._window.popleft()
