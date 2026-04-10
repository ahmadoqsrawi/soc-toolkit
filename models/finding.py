"""
models/finding.py
-----------------
A Finding is what a detector produces. It is not a raw event — it is a
structured conclusion drawn from one or more events, with enough context
for an analyst to act on it without going back to the raw log.

Confidence + severity are both required. A finding without both is not
actionable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime    import datetime
from enum        import Enum
from typing      import List, Optional

from .event import Event, Severity


class Confidence(str, Enum):
    HIGH   = "HIGH"
    MEDIUM = "MEDIUM"
    LOW    = "LOW"


@dataclass
class Finding:
    """
    One detection result. Always tied to a list of supporting events so the
    analyst can trace the evidence directly.
    """

    # --- Identity ---
    rule_id:     str                    # e.g. "brute_force", "password_spray"
    title:       str                    # short human label

    # --- Classification ---
    severity:    Severity
    confidence:  Confidence

    # --- Analyst context ---
    description: str                    # what happened and why it matters
    recommendation: str                 # what the analyst should do next

    # --- Evidence ---
    events:      List[Event]            # the raw events that triggered this

    # --- Timing (derived from events, set by detector) ---
    first_seen:  Optional[datetime] = None
    last_seen:   Optional[datetime] = None

    # --- Extension ---
    # Correlation rules and enrichers write here.
    # e.g. metadata["mitre"] = {"tactic": "Credential Access", "technique": "T1110"}
    metadata:    dict = field(default_factory=dict)

    def __post_init__(self):
        if isinstance(self.severity, str):
            self.severity = Severity(self.severity.upper())
        if isinstance(self.confidence, str):
            self.confidence = Confidence(self.confidence.upper())

        # Auto-derive timing from evidence if not explicitly set
        timed = [e.timestamp for e in self.events if e.timestamp]
        if timed:
            if self.first_seen is None:
                self.first_seen = min(timed)
            if self.last_seen is None:
                self.last_seen  = max(timed)

    @property
    def event_count(self) -> int:
        return len(self.events)

    @property
    def source_ips(self) -> list[str]:
        return list({e.ip for e in self.events if e.ip})

    @property
    def users(self) -> list[str]:
        return list({e.user for e in self.events if e.user})
