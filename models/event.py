"""
models/event.py
---------------
The normalized event schema. Every parser in the toolkit must produce Event
objects. Every detector consumes them. This is the contract that holds the
pipeline together.

Nothing downstream should ever touch raw log lines directly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime    import datetime
from enum        import Enum
from typing      import Optional


class Severity(str, Enum):
    # Log-level severity (parsers)
    CRITICAL = "CRITICAL"
    ERROR    = "ERROR"
    WARNING  = "WARNING"
    INFO     = "INFO"
    DEBUG    = "DEBUG"
    UNKNOWN  = "UNKNOWN"
    # Finding-level severity (detectors) — maps intuitively for analysts
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"


class EventType(str, Enum):
    # Authentication
    AUTH_FAILURE  = "auth_failure"
    AUTH_SUCCESS  = "auth_success"
    # Privilege
    SUDO          = "sudo"
    SU            = "su"
    # User / group management
    USER_CREATED  = "user_created"
    USER_DELETED  = "user_deleted"
    GROUP_CHANGE  = "group_change"
    # Session
    SESSION_OPEN  = "session_open"
    SESSION_CLOSE = "session_close"
    # Generic
    GENERIC       = "generic"


@dataclass
class Event:
    """
    One normalized log event. All fields are explicit — no raw dict access
    downstream.

    Streaming-safe: parsers yield Event objects one at a time so the full
    log file is never held in memory.
    """

    # --- Identity ---
    event_type: EventType
    severity:   Severity

    # --- Timing ---
    timestamp:  Optional[datetime]          # None when log has no timestamp

    # --- Origin ---
    source:     str                         # file path or stream name
    host:       str
    process:    str
    pid:        Optional[str]

    # --- Actors ---
    user:       Optional[str]               # acting / targeted user
    ip:         Optional[str]               # source IP when present

    # --- Content ---
    message:    str                         # normalized, human-readable
    raw:        str                         # original unmodified log line

    # --- Extension point ---
    # Enrichers and detectors can add fields here without breaking the schema.
    # Keys are namespaced by the component that writes them, e.g.
    # metadata["geoip"] = {"country": "RU", "asn": "AS12345"}
    # metadata["detector"] = {"rule": "brute_force", "count": 42}
    metadata:   dict = field(default_factory=dict)

    def __post_init__(self):
        if isinstance(self.event_type, str):
            self.event_type = EventType(self.event_type)
        if isinstance(self.severity, str):
            try:
                self.severity = Severity(self.severity.upper())
            except ValueError:
                self.severity = Severity.UNKNOWN
