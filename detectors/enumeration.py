"""
detectors/enumeration.py
------------------------
Detects account enumeration: an IP systematically probing for valid
usernames by triggering "invalid user" / "no such user" responses.

This is distinct from brute force:
  Brute force   — tests PASSWORDS against known/guessed valid users
  Enumeration   — tests USERNAMES to discover which accounts exist

Finding severity:
  HIGH   — many distinct invalid usernames probed
  MEDIUM — moderate probing
"""

from __future__ import annotations

from collections import defaultdict
from datetime    import timedelta
from typing      import Iterator

from .base import BaseDetector
from soc_toolkit.models.event   import Event, EventType, Severity
from soc_toolkit.models.finding import Finding, Confidence
from soc_toolkit.config.loader  import Config

# Auth failures on non-existent accounts are logged as AUTH_FAILURE
# with "invalid user" in the message — we detect this via message content
_INVALID_USER_MARKERS = (
    'invalid user',
    'no such user',
    'unknown user',
    'user unknown',
)

_ENUMERATION_THRESHOLD = 5   # distinct invalid usernames from one IP


class EnumerationDetector(BaseDetector):

    def __init__(self, config: Config = None):
        self.cfg = config or Config()

    @property
    def rule_id(self) -> str:
        return "enumeration"

    def _is_invalid_user_event(self, event: Event) -> bool:
        msg = event.message.lower()
        return (
            event.event_type == EventType.AUTH_FAILURE
            and any(m in msg for m in _INVALID_USER_MARKERS)
        )

    def analyze(self, events: Iterator[Event]) -> Iterator[Finding]:
        # IP → list of invalid-user events
        by_ip: dict[str, list[Event]] = defaultdict(list)

        for event in events:
            if event.ip and self._is_invalid_user_event(event):
                by_ip[event.ip].append(event)

        window = timedelta(seconds=self.cfg.brute_force_window_sec)

        for ip, evs in by_ip.items():
            if ip in self.cfg.allowed_ips:
                continue

            timed   = sorted([e for e in evs if e.timestamp], key=lambda e: e.timestamp)
            untimed = [e for e in evs if not e.timestamp]

            # Best window: most distinct invalid usernames
            max_distinct: set[str] = set()
            best_events:  list[Event] = []

            if timed:
                for i, ev in enumerate(timed):
                    in_window     = [e for e in timed[i:] if e.timestamp - ev.timestamp <= window]
                    distinct_here = {e.user for e in in_window if e.user}
                    if len(distinct_here) > len(max_distinct):
                        max_distinct = distinct_here
                        best_events  = in_window

            if not timed and untimed:
                max_distinct = {e.user for e in untimed if e.user}
                best_events  = untimed

            count = len(max_distinct)
            if count < _ENUMERATION_THRESHOLD:
                continue

            severity   = Severity.HIGH   if count >= _ENUMERATION_THRESHOLD * 2 else Severity.MEDIUM
            confidence = Confidence.HIGH if count >= _ENUMERATION_THRESHOLD * 2 else Confidence.MEDIUM

            users_preview = sorted(max_distinct)[:10]
            users_str     = ", ".join(users_preview)
            if count > 10:
                users_str += f" (+{count - 10} more)"

            yield Finding(
                rule_id     = self.rule_id,
                title       = f"Account enumeration from {ip}",
                severity    = severity,
                confidence  = confidence,
                description = (
                    f"{ip} probed {count} non-existent username(s), "
                    f"suggesting automated account enumeration. "
                    f"Invalid accounts probed: {users_str}."
                ),
                recommendation = (
                    f"Block {ip} at the firewall. Enumeration is typically "
                    f"a reconnaissance step before a targeted brute force or "
                    f"spray attack — correlate with subsequent auth failure "
                    f"findings from the same IP."
                ),
                events   = best_events or evs,
                metadata = {
                    "ip":              ip,
                    "distinct_invalid": count,
                    "invalid_users":   sorted(max_distinct),
                },
            )
