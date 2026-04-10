"""
detectors/password_spray.py
---------------------------
Detects password spray attacks: a single IP attempting authentication
against many DISTINCT usernames within a time window.

Distinguishes from brute force:
  Brute force  — many attempts against FEW usernames (high attempt/user ratio)
  Password spray — fewer attempts against MANY usernames (low attempt/user ratio)

Finding severity scale:
  HIGH   — distinct users >= threshold
  MEDIUM — distinct users >= threshold // 2 but < threshold (partial spray)
"""

from __future__ import annotations

from collections import defaultdict
from datetime    import timedelta
from typing      import Iterator

from .base import BaseDetector
from soc_toolkit.models.event   import Event, EventType, Severity
from soc_toolkit.models.finding import Finding, Confidence
from soc_toolkit.config.loader  import Config


class PasswordSprayDetector(BaseDetector):

    def __init__(self, config: Config = None):
        self.cfg = config or Config()

    @property
    def rule_id(self) -> str:
        return "password_spray"

    def analyze(self, events: Iterator[Event]) -> Iterator[Finding]:
        # Track: IP → list of (user, event) tuples
        by_ip: dict[str, list[Event]] = defaultdict(list)

        for event in events:
            if (event.event_type == EventType.AUTH_FAILURE
                    and event.ip
                    and event.user):
                by_ip[event.ip].append(event)

        threshold  = self.cfg.spray_threshold
        window_sec = self.cfg.spray_window_sec
        window     = timedelta(seconds=window_sec)

        for ip, evs in by_ip.items():
            if ip in self.cfg.allowed_ips:
                continue

            timed   = sorted([e for e in evs if e.timestamp], key=lambda e: e.timestamp)
            untimed = [e for e in evs if not e.timestamp]

            # Find the window with the most distinct usernames
            max_users_in_window: set[str] = set()
            window_events: list[Event]    = []

            if timed:
                for i, ev in enumerate(timed):
                    in_window = [
                        e for e in timed[i:]
                        if e.timestamp - ev.timestamp <= window
                    ]
                    users_in_window = {e.user for e in in_window if e.user}
                    if len(users_in_window) > len(max_users_in_window):
                        max_users_in_window = users_in_window
                        window_events       = in_window

            # For untimed events, count all unique users
            if not timed and untimed:
                max_users_in_window = {e.user for e in untimed if e.user}
                window_events       = untimed

            distinct_count = len(max_users_in_window)
            half_threshold = max(2, threshold // 2)

            if distinct_count < half_threshold:
                continue

            # Severity based on how many distinct users were targeted
            if distinct_count >= threshold:
                severity   = Severity.HIGH
                confidence = Confidence.HIGH
            else:
                severity   = Severity.MEDIUM
                confidence = Confidence.MEDIUM

            users_preview = sorted(max_users_in_window)[:8]
            users_str     = ", ".join(users_preview)
            if distinct_count > 8:
                users_str += f" (+{distinct_count - 8} more)"

            total_attempts = len(window_events) or len(evs)

            yield Finding(
                rule_id     = self.rule_id,
                title       = f"Password spray from {ip}",
                severity    = severity,
                confidence  = confidence,
                description = (
                    f"{ip} targeted {distinct_count} distinct account(s) "
                    f"with {total_attempts} attempt(s) within "
                    f"{window_sec // 60} minutes — consistent with a "
                    f"password spray attack. "
                    f"Accounts targeted: {users_str}."
                ),
                recommendation = (
                    f"Block {ip} at the firewall or rate-limit at the "
                    f"authentication layer. Audit all targeted accounts "
                    f"for subsequent successful logins. Consider alerting "
                    f"account owners."
                ),
                events   = window_events or evs,
                metadata = {
                    "ip":             ip,
                    "distinct_users": distinct_count,
                    "total_attempts": total_attempts,
                    "users":          sorted(max_users_in_window),
                    "window_sec":     window_sec,
                },
            )
