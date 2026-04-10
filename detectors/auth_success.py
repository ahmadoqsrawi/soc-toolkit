"""
detectors/auth_success.py
--------------------------
Detects successful authentication events and produces auth_success Findings.
This is a prerequisite for correlation rules:
  - brute_then_success
  - success_then_priv_esc
  - full_attack_chain

Without this detector those correlation rules never fire on real logs
because they require auth_success Findings, not just Events.

Every successful login produces one Finding. The Finding carries
the source IP and user so the correlation engine can match it against
preceding brute force or spray Findings from the same source.
"""

from __future__ import annotations

from typing import Iterator

from .base import BaseDetector
from soc_toolkit.models.event   import Event, EventType, Severity
from soc_toolkit.models.finding import Finding, Confidence
from soc_toolkit.config.loader  import Config


class AuthSuccessDetector(BaseDetector):

    def __init__(self, config: Config = None):
        self.cfg = config or Config()

    @property
    def rule_id(self) -> str:
        return "auth_success"

    def analyze(self, events: Iterator[Event]) -> Iterator[Finding]:
        for event in events:
            if event.event_type != EventType.AUTH_SUCCESS:
                continue

            # Skip allowlisted IPs and users
            if event.ip   and event.ip   in self.cfg.allowed_ips:
                continue
            if event.user and event.user in self.cfg.allowed_users:
                continue

            user_str = event.user or "unknown"
            ip_str   = event.ip   or "unknown"

            yield Finding(
                rule_id     = self.rule_id,
                title       = f"Successful login: {user_str} from {ip_str}",
                severity    = Severity.INFO,
                confidence  = Confidence.HIGH,
                description = (
                    f"{user_str} authenticated successfully from {ip_str}. "
                    f"This finding exists to enable correlation rules - "
                    f"on its own it is informational."
                ),
                recommendation = (
                    "Review if this login follows suspicious activity from "
                    "the same source IP. Check for brute_then_success or "
                    "full_attack_chain correlated findings."
                ),
                events   = [event],
                metadata = {
                    "ip":   ip_str,
                    "user": user_str,
                },
            )
