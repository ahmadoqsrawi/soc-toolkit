"""
detectors/brute_force.py
------------------------
Detects brute force attacks: a single IP generating N or more failed
authentication attempts within a sliding time window.

Finding severity scale:
  CRITICAL — burst >= threshold AND total >= 3x threshold
  HIGH     — burst >= threshold
  MEDIUM   — total >= threshold, no tight burst detected
"""

from __future__ import annotations

from collections import defaultdict
from datetime    import timedelta
from typing      import Iterator

from .base import BaseDetector
from soc_toolkit.models.event   import Event, EventType, Severity
from soc_toolkit.models.finding import Finding, Confidence
from soc_toolkit.config.loader  import Config


class BruteForceDetector(BaseDetector):

    def __init__(self, config: Config = None):
        self.cfg = config or Config()

    @property
    def rule_id(self) -> str:
        return "brute_force"

    def analyze(self, events: Iterator[Event]) -> Iterator[Finding]:
        # Group auth failures by source IP
        by_ip: dict[str, list[Event]] = defaultdict(list)

        for event in events:
            if event.event_type == EventType.AUTH_FAILURE and event.ip:
                by_ip[event.ip].append(event)

        threshold  = self.cfg.brute_force_threshold
        window_sec = self.cfg.brute_force_window_sec
        window     = timedelta(seconds=window_sec)

        for ip, evs in by_ip.items():
            total = len(evs)
            if total < threshold:
                continue

            # Skip allowlisted IPs
            if ip in self.cfg.allowed_ips:
                continue

            # Find the tightest burst within the window
            timed   = sorted([e for e in evs if e.timestamp], key=lambda e: e.timestamp)
            untimed = [e for e in evs if not e.timestamp]

            burst_count  = 0
            burst_start  = None

            if timed:
                for i, ev in enumerate(timed):
                    count = sum(
                        1 for e in timed[i:]
                        if e.timestamp - ev.timestamp <= window
                    )
                    if count > burst_count:
                        burst_count = count
                        burst_start = ev.timestamp

            # If all events are untimed, treat total as burst
            if not timed:
                burst_count = len(untimed)

            if burst_count < threshold and total < threshold:
                continue

            targeted_users = list({e.user for e in evs if e.user})

            # Severity based on burst intensity
            if burst_count >= threshold * 3:
                severity   = Severity.CRITICAL
                confidence = Confidence.HIGH
            elif burst_count >= threshold:
                severity   = Severity.HIGH
                confidence = Confidence.HIGH
            else:
                severity   = Severity.MEDIUM
                confidence = Confidence.MEDIUM

            users_str = ", ".join(sorted(targeted_users)[:5])
            if len(targeted_users) > 5:
                users_str += f" (+{len(targeted_users)-5} more)"

            yield Finding(
                rule_id     = self.rule_id,
                title       = f"Brute force attack from {ip}",
                severity    = severity,
                confidence  = confidence,
                description = (
                    f"{ip} made {total} failed login attempt(s), "
                    f"with a peak burst of {burst_count} within "
                    f"{window_sec // 60} minutes. "
                    f"Targeted account(s): {users_str}."
                ),
                recommendation = (
                    f"Block {ip} at the firewall. "
                    f"Review whether any targeted accounts were later "
                    f"successfully authenticated. "
                    f"Consider enabling fail2ban or equivalent."
                ),
                events   = evs,
                metadata = {
                    "ip":            ip,
                    "total":         total,
                    "burst_count":   burst_count,
                    "burst_start":   str(burst_start) if burst_start else None,
                    "window_sec":    window_sec,
                    "targeted_users": targeted_users,
                },
            )
