"""
correlators/engine.py
---------------------
The correlation engine. Consumes a stream of Findings and emits new
correlated Findings when a CorrelationRule's conditions are satisfied
within its time window.

How it works:
  - Maintains a bounded sliding window (deque) of recent findings
  - For each new finding, expires old entries outside the window
  - Checks every rule against the current window
  - When all conditions in a rule match (in order), emits a correlated Finding
  - Each rule fires at most once per unique key (e.g. per IP) to avoid duplicates

Design constraints:
  - Window is bounded (maxlen=10_000) — never grows unbounded
  - Rules are evaluated lazily — only when a new finding arrives
  - Correlated findings are appended back into the window so rules can chain
"""

from __future__ import annotations

from collections import deque
from datetime    import timedelta
from typing      import Iterator

from .base import BaseCorrelator, CorrelationRule
from soc_toolkit.models.finding import Finding, Confidence
from soc_toolkit.models.event   import Severity


class CorrelationEngine(BaseCorrelator):

    def __init__(self, rules: list[CorrelationRule], window_sec: int = 600):
        super().__init__(rules, window_sec)
        # Track which (rule_id, key) pairs have already fired to avoid duplicates
        self._fired: set[tuple[str, str]] = set()

    def correlate(self, findings: Iterator[Finding]) -> Iterator[Finding]:
        """
        Consume findings, yield all original findings plus any correlated findings
        that are generated when rules match.
        """
        for finding in findings:
            # Always yield the original finding
            yield finding

            # Expire stale entries from the window
            self._expire_window(finding.first_seen)

            # Add this finding to the sliding window
            self._window.append(finding)

            # Check every rule against the current window
            for rule in self.rules:
                correlated = self._try_rule(rule, finding)
                if correlated:
                    yield correlated
                    # Add correlated finding to window so it can chain further rules
                    self._window.append(correlated)

    def _try_rule(
        self, rule: CorrelationRule, trigger: Finding
    ) -> Finding | None:
        """
        Try to match a rule against the current window.
        Returns a correlated Finding if all conditions match, else None.
        """
        window_contents = list(self._window)

        # Collect findings that satisfy each condition in order
        matched: list[Finding] = []
        remaining = window_contents.copy()

        for condition in rule.conditions:
            hit = next((f for f in remaining if condition(f)), None)
            if hit is None:
                return None  # Condition unmatched — rule doesn't fire
            matched.append(hit)
            remaining = [f for f in remaining if f is not hit]

        if not matched:
            return None

        # Derive a dedup key from shared IPs or users across matched findings
        all_ips   = list({ip for f in matched for ip in f.source_ips})
        all_users = list({u  for f in matched for u  in f.users})
        dedup_key = f"{rule.rule_id}::{','.join(sorted(all_ips + all_users))}"

        if dedup_key in self._fired:
            return None
        self._fired.add(dedup_key)

        # Collect all evidence events from matched findings
        all_events = [e for f in matched for e in f.events]
        # Cap at config limit to avoid huge objects
        all_events = all_events[:500]

        matched_rules = [f.rule_id for f in matched]

        return Finding(
            rule_id     = rule.rule_id,
            title       = rule.name,
            severity    = rule.severity,
            confidence  = rule.confidence,
            description = rule.description,
            recommendation = rule.recommendation,
            events      = all_events,
            metadata    = {
                "correlated_rules": matched_rules,
                "source_ips":       all_ips,
                "users":            all_users,
                "window_sec":       rule.window_sec,
                "is_correlated":    True,
            },
        )
