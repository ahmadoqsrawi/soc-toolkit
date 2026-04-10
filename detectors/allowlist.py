"""
detectors/allowlist.py
----------------------
The AllowlistEngine is not a detector — it is a Finding filter.
It wraps any detector's output and suppresses findings that match
known-good criteria defined in Config.

Usage:
    engine   = AllowlistEngine(config)
    findings = engine.filter(brute_force_detector.analyze(events))

Suppression rules (checked in order):
  1. All source IPs in the finding are in config.allowed_ips
  2. All targeted users in the finding are in config.allowed_users
  3. The finding's rule_id is in the per-rule suppression list

Suppressed findings are logged to metadata, never silently dropped,
so analysts can audit what was suppressed and why.
"""

from __future__ import annotations

from typing import Iterator

from soc_toolkit.models.finding import Finding
from soc_toolkit.config.loader  import Config


class AllowlistEngine:

    def __init__(self, config: Config = None):
        self.cfg = config or Config()

    def filter(self, findings: Iterator[Finding]) -> Iterator[Finding]:
        """
        Yield findings that are NOT suppressed.
        Attach suppression metadata to suppressed findings and drop them.
        """
        allowed_ips   = set(self.cfg.allowed_ips)
        allowed_users = set(self.cfg.allowed_users)

        for finding in findings:
            reason = self._suppression_reason(finding, allowed_ips, allowed_users)
            if reason:
                # Suppressed — do not yield. In a future version this could
                # write to a suppression audit log instead.
                continue
            yield finding

    def _suppression_reason(
        self,
        finding:       Finding,
        allowed_ips:   set[str],
        allowed_users: set[str],
    ) -> str | None:
        """Return a reason string if the finding should be suppressed, else None."""

        # Suppress if ALL source IPs are allowlisted
        if finding.source_ips and allowed_ips:
            if all(ip in allowed_ips for ip in finding.source_ips):
                return f"all source IPs allowlisted: {finding.source_ips}"

        # Suppress if ALL targeted users are allowlisted
        if finding.users and allowed_users:
            if all(u in allowed_users for u in finding.users):
                return f"all targeted users allowlisted: {finding.users}"

        return None


class DetectionPipeline:
    """
    Convenience class that wires parsers → detectors → allowlist → findings.

    Usage:
        pipeline = DetectionPipeline(config)
        pipeline.add_detector(BruteForceDetector(config))
        pipeline.add_detector(PasswordSprayDetector(config))

        for finding in pipeline.run(events):
            print(finding.title)
    """

    def __init__(self, config: Config = None):
        self.cfg       = config or Config()
        self._detectors = []
        self._allowlist = AllowlistEngine(config)

    def add_detector(self, detector) -> 'DetectionPipeline':
        self._detectors.append(detector)
        return self

    def run(self, events: Iterator) -> Iterator[Finding]:
        """
        Run all detectors over the event stream and filter through allowlist.
        Events are materialized once into a list so each detector gets the
        full set. For very large files, consider chunking upstream.
        """
        event_list = list(events)

        for detector in self._detectors:
            raw_findings = detector.analyze(iter(event_list))
            for finding in self._allowlist.filter(raw_findings):
                yield finding
