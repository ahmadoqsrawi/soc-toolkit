"""
exporters/timeline.py
---------------------
Builds a unified, chronological timeline from a list of findings.
The timeline is the backbone of every report format — all exporters
consume it rather than raw findings directly.

Each TimelineEntry represents one moment in the attack narrative:
either an individual event or a finding-level summary.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime    import datetime
from typing      import List, Optional

from soc_toolkit.models.finding import Finding
from soc_toolkit.models.event   import Event


@dataclass
class TimelineEntry:
    timestamp:  Optional[datetime]
    kind:       str            # "event" | "finding" | "correlated"
    severity:   str
    actor:      str            # IP or username
    action:     str            # short description
    detail:     str            # full message or finding description
    source:     str            # log file or rule_id
    finding:    Optional[Finding] = None
    event:      Optional[Event]   = None


def build_timeline(findings: list[Finding]) -> list[TimelineEntry]:
    """
    Flatten all findings and their evidence events into a single
    chronological timeline. Correlated findings appear as summary
    entries above their constituent events.
    """
    entries: list[TimelineEntry] = []

    for finding in findings:
        is_correlated = finding.metadata.get("is_correlated", False)
        kind = "correlated" if is_correlated else "finding"

        # Finding-level summary entry
        actor = (finding.source_ips + finding.users + ["unknown"])[0]
        entries.append(TimelineEntry(
            timestamp = finding.first_seen,
            kind      = kind,
            severity  = finding.severity.value,
            actor     = actor,
            action    = finding.title,
            detail    = finding.description,
            source    = finding.rule_id,
            finding   = finding,
        ))

        # Individual evidence events
        for event in finding.events:
            entries.append(TimelineEntry(
                timestamp = event.timestamp,
                kind      = "event",
                severity  = event.severity.value,
                actor     = event.ip or event.user or event.host or "unknown",
                action    = event.event_type.value,
                detail    = event.message,
                source    = event.source,
                event     = event,
            ))

    # Sort chronologically; entries without timestamps go to end
    entries.sort(key=lambda e: (e.timestamp is None, e.timestamp))

    # Deduplicate identical event entries (findings share events in correlation).
    # Key includes timestamp + source + full detail to handle events with
    # identical messages at different times or from different sources.
    seen: set[tuple] = set()
    unique: list[TimelineEntry] = []
    for e in entries:
        # For events, use the underlying raw line if available (most unique key).
        # For findings/correlated, use kind + detail.
        raw = e.event.raw if (e.kind == 'event' and e.event and e.event.raw) else ''
        key = (e.timestamp, e.kind, e.source, raw or e.detail[:120])
        if key not in seen:
            seen.add(key)
            unique.append(e)

    return unique
