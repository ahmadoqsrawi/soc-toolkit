"""
exporters/json_export.py
------------------------
Full structured JSON export. Machine-readable, suitable for SIEM
ingestion, pipeline consumption, or further programmatic analysis.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing   import IO, Iterator

from .base     import BaseExporter
from .timeline import build_timeline
from soc_toolkit.models.finding import Finding


def _finding_to_dict(f: Finding) -> dict:
    return {
        "rule_id":          f.rule_id,
        "title":            f.title,
        "severity":         f.severity.value,
        "confidence":       f.confidence.value,
        "description":      f.description,
        "recommendation":   f.recommendation,
        "first_seen":       str(f.first_seen) if f.first_seen else None,
        "last_seen":        str(f.last_seen)  if f.last_seen  else None,
        "event_count":      f.event_count,
        "source_ips":       f.source_ips,
        "users":            f.users,
        "is_correlated":    f.metadata.get("is_correlated", False),
        "correlated_rules": f.metadata.get("correlated_rules", []),
        "metadata":         {
            k: v for k, v in f.metadata.items()
            if isinstance(v, (str, int, float, bool, list, type(None)))
        },
        "evidence": [
            {
                "timestamp":  str(e.timestamp) if e.timestamp else None,
                "event_type": e.event_type.value,
                "severity":   e.severity.value,
                "host":       e.host,
                "process":    e.process,
                "user":       e.user,
                "ip":         e.ip,
                "message":    e.message,
                "source":     e.source,
            }
            for e in f.events[:100]  # cap evidence per finding
        ],
    }


class JsonExporter(BaseExporter):

    def export(self, findings: Iterator[Finding], stream: IO[str]) -> None:
        finding_list = list(findings)
        timeline     = build_timeline(finding_list)

        output = {
            "generated_at":  datetime.now().isoformat(),
            "summary": {
                "total_findings": len(finding_list),
                "critical":  sum(1 for f in finding_list if f.severity.value == 'CRITICAL'),
                "high":      sum(1 for f in finding_list if f.severity.value == 'HIGH'),
                "medium":    sum(1 for f in finding_list if f.severity.value == 'MEDIUM'),
                "low":       sum(1 for f in finding_list if f.severity.value == 'LOW'),
                "source_ips": sorted({ip for f in finding_list for ip in f.source_ips}),
                "users":      sorted({u  for f in finding_list for u  in f.users}),
            },
            "findings":  [_finding_to_dict(f) for f in finding_list],
            "timeline":  [
                {
                    "timestamp": str(e.timestamp) if e.timestamp else None,
                    "kind":      e.kind,
                    "severity":  e.severity,
                    "actor":     e.actor,
                    "action":    e.action,
                    "detail":    e.detail[:200],
                    "source":    e.source,
                }
                for e in timeline
            ],
        }

        json.dump(output, stream, indent=2, default=str)
        stream.write('\n')
