"""
exporters/markdown.py
---------------------
Generates a structured Markdown incident report from findings.
Designed to be pasted directly into a ticket, wiki, or IR doc.

Structure:
  # SOC Investigation Report
  ## Executive Summary
  ## Attack Timeline
  ## Findings (one section per finding)
  ## Recommended Actions
  ## Evidence Summary
"""

from __future__ import annotations

import sys
from datetime import datetime
from typing   import IO, Iterator

from .base     import BaseExporter
from .timeline import build_timeline, TimelineEntry
from soc_toolkit.models.finding import Finding


_SEV_EMOJI = {
    'CRITICAL': '🔴',
    'HIGH':     '🟠',
    'MEDIUM':   '🟡',
    'LOW':      '🟢',
    'INFO':     '⚪',
}

_SEV_RANK = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}


class MarkdownExporter(BaseExporter):

    def export(self, findings: Iterator[Finding], stream: IO[str]) -> None:
        finding_list = sorted(
            list(findings),
            key=lambda f: _SEV_RANK.get(f.severity.value, 9)
        )
        timeline = build_timeline(finding_list)

        w = stream.write

        # ── Header ────────────────────────────────────────────────────────
        w(f"# SOC Investigation Report\n\n")
        w(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}  \n")
        w(f"**Findings:** {len(finding_list)}  \n")

        criticals = [f for f in finding_list if f.severity.value == 'CRITICAL']
        highs     = [f for f in finding_list if f.severity.value == 'HIGH']
        if criticals:
            w(f"**Status:** 🔴 CRITICAL — immediate action required  \n")
        elif highs:
            w(f"**Status:** 🟠 HIGH — action required  \n")
        else:
            w(f"**Status:** 🟡 Review recommended  \n")
        w("\n---\n\n")

        # ── Executive Summary ─────────────────────────────────────────────
        w("## Executive Summary\n\n")
        all_ips   = sorted({ip for f in finding_list for ip in f.source_ips})
        all_users = sorted({u  for f in finding_list for u  in f.users})

        if criticals:
            w(f"**{len(criticals)} CRITICAL finding(s) require immediate response.**\n\n")

        w(f"Analysis identified **{len(finding_list)} finding(s)** across "
          f"**{len(all_ips)} source IP(s)** targeting "
          f"**{len(all_users)} account(s)**.\n\n")

        if all_ips:
            w(f"**Source IPs:** `{'`, `'.join(all_ips)}`  \n")
        if all_users:
            w(f"**Targeted accounts:** `{'`, `'.join(all_users)}`  \n")

        w("\n### Finding summary\n\n")
        w("| # | Severity | Rule | Title | Events |\n")
        w("|---|----------|------|-------|--------|\n")
        for i, f in enumerate(finding_list, 1):
            emoji = _SEV_EMOJI.get(f.severity.value, '')
            w(f"| {i} | {emoji} {f.severity.value} | `{f.rule_id}` "
              f"| {f.title} | {f.event_count} |\n")
        w("\n---\n\n")

        # ── Attack Timeline ───────────────────────────────────────────────
        w("## Attack Timeline\n\n")
        w("```\n")
        for entry in timeline:
            ts  = entry.timestamp.strftime('%Y-%m-%d %H:%M:%S') if entry.timestamp else 'unknown time'
            sev = f"[{entry.severity:<8}]"
            kind_marker = "▶▶" if entry.kind == "correlated" else \
                          "▶ " if entry.kind == "finding"    else "  "
            detail = entry.detail[:100] + ('…' if len(entry.detail) > 100 else '')
            w(f"{ts}  {sev}  {kind_marker}  {detail}\n")
        w("```\n\n---\n\n")

        # ── Findings (detail) ─────────────────────────────────────────────
        w("## Findings\n\n")
        for i, f in enumerate(finding_list, 1):
            emoji = _SEV_EMOJI.get(f.severity.value, '')
            w(f"### Finding {i}: {f.title}\n\n")
            w(f"| Field | Value |\n|-------|-------|\n")
            w(f"| Rule | `{f.rule_id}` |\n")
            w(f"| Severity | {emoji} **{f.severity.value}** |\n")
            w(f"| Confidence | {f.confidence.value} |\n")
            w(f"| First seen | {f.first_seen or 'N/A'} |\n")
            w(f"| Last seen | {f.last_seen or 'N/A'} |\n")
            w(f"| Events | {f.event_count} |\n")
            if f.source_ips:
                w(f"| Source IPs | `{'`, `'.join(f.source_ips)}` |\n")
            if f.users:
                w(f"| Accounts | `{'`, `'.join(f.users)}` |\n")
            w(f"\n**Description:** {f.description}\n\n")
            w(f"**Recommendation:** {f.recommendation}\n\n")

            # Show up to 10 evidence events
            if f.events:
                w(f"<details>\n<summary>Evidence ({f.event_count} event(s))</summary>\n\n")
                w("```\n")
                for ev in f.events[:10]:
                    ts = str(ev.timestamp)[:19] if ev.timestamp else 'N/A'
                    w(f"{ts}  [{ev.severity.value}]  {ev.message[:120]}\n")
                if f.event_count > 10:
                    w(f"… and {f.event_count - 10} more event(s)\n")
                w("```\n\n</details>\n\n")

        w("---\n\n")

        # ── Recommended Actions ───────────────────────────────────────────
        w("## Recommended Actions\n\n")
        seen_recs: set[str] = set()
        action_num = 1
        for f in finding_list:
            rec_key = f.recommendation[:60]
            if rec_key not in seen_recs:
                seen_recs.add(rec_key)
                w(f"{action_num}. **[{f.severity.value}]** {f.recommendation}\n\n")
                action_num += 1

        w("---\n\n")

        # ── Evidence summary ──────────────────────────────────────────────
        w("## Evidence Summary\n\n")
        total_events = sum(f.event_count for f in finding_list)
        sources      = sorted({e.source for f in finding_list for e in f.events})
        w(f"- Total events analysed: **{total_events}**\n")
        w(f"- Log sources: {', '.join(f'`{s}`' for s in sources)}\n")
        w(f"- Report generated by: SOC Toolkit\n\n")
        w("*This report was generated automatically. Analyst review is required "
          "before taking action based on these findings.*\n")
