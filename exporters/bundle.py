"""
exporters/bundle.py
-------------------
Generates a ZIP evidence bundle containing:
  - report.md       — Markdown report
  - report.html     — HTML case report
  - findings.json   — Full structured JSON
  - evidence.log    — Filtered raw log lines from all evidence events
  - manifest.txt    — Bundle metadata

The bundle is self-contained and suitable for attaching to IR tickets,
sharing with stakeholders, or archiving.
"""

from __future__ import annotations

import io
import zipfile
from datetime import datetime
from pathlib  import Path
from typing   import Iterator

from .markdown   import MarkdownExporter
from .html_report import HtmlExporter
from .json_export import JsonExporter
from soc_toolkit.models.finding import Finding


def create_bundle(
    findings:    Iterator[Finding],
    output_path: Path,
) -> Path:
    """
    Write a ZIP bundle to output_path and return the path.
    output_path should end in .zip.
    """
    finding_list = list(findings)
    now          = datetime.now()
    ts_str       = now.strftime('%Y%m%d_%H%M%S')

    if not str(output_path).endswith('.zip'):
        output_path = output_path.with_suffix('.zip')

    with zipfile.ZipFile(output_path, 'w', compression=zipfile.ZIP_DEFLATED) as zf:

        # ── Markdown report ───────────────────────────────────────────────
        md_buf = io.StringIO()
        MarkdownExporter().export(iter(finding_list), md_buf)
        zf.writestr('report.md', md_buf.getvalue())

        # ── HTML report ───────────────────────────────────────────────────
        html_buf = io.StringIO()
        HtmlExporter().export(iter(finding_list), html_buf)
        zf.writestr('report.html', html_buf.getvalue())

        # ── JSON export ───────────────────────────────────────────────────
        json_buf = io.StringIO()
        JsonExporter().export(iter(finding_list), json_buf)
        zf.writestr('findings.json', json_buf.getvalue())

        # ── Raw evidence log ──────────────────────────────────────────────
        ev_lines: list[str] = []
        seen_raws: set[str] = set()
        for f in finding_list:
            ev_lines.append(f"# Finding: {f.title} [{f.severity.value}]")
            for ev in f.events:
                if ev.raw and ev.raw not in seen_raws:
                    seen_raws.add(ev.raw)
                    ev_lines.append(ev.raw)
            ev_lines.append('')
        zf.writestr('evidence.log', '\n'.join(ev_lines))

        # ── Manifest ──────────────────────────────────────────────────────
        all_ips   = sorted({ip for f in finding_list for ip in f.source_ips})
        all_users = sorted({u  for f in finding_list for u  in f.users})
        criticals = sum(1 for f in finding_list if f.severity.value == 'CRITICAL')

        manifest = [
            f"SOC Toolkit — Evidence Bundle",
            f"Generated:      {now.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"",
            f"Summary:",
            f"  Total findings:  {len(finding_list)}",
            f"  Critical:        {criticals}",
            f"  Source IPs:      {', '.join(all_ips) or 'none'}",
            f"  Accounts:        {', '.join(all_users) or 'none'}",
            f"  Evidence events: {sum(len(f.events) for f in finding_list)}",
            f"",
            f"Files:",
            f"  report.md      — Markdown incident report",
            f"  report.html    — HTML case report (self-contained)",
            f"  findings.json  — Structured JSON for SIEM/pipeline",
            f"  evidence.log   — Filtered raw log lines",
            f"  manifest.txt   — This file",
            f"",
            f"IMPORTANT: This bundle was generated automatically.",
            f"Analyst review is required before taking action.",
        ]
        zf.writestr('manifest.txt', '\n'.join(manifest))

    return output_path
