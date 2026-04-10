"""
exporters/html_report.py
------------------------
Generates a self-contained HTML case report. No external dependencies —
the CSS and JS are inlined so the file works offline and can be attached
to tickets or emailed directly.
"""

from __future__ import annotations

from datetime import datetime
from typing   import IO, Iterator

from .base     import BaseExporter
from .timeline import build_timeline
from soc_toolkit.models.finding import Finding


_SEV_COLOR = {
    'CRITICAL': ('#7f1d1d', '#fca5a5'),
    'HIGH':     ('#7c2d12', '#fdba74'),
    'MEDIUM':   ('#713f12', '#fde68a'),
    'LOW':      ('#14532d', '#86efac'),
    'INFO':     ('#1e3a5f', '#93c5fd'),
}
_SEV_RANK = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}


def _badge(severity: str) -> str:
    bg, fg = _SEV_COLOR.get(severity, ('#374151', '#d1d5db'))
    return (f'<span style="background:{bg};color:{fg};padding:2px 8px;'
            f'border-radius:4px;font-size:11px;font-weight:700;'
            f'letter-spacing:0.05em">{severity}</span>')


def _esc(s: str) -> str:
    return (s.replace('&', '&amp;').replace('<', '&lt;')
             .replace('>', '&gt;').replace('"', '&quot;'))


class HtmlExporter(BaseExporter):

    def export(self, findings: Iterator[Finding], stream: IO[str]) -> None:
        finding_list = sorted(
            list(findings),
            key=lambda f: _SEV_RANK.get(f.severity.value, 9)
        )
        timeline = build_timeline(finding_list)
        now      = datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')

        all_ips   = sorted({ip for f in finding_list for ip in f.source_ips})
        all_users = sorted({u  for f in finding_list for u  in f.users})
        criticals = sum(1 for f in finding_list if f.severity.value == 'CRITICAL')
        highs     = sum(1 for f in finding_list if f.severity.value == 'HIGH')

        stream.write(f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SOC Report — {now}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
  background:#0f172a;color:#e2e8f0;font-size:14px;line-height:1.6}}
.wrap{{max-width:960px;margin:0 auto;padding:32px 24px 80px}}
h1{{font-size:28px;font-weight:700;color:#f8fafc;margin-bottom:4px}}
h2{{font-size:18px;font-weight:600;color:#cbd5e1;margin:32px 0 12px;
  border-bottom:1px solid #1e293b;padding-bottom:8px}}
h3{{font-size:15px;font-weight:600;color:#94a3b8;margin:20px 0 8px}}
.meta{{color:#64748b;font-size:12px;margin-bottom:24px}}
.stat-row{{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));
  gap:12px;margin-bottom:28px}}
.stat{{background:#1e293b;border:1px solid #334155;border-radius:8px;
  padding:14px;text-align:center}}
.stat-val{{font-size:28px;font-weight:700;color:#38bdf8}}
.stat-label{{font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:.05em}}
.stat-val.red{{color:#f87171}} .stat-val.amber{{color:#fb923c}}
.stat-val.green{{color:#4ade80}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th{{text-align:left;padding:8px 12px;background:#1e293b;
  color:#94a3b8;font-weight:500;font-size:11px;text-transform:uppercase;letter-spacing:.05em}}
td{{padding:8px 12px;border-bottom:1px solid #1e293b;vertical-align:top}}
tr:hover td{{background:#1e293b}}
.finding-card{{background:#1e293b;border:1px solid #334155;border-radius:10px;
  margin-bottom:16px;overflow:hidden}}
.finding-header{{padding:14px 18px;display:flex;align-items:center;
  gap:12px;cursor:pointer;user-select:none}}
.finding-header:hover{{background:#273549}}
.finding-body{{padding:0 18px 16px;display:none}}
.finding-body.open{{display:block}}
.finding-title{{flex:1;font-weight:600;color:#f1f5f9}}
.detail-grid{{display:grid;grid-template-columns:140px 1fr;
  gap:4px 12px;font-size:13px;margin:12px 0}}
.detail-label{{color:#64748b;font-weight:500}}
.detail-val{{color:#cbd5e1}}
pre{{background:#0f172a;border:1px solid #334155;border-radius:6px;
  padding:12px;font-size:11px;overflow-x:auto;color:#94a3b8;
  font-family:'JetBrains Mono',monospace;white-space:pre-wrap;word-break:break-all}}
.timeline-entry{{display:grid;grid-template-columns:160px 90px 1fr;
  gap:8px;padding:6px 0;border-bottom:1px solid #1e293b;font-size:12px}}
.timeline-entry.finding{{background:#1e293b;border-radius:4px;
  padding:6px 8px;margin:4px 0}}
.timeline-entry.correlated{{background:#172033;border-left:3px solid #818cf8;
  padding:6px 8px;margin:4px 0}}
.ts{{color:#475569;font-family:monospace}}
.msg{{color:#cbd5e1}}
.rec{{background:#172033;border-left:3px solid #fbbf24;padding:10px 14px;
  border-radius:0 6px 6px 0;margin:10px 0;color:#fde68a;font-size:13px}}
.ip-pill{{display:inline-block;background:#1e3a5f;color:#93c5fd;
  padding:2px 8px;border-radius:4px;font-size:11px;font-family:monospace;margin:2px}}
footer{{margin-top:48px;padding-top:16px;border-top:1px solid #1e293b;
  color:#475569;font-size:11px;text-align:center}}
</style>
</head>
<body>
<div class="wrap">
<h1>SOC Investigation Report</h1>
<div class="meta">Generated: {now}</div>

<div class="stat-row">
  <div class="stat">
    <div class="stat-val {'red' if criticals else 'amber' if highs else 'green'}">{len(finding_list)}</div>
    <div class="stat-label">Findings</div>
  </div>
  <div class="stat">
    <div class="stat-val red">{criticals}</div>
    <div class="stat-label">Critical</div>
  </div>
  <div class="stat">
    <div class="stat-val amber">{highs}</div>
    <div class="stat-label">High</div>
  </div>
  <div class="stat">
    <div class="stat-val">{len(all_ips)}</div>
    <div class="stat-label">Source IPs</div>
  </div>
  <div class="stat">
    <div class="stat-val">{len(all_users)}</div>
    <div class="stat-label">Accounts</div>
  </div>
</div>
""")

        # ── Finding table ─────────────────────────────────────────────────
        stream.write("<h2>Findings</h2>\n")
        stream.write("<table><tr><th>#</th><th>Severity</th><th>Rule</th>"
                     "<th>Title</th><th>Events</th><th>IPs</th></tr>\n")
        for i, f in enumerate(finding_list, 1):
            ips = ', '.join(f'<span class="ip-pill">{_esc(ip)}</span>'
                            for ip in f.source_ips) or '—'
            stream.write(
                f"<tr><td>{i}</td><td>{_badge(f.severity.value)}</td>"
                f"<td><code>{_esc(f.rule_id)}</code></td>"
                f"<td>{_esc(f.title)}</td><td>{f.event_count}</td>"
                f"<td>{ips}</td></tr>\n"
            )
        stream.write("</table>\n")

        # ── Finding detail cards ──────────────────────────────────────────
        stream.write("<h2>Finding Details</h2>\n")
        for i, f in enumerate(finding_list, 1):
            stream.write(
                f'<div class="finding-card">'
                f'<div class="finding-header" onclick="toggle(this)">'
                f'{_badge(f.severity.value)}'
                f'<span class="finding-title">{i}. {_esc(f.title)}</span>'
                f'<span style="color:#475569;font-size:12px">'
                f'{f.event_count} events ▶</span>'
                f'</div>'
                f'<div class="finding-body">'
            )
            stream.write('<div class="detail-grid">')
            rows = [
                ("Rule",        f'<code>{_esc(f.rule_id)}</code>'),
                ("Confidence",  f.confidence.value),
                ("First seen",  str(f.first_seen or "N/A")),
                ("Last seen",   str(f.last_seen  or "N/A")),
                ("Event count", str(f.event_count)),
            ]
            if f.source_ips:
                rows.append(("Source IPs",
                    ' '.join(f'<span class="ip-pill">{_esc(ip)}</span>'
                             for ip in f.source_ips)))
            if f.users:
                rows.append(("Accounts",
                    ' '.join(f'<span class="ip-pill">{_esc(u)}</span>'
                             for u in f.users)))
            for label, val in rows:
                stream.write(f'<span class="detail-label">{label}</span>'
                             f'<span class="detail-val">{val}</span>')
            stream.write('</div>')

            stream.write(f'<p style="margin:10px 0;color:#cbd5e1">'
                         f'{_esc(f.description)}</p>')
            stream.write(f'<div class="rec">→ {_esc(f.recommendation)}</div>')

            if f.events:
                stream.write(f'<h3>Evidence ({f.event_count} events)</h3><pre>')
                for ev in f.events[:15]:
                    ts  = str(ev.timestamp)[:19] if ev.timestamp else "N/A"
                    msg = _esc(ev.message[:120])
                    stream.write(f"{ts}  [{ev.severity.value:<8}]  {msg}\n")
                if f.event_count > 15:
                    stream.write(f"… and {f.event_count - 15} more\n")
                stream.write("</pre>")

            stream.write("</div></div>\n")

        # ── Timeline ──────────────────────────────────────────────────────
        stream.write("<h2>Attack Timeline</h2>\n")
        for entry in timeline:
            ts  = entry.timestamp.strftime('%Y-%m-%d %H:%M:%S') \
                  if entry.timestamp else 'unknown'
            detail = _esc(entry.detail[:120])
            css    = f"timeline-entry {entry.kind}"
            stream.write(
                f'<div class="{css}">'
                f'<span class="ts">{ts}</span>'
                f'{_badge(entry.severity)}'
                f'<span class="msg">{detail}</span>'
                f'</div>\n'
            )

        stream.write(f"""
<footer>
  SOC Toolkit — auto-generated report — analyst review required before action
</footer>
</div>
<script>
function toggle(header) {{
  const body = header.nextElementSibling;
  body.classList.toggle('open');
  const arrow = header.querySelector('span:last-child');
  arrow.textContent = body.classList.contains('open')
    ? arrow.textContent.replace('▶','▼')
    : arrow.textContent.replace('▼','▶');
}}
</script>
</body></html>
""")
