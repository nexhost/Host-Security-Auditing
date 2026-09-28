from __future__ import annotations

import html
from datetime import datetime, timezone


def render_html(payload: dict) -> str:
    summary = payload["summary"]
    assets = "".join(
        f"<tr><td>{html.escape(str(a['address']))}</td><td>{html.escape(str(a.get('hostname') or ''))}</td>"
        f"<td>{html.escape(str(a.get('status') or ''))}</td><td>{html.escape(str(a.get('os') or ''))}</td></tr>"
        for a in payload["assets"]
    )
    findings = "".join(
        f"<tr><td class='{html.escape(str(f['severity']).lower())}'>{html.escape(str(f['severity']))}</td>"
        f"<td>{html.escape(str(f['title']))}</td><td>{html.escape(str(f['category']))}</td>"
        f"<td>{html.escape(str(f['evidence']))}</td><td>{html.escape(str(f['recommendation']))}</td></tr>"
        for f in payload["findings"]
    )
    generated = datetime.now(timezone.utc).isoformat()
    return f"""<!doctype html><html><head><meta charset='utf-8'><title>Nexhost HSA Report</title>
<style>body{{font:14px Arial;color:#182331;margin:35px}}h1{{color:#0b617a}}.notice{{background:#fff3cd;padding:12px}}
.cards{{display:flex;gap:12px}}.card{{background:#eef4f7;padding:14px;min-width:100px}}table{{width:100%;border-collapse:collapse;margin:16px 0}}
th,td{{border:1px solid #ccd6dd;padding:7px;text-align:left}}th{{background:#17354a;color:white}}.critical,.high{{color:#a51d2d}}.medium{{color:#9a6500}}</style></head>
<body><h1>Nexhost HSA Security Posture Report</h1><p>Generated {generated}</p>
<div class='notice'>Authorized assessment only. Potential risks and CVE matches require validation; this report does not assert legal compliance or certification.</div>
<h2>Executive Summary</h2><div class='cards'>{''.join(f"<div class='card'><b>{value}</b><br>{html.escape(key.title())}</div>" for key,value in summary.items())}</div>
<h2>Scope and Methodology</h2><p>Nmap XML evidence, normalized inventory, non-destructive exposure rules, and HSA scoring.</p>
<h2>Assets</h2><table><thead><tr><th>Address</th><th>Hostname</th><th>Status</th><th>OS</th></tr></thead><tbody>{assets}</tbody></table>
<h2>Findings and Remediation</h2><table><thead><tr><th>Severity</th><th>Finding</th><th>Type</th><th>Evidence</th><th>Recommendation</th></tr></thead><tbody>{findings}</tbody></table>
<h2>Compliance</h2><p>Mappings are technical evidence aids and do not represent certification.</p><h2>Appendix</h2><p>Raw evidence remains in the protected evidence directory.</p></body></html>"""

