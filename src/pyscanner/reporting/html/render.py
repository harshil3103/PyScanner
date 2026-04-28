from __future__ import annotations
import html
from pathlib import Path
from pyscanner.models.findings import ScanReport
def render_html_report(report: ScanReport) -> str:
    # Colors matching the CLI
    colors = {
        "critical": "#ff4444",
        "high": "#ff8800",
        "medium": "#ffcc00",
        "low": "#33b5e5",
    }
    
    score_colors = {
        "Excellent": "#00C851",
        "Good": "#33b5e5",
        "Risky": "#ffbb33",
        "Critical": "#ff4444",
    }
    
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in report.findings:
        counts[f.severity_label] += 1

    rows = []
    for f in report.findings:
        color = colors.get(f.severity_label, "#ffffff")
        
        # Build explanation with impact
        expl_parts = f.explanation.split("Impact: ")
        issue = html.escape(expl_parts[0].strip())
        impact = ""
        if len(expl_parts) > 1:
            impact = f"<br/><br/><strong>Impact:</strong> {html.escape(expl_parts[1].strip())}"
        
        # Build remediation block
        remedy = ""
        if f.remediation_suggestion:
            remedy += f"<div class='remedy-hint'><strong>Fix:</strong> {html.escape(f.remediation_suggestion)}</div>"
        if f.remediation_code:
            remedy += f"<pre class='remedy-code'><code>{html.escape(f.remediation_code)}</code></pre>"
            
        snippet = f"<pre class='evidence'><code>{html.escape(f.evidence or '')}</code></pre>" if f.evidence else ""

        rows.append(
            f"<div class='finding-card' style='border-left: 4px solid {color}'>"
            f"<div class='finding-header'>"
            f"<span class='badge' style='background: {color}'>{f.severity_label.upper()}</span>"
            f"<span class='title'>{html.escape(f.vulnerability_type)}</span>"
            f"<span class='location'>{html.escape(f.file_path)}:{f.line_number}</span>"
            f"</div>"
            f"<div class='finding-body'>"
            f"<p><strong>Issue:</strong> {issue}{impact}</p>"
            f"{snippet}"
            f"{remedy}"
            f"</div>"
            f"<div class='finding-footer'>"
            f"<span>Confidence: {int(f.confidence_score * 100)}%</span>"
            f"<span>OWASP: {html.escape(f.owasp_category or 'N/A')}</span>"
            f"<span>CWE: {html.escape(f.cwe_id or 'N/A')}</span>"
            f"</div>"
            f"</div>"
        )

    findings_html = "\n".join(rows) if rows else "<div class='finding-card'><p>No vulnerabilities found!</p></div>"
    score_color = score_colors.get(report.score_label, "#ffffff")

    return f"""<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PyScanner Security Report</title>
    <style>
        :root {{
            --bg: #0d1117;
            --surface: #161b22;
            --border: #30363d;
            --text: #c9d1d9;
            --text-muted: #8b949e;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            line-height: 1.5;
            margin: 0;
            padding: 2rem;
        }}
        .container {{
            max-width: 1000px;
            margin: 0 auto;
        }}
        .dashboard {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 2rem;
            margin-bottom: 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .score-box {{
            text-align: center;
        }}
        .score-value {{
            font-size: 3rem;
            font-weight: bold;
            color: {score_color};
        }}
        .score-label {{
            font-size: 1.2rem;
            color: {score_color};
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        .stats {{
            display: flex;
            gap: 2rem;
        }}
        .stat-item {{
            display: flex;
            flex-direction: column;
        }}
        .stat-value {{ font-size: 1.5rem; font-weight: bold; }}
        .stat-label {{ color: var(--text-muted); font-size: 0.9rem; text-transform: uppercase; }}
        
        .finding-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            margin-bottom: 1rem;
            overflow: hidden;
        }}
        .finding-header {{
            padding: 1rem;
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            gap: 1rem;
            background: rgba(255,255,255,0.02);
        }}
        .badge {{
            color: #000;
            padding: 0.2rem 0.6rem;
            border-radius: 12px;
            font-size: 0.8rem;
            font-weight: bold;
        }}
        .title {{ font-weight: bold; font-size: 1.1rem; }}
        .location {{ color: var(--text-muted); margin-left: auto; font-family: monospace; }}
        
        .finding-body {{ padding: 1rem; }}
        .evidence {{
            background: #000;
            padding: 1rem;
            border-radius: 6px;
            overflow-x: auto;
            border: 1px solid var(--border);
        }}
        .remedy-hint {{
            color: #56d364;
            margin-top: 1rem;
        }}
        .remedy-code {{
            background: #0d2a1a;
            border: 1px solid #1a4d2e;
            padding: 1rem;
            border-radius: 6px;
            color: #56d364;
            overflow-x: auto;
        }}
        
        .finding-footer {{
            padding: 0.75rem 1rem;
            background: rgba(0,0,0,0.2);
            border-top: 1px solid var(--border);
            display: flex;
            gap: 2rem;
            font-size: 0.85rem;
            color: var(--text-muted);
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>PyScanner AI Security Report</h1>
        
        <div class="dashboard">
            <div class="stats">
                <div class="stat-item">
                    <span class="stat-value">{report.metrics.files_scanned}</span>
                    <span class="stat-label">Files Scanned</span>
                </div>
                <div class="stat-item">
                    <span class="stat-value">{len(report.findings)}</span>
                    <span class="stat-label">Findings</span>
                </div>
                <div class="stat-item">
                    <span class="stat-value">{report.duration_ms}ms</span>
                    <span class="stat-label">Duration</span>
                </div>
                <div class="stat-item">
                    <span class="stat-value" style="color: #ff4444">{counts['critical']}</span>
                    <span class="stat-label">Critical</span>
                </div>
                <div class="stat-item">
                    <span class="stat-value" style="color: #ff8800">{counts['high']}</span>
                    <span class="stat-label">High</span>
                </div>
            </div>
            
            <div class="score-box">
                <div class="score-value">{report.security_score}/100</div>
                <div class="score-label">{report.score_label}</div>
            </div>
        </div>
        
        <h2>Detailed Findings</h2>
        {findings_html}
    </div>
</body>
</html>
"""


def write_html_report(report: ScanReport, path: Path) -> None:
    path.write_text(render_html_report(report), encoding="utf-8")

