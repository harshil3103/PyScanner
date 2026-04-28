from __future__ import annotations

from pathlib import Path

from pyscanner.models.findings import ScanReport


def render_markdown_report(report: ScanReport) -> str:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in report.findings:
        counts[f.severity_label] += 1

    lines = [
        "# PyScanner AI Security Report",
        "",
        "## Scan Summary",
        f"- **Scan ID:** `{report.scan_id}`",
        f"- **Security Score:** **{report.security_score}/100** ({report.score_label})",
        f"- **Files Scanned:** {report.metrics.files_scanned}",
        f"- **Total Findings:** {len(report.findings)}",
        f"- **Duration:** {report.duration_ms} ms",
        "",
        "### Severity Breakdown",
        f"- 🔴 **Critical:** {counts['critical']}",
        f"- 🟠 **High:** {counts['high']}",
        f"- 🟡 **Medium:** {counts['medium']}",
        f"- 🔵 **Low:** {counts['low']}",
        "",
        "## Detailed Findings",
        "",
    ]

    if not report.findings:
        lines.append("🎉 **No vulnerabilities found! Great job.**")
        return "\n".join(lines)

    for i, f in enumerate(report.findings, start=1):
        sev_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}.get(f.severity_label, "⚪")
        
        lines.append(f"### {i}. {sev_icon} [{f.severity_label.upper()}] {f.vulnerability_type}")
        lines.append("")
        lines.append(f"- **Location:** `{f.file_path}:{f.line_number}`")
        if f.owasp_category:
            lines.append(f"- **OWASP:** {f.owasp_category}")
        if f.cwe_id:
            lines.append(f"- **CWE:** {f.cwe_id}")
        lines.append(f"- **Confidence:** {int(f.confidence_score * 100)}%")
        lines.append("")
        
        expl_parts = f.explanation.split("Impact: ")
        lines.append(f"**Issue:** {expl_parts[0].strip()}")
        if len(expl_parts) > 1:
            lines.append("")
            lines.append(f"**Impact:** {expl_parts[1].strip()}")
            
        if f.evidence:
            lines.append("")
            lines.append("```python")
            lines.append(f.evidence.strip())
            lines.append("```")
            
        if f.remediation_suggestion:
            lines.append("")
            lines.append(f"✅ **Fix Recommendation:** {f.remediation_suggestion}")
            
        if f.remediation_code:
            lines.append("")
            lines.append("```python")
            lines.append(f.remediation_code.strip())
            lines.append("```")
            
        lines.append("\n---\n")

    return "\n".join(lines)


def write_markdown_report(report: ScanReport, path: Path) -> None:
    path.write_text(render_markdown_report(report), encoding="utf-8")
