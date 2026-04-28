from __future__ import annotations

import csv
import io
from pathlib import Path

from pyscanner.models.findings import ScanReport


def render_csv_report(report: ScanReport) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow([
        "Scan ID",
        "Severity Label",
        "Severity Score",
        "Confidence",
        "Vulnerability Type",
        "File Path",
        "Line Number",
        "CWE ID",
        "OWASP Category",
        "Issue",
        "Impact",
        "Remediation Suggestion",
    ])
    
    for f in report.findings:
        expl_parts = f.explanation.split("Impact: ")
        issue = expl_parts[0].strip()
        impact = expl_parts[1].strip() if len(expl_parts) > 1 else ""
        
        writer.writerow([
            report.scan_id,
            f.severity_label.upper(),
            f"{f.severity_score:.1f}",
            f"{int(f.confidence_score * 100)}%",
            f.vulnerability_type,
            f.file_path,
            f.line_number,
            f.cwe_id or "",
            f.owasp_category or "",
            issue,
            impact,
            f.remediation_suggestion or "",
        ])
        
    return output.getvalue()


def write_csv_report(report: ScanReport, path: Path) -> None:
    path.write_text(render_csv_report(report), encoding="utf-8")
