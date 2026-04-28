from __future__ import annotations

import json
from pathlib import Path

from pyscanner.models.findings import ScanReport, SecurityFinding


def report_to_sarif(report: ScanReport) -> str:
    """Minimal SARIF 2.1.0 envelope for CI uploads."""
    runs = [
        {
            "tool": {"driver": {"name": "pyscanner", "version": "0.1.0"}},
            "results": [_finding_to_sarif(f) for f in report.findings],
        }
    ]
    doc = {
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": runs,
    }
    return json.dumps(doc, indent=2)


def write_sarif_report(report: ScanReport, path: Path) -> None:
    path.write_text(report_to_sarif(report), encoding="utf-8")


def _finding_to_sarif(f: SecurityFinding) -> dict:
    uri = Path(f.file_path).as_posix()
    return {
        "ruleId": f.rule_id or f.vulnerability_type,
        "message": {"text": f.explanation},
        "level": "warning",
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": f.line_number, "endLine": f.end_line or f.line_number},
                }
            }
        ],
        "properties": {"severityScore": f.severity_score, "confidence": f.confidence_score},
    }
