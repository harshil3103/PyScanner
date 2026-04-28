from __future__ import annotations

from pathlib import Path

from pyscanner.models.findings import ScanReport


def report_to_json(report: ScanReport) -> str:
    return report.model_dump_json(indent=2)


def write_json_report(report: ScanReport, path: Path) -> None:
    path.write_text(report_to_json(report), encoding="utf-8")
