from __future__ import annotations

import sqlite3
import uuid
from pathlib import Path

from pyscanner.models.findings import ScanReport


class SqliteStore:
    def __init__(self, db_path: Path) -> None:
        self._path = db_path
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def _conn(self) -> sqlite3.Connection:
        con = sqlite3.connect(self._path)
        con.execute("PRAGMA journal_mode=WAL;")
        con.row_factory = sqlite3.Row
        return con

    def _init(self) -> None:
        with self._conn() as c:
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    created_at TEXT,
                    payload TEXT NOT NULL
                );
                """
            )
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS shadow_rules (
                    rule_id TEXT PRIMARY KEY,
                    yaml TEXT NOT NULL,
                    state TEXT NOT NULL
                );
                """
            )
            c.commit()

    def save_scan(self, report: ScanReport) -> None:
        with self._conn() as c:
            c.execute(
                "INSERT OR REPLACE INTO scans(scan_id, created_at, payload) VALUES(?,?,?)",
                (
                    report.scan_id,
                    report.started_at.isoformat(),
                    report.model_dump_json(),
                ),
            )
            c.commit()

    def new_scan_id(self) -> str:
        return str(uuid.uuid4())

    def get_scan(self, scan_id: str) -> ScanReport | None:
        with self._conn() as c:
            row = c.execute("SELECT payload FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
            if row:
                return ScanReport.model_validate_json(row["payload"])
        return None

    def get_history(self, limit: int = 10) -> list[ScanReport]:
        """Return the last N scan reports."""
        with self._conn() as c:
            rows = c.execute(
                "SELECT payload FROM scans ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
            return [ScanReport.model_validate_json(r["payload"]) for r in rows]

    def mark_feedback(self, scan_id: str, file_path: str, line_number: int, is_fp: bool, note: str = "") -> bool:
        """Mark a specific finding as a false positive within the stored report JSON."""
        report = self.get_scan(scan_id)
        if not report:
            return False
            
        updated = False
        for f in report.findings:
            if f.file_path == file_path and f.line_number == line_number:
                f.false_positive = is_fp
                f.feedback_note = note
                updated = True
                
        if updated:
            self.save_scan(report)
            return True
        return False
