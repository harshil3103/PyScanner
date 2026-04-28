from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field


class Reference(BaseModel):
    kind: Literal["cwe", "owasp", "url", "doc"]
    id_or_url: str


class SecurityFinding(BaseModel):
    file_path: str
    line_number: int
    end_line: int | None = None
    vulnerability_type: str
    cwe_id: str | None = None
    severity_score: float = Field(ge=0.0, le=10.0)
    severity_label: Literal["critical", "high", "medium", "low"] = "medium"
    confidence_score: float = Field(ge=0.0, le=1.0)
    explanation: str
    owasp_category: str | None = None
    remediation_code: str | None = None
    remediation_suggestion: str | None = None
    references: list[Reference] = Field(default_factory=list)
    provenance: Literal["rule", "slm", "llm", "hybrid"] = "rule"
    rule_id: str | None = None
    slice_id: str | None = None
    evidence: str | None = None
    false_positive: bool = False
    feedback_note: str | None = None


class ScanSummary(BaseModel):
    files_scanned: int = 0
    raw_findings: int = 0
    llm_calls: int = 0
    slm_calls: int = 0
    estimated_cost_usd: float = 0.0


class ScanReport(BaseModel):
    schema_version: str = "1.1"
    scan_id: str
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    duration_ms: int = 0
    config_summary: dict = Field(default_factory=dict)
    metrics: ScanSummary = Field(default_factory=ScanSummary)
    findings: list[SecurityFinding] = Field(default_factory=list)
    security_score: int = 100
    score_label: str = "Excellent"

