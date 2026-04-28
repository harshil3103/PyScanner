from __future__ import annotations

from pydantic import BaseModel, Field

from pyscanner.models.findings import Reference, SecurityFinding


class LlmSecurityFinding(BaseModel):
    """Strict schema for LLM JSON output before mapping to SecurityFinding."""

    vulnerability_type: str
    cwe_id: str | None = None
    severity_score: float = Field(ge=0.0, le=10.0)
    confidence_score: float = Field(ge=0.0, le=1.0)
    explanation: str
    remediation_code: str | None = None
    references: list[Reference] = Field(default_factory=list)

    def to_security_finding(
        self,
        *,
        file_path: str,
        line_number: int,
        rule_id: str | None,
        slice_id: str | None,
    ) -> SecurityFinding:
        return SecurityFinding(
            file_path=file_path,
            line_number=line_number,
            end_line=None,
            vulnerability_type=self.vulnerability_type,
            cwe_id=self.cwe_id,
            severity_score=self.severity_score,
            confidence_score=self.confidence_score,
            explanation=self.explanation,
            remediation_code=self.remediation_code,
            references=self.references,
            provenance="llm",
            rule_id=rule_id,
            slice_id=slice_id,
        )


class LlmTriageJson(BaseModel):
    """Optional wrapper when model returns {finding: ...}."""

    finding: LlmSecurityFinding
