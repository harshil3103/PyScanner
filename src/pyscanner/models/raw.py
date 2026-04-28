from __future__ import annotations

from pydantic import BaseModel, Field


class RawFinding(BaseModel):
    """Finding emitted by the rule-based SAST engine before triage/LLM."""

    file_path: str
    start_line: int
    end_line: int
    start_col: int = 0
    end_col: int = 0
    rule_id: str
    message: str
    evidence: str = ""
    tags: list[str] = Field(default_factory=list)
    cwe_id: str | None = None
