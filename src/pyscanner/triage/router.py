from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from pyscanner.config.settings import ScanConfig
from pyscanner.models.raw import RawFinding
from pyscanner.slicer.slice_builder import ProgramSlice
from pyscanner.triage.slm_client import SlmClient, SlmTriageResult


class TriageVerdict(BaseModel):
    """Outcome after SLM (and optional LLM escalation)."""

    label: Literal["true_positive", "false_positive", "uncertain"]
    confidence: float = Field(ge=0.0, le=1.0)
    used_slm: bool = False


def route_finding(
    finding: RawFinding,
    slice_: ProgramSlice,
    *,
    config: ScanConfig,
    slm: SlmClient | None = None,
) -> TriageVerdict:
    """Route raw finding: SLM when online; else uncertain for LLM/policy."""
    client = slm or SlmClient(config)
    if not config.enable_slm:
        return TriageVerdict(label="uncertain", confidence=0.5, used_slm=False)
    res: SlmTriageResult | None = client.triage(finding, slice_)
    if res is None:
        return TriageVerdict(label="uncertain", confidence=0.5, used_slm=False)
    high = res.confidence >= 0.85 and res.verdict in {"true_positive", "false_positive"}
    if high:
        return TriageVerdict(label=res.verdict, confidence=res.confidence, used_slm=True)
    return TriageVerdict(label="uncertain", confidence=res.confidence, used_slm=True)
