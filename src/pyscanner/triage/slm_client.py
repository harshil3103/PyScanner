from __future__ import annotations

import json
import re
from typing import Literal

import httpx
from pydantic import BaseModel, Field

from pyscanner.config.settings import ScanConfig
from pyscanner.models.raw import RawFinding
from pyscanner.slicer.slice_builder import ProgramSlice
from pyscanner.triage.prompts import build_triage_prompt


class SlmTriageResult(BaseModel):
    verdict: Literal["true_positive", "false_positive", "uncertain"]
    confidence: float = Field(ge=0.0, le=1.0)
    rationale_short: str = ""


class SlmClient:
    def __init__(self, config: ScanConfig) -> None:
        self._config = config

    def triage(self, finding: RawFinding, slice_: ProgramSlice) -> SlmTriageResult | None:
        if not self._config.enable_slm:
            return None
        url = f"{self._config.ollama_base_url.rstrip('/')}/api/generate"
        prompt = build_triage_prompt(finding, slice_)
        payload = {
            "model": self._config.ollama_model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0},
        }
        try:
            r = httpx.post(url, json=payload, timeout=60.0)
            r.raise_for_status()
            data = r.json()
            text = data.get("response", "")
        except (httpx.HTTPError, ValueError, KeyError):
            return None
        return _parse_slm_json(text)


def _parse_slm_json(text: str) -> SlmTriageResult | None:
    m = re.search(r"\{[^{}]*\}", text, re.DOTALL)
    if not m:
        return None
    try:
        obj = json.loads(m.group())
        return SlmTriageResult.model_validate(obj)
    except (json.JSONDecodeError, ValueError):
        return None
