from __future__ import annotations

from dataclasses import dataclass

from pyscanner.models.findings import SecurityFinding


@dataclass
class ShadowRuleDraft:
    yaml_text: str
    confidence: float
    tests_hint: str


def propose_shadow_rule(finding: SecurityFinding) -> ShadowRuleDraft | None:
    """Generate a Semgrep-style stub when LLM confirmed something actionable."""
    if finding.provenance not in {"llm", "hybrid"}:
        return None
    rid = finding.vulnerability_type.replace(" ", "-").lower()[:40]
    yaml_text = (
        "rules:\n"
        f"  - id: shadow.{rid}\n"
        "    languages: [python]\n"
        f"    message: {finding.explanation[:120]!r}\n"
        "    severity: ERROR\n"
        "    metadata:\n"
        f"      cwe: {finding.cwe_id or 'CWE-000'}\n"
        "      origin: shadow_generator\n"
        "    pattern-either:\n"
        "      - pattern: eval(...)\n"
        "      - pattern: exec(...)\n"
    )
    return ShadowRuleDraft(
        yaml_text=yaml_text,
        confidence=finding.confidence_score,
        tests_hint="Add positive/negative fixtures under tests/bench/",
    )
