"""Security score computation for scan reports."""
from __future__ import annotations

from pyscanner.models.findings import SecurityFinding

# Deductions per severity bucket (from a 100-point baseline)
_PENALTY = {"critical": 15, "high": 8, "medium": 3, "low": 1}

# Thresholds for the severity label derived from the 0–10 score
_SEVERITY_THRESHOLDS = [(8.5, "critical"), (6.5, "high"), (4.0, "medium")]


def severity_label(score: float) -> str:
    for threshold, label in _SEVERITY_THRESHOLDS:
        if score >= threshold:
            return label
    return "low"


def compute_score(findings: list[SecurityFinding]) -> int:
    """Return a 0–100 project security score.

    Starts at 100 and deducts points for each finding, weighted
    by severity and confidence.  Extra penalties for critical
    findings and widespread file impact.
    """
    if not findings:
        return 100

    total = 100.0
    affected_files: set[str] = set()

    for f in findings:
        label = severity_label(f.severity_score)
        penalty = _PENALTY.get(label, 1) * f.confidence_score
        total -= penalty
        affected_files.add(f.file_path)

    # Extra penalty when many distinct files are affected
    spread_ratio = len(affected_files) / max(len(findings), 1)
    if len(affected_files) > 5:
        total -= spread_ratio * 5

    return max(0, min(100, int(total)))


def score_label(score: int) -> str:
    if score >= 85:
        return "Excellent"
    if score >= 65:
        return "Good"
    if score >= 40:
        return "Risky"
    return "Critical"
