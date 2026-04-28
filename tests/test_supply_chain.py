
from __future__ import annotations

from pyscanner.sast.rules.supply_chain import check_manifests


def test_detects_typosquat() -> None:
    findings = check_manifests(["reqeusts", "flask"])
    assert any(f.rule_id == "py.supply.typosquat" for f in findings)
    assert not any(f.rule_id == "py.supply.typosquat" and "flask" in f.evidence for f in findings)


def test_detects_known_malicious() -> None:
    findings = check_manifests(["colourama", "requests"])
    assert any(f.rule_id == "py.supply.known-malicious" for f in findings)


def test_clean_packages_no_findings() -> None:
    findings = check_manifests(["requests", "flask", "django", "numpy"])
    assert len(findings) == 0
