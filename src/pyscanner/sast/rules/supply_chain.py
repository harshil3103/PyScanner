
from __future__ import annotations

import ast
from pathlib import Path

from pyscanner.models.raw import RawFinding

# Known typosquat / malicious packages (curated subset for demonstration)
_KNOWN_TYPOSQUATS: dict[str, str] = {
    "python-dateutil": "python_dateutil",
    "python3-dateutil": "python-dateutil",
    "reqeusts": "requests",
    "requets": "requests",
    "requsts": "requests",
    "reequests": "requests",
    "djando": "django",
    "djnago": "django",
    "fask": "flask",
    "falsk": "flask",
    "numppy": "numpy",
    "nuumpy": "numpy",
    "scikitlearn": "scikit-learn",
    "tenserflow": "tensorflow",
    "teensorflow": "tensorflow",
    "beautifulsoup": "beautifulsoup4",
    "python-nmap": "nmap",
    "colourama": "colorama",
    "coloarama": "colorama",
}

_KNOWN_MALICIOUS: frozenset[str] = frozenset({
    "colourama",
    "python3-dateutil",
    "jeIlyfish",
    "python-sqlite",
    "free-net-vpn",
    "free-net-vpn2",
    "libpeshka",
    "requesocks",
    "distaborutils",
    "typing-extensions-3",
})


def collect(tree: ast.AST, source: str, file_path: Path) -> list[RawFinding]:
    """AST-based rule stub — supply-chain checks run separately via check_manifests."""
    return []


def check_manifests(packages: list[str], file_path: str = "<manifest>") -> list[RawFinding]:
    """Check declared package names for known typosquats and malicious packages."""
    out: list[RawFinding] = []

    for pkg in packages:
        pkg_lower = pkg.lower().strip()

        if pkg_lower in _KNOWN_MALICIOUS:
            out.append(RawFinding(
                file_path=file_path, start_line=1, end_line=1,
                rule_id="py.supply.known-malicious",
                message=f"Package '{pkg}' is a known malicious package. Remove immediately.",
                evidence=pkg, tags=["supply_chain"], cwe_id="CWE-1357",
            ))
        elif pkg_lower in _KNOWN_TYPOSQUATS:
            legit = _KNOWN_TYPOSQUATS[pkg_lower]
            out.append(RawFinding(
                file_path=file_path, start_line=1, end_line=1,
                rule_id="py.supply.typosquat",
                message=f"Package '{pkg}' looks like a typosquat of '{legit}'. Verify spelling.",
                evidence=f"{pkg} → {legit}?", tags=["supply_chain"], cwe_id="CWE-1357",
            ))

    return out
