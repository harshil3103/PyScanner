from __future__ import annotations

import re
from pathlib import Path

from pydantic import BaseModel, Field


class DependencyManifest(BaseModel):
    requirements_files: list[str] = Field(default_factory=list)
    pyproject_path: str | None = None
    declared_packages: list[str] = Field(default_factory=list)


_REQ_LINE = re.compile(r"^([A-Za-z0-9_.\-]+)", re.MULTILINE)


def extract_manifests(root: Path) -> DependencyManifest:
    root = root.resolve()
    req_files: list[str] = []
    pyproject: str | None = None
    packages: list[str] = []

    if root.is_file():
        base = root.parent
    else:
        base = root

    for name in ("requirements.txt", "requirements-dev.txt", "constraints.txt"):
        p = base / name
        if p.is_file():
            req_files.append(str(p))
            packages.extend(_parse_requirements(p.read_text()))

    pp = base / "pyproject.toml"
    if pp.is_file():
        pyproject = str(pp)
        packages.extend(_parse_pyproject_deps(pp.read_text()))

    return DependencyManifest(
        requirements_files=req_files,
        pyproject_path=pyproject,
        declared_packages=sorted(set(packages)),
    )


def _parse_requirements(text: str) -> list[str]:
    names: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = _REQ_LINE.match(line)
        if m:
            names.append(m.group(1).lower())
    return names


def _parse_pyproject_deps(text: str) -> list[str]:
    """Very small TOML-ish scrape for dependencies; full parse deferred."""
    names: list[str] = []
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("#"):
            continue
        if "=" in s and '"' in s:
            # e.g. requests = "^2.0"
            pkg = s.split("=", 1)[0].strip().strip('"').strip("'")
            if pkg and pkg[0].isalpha():
                names.append(pkg.lower())
    return names
