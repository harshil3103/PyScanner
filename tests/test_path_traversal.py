from __future__ import annotations

import hashlib
from pathlib import Path

from pyscanner.ingestion.ast_parse import parse_python_file
from pyscanner.ingestion.reader import CodeUnit
from pyscanner.sast.engine import run_sast


def _unit(content: str) -> CodeUnit:
    return CodeUnit(
        path=Path("dummy.py"),
        content=content,
        content_sha256=hashlib.sha256(content.encode()).hexdigest(),
    )


def test_detects_open_with_variable() -> None:
    src = "data = open(user_path).read()\n"
    parsed = parse_python_file(_unit(src))
    findings = run_sast(parsed)
    assert any(f.rule_id == "py.path.open-variable" for f in findings)


def test_detects_os_path_join_variable() -> None:
    src = "import os\nfull = os.path.join(base_dir, user_input)\n"
    parsed = parse_python_file(_unit(src))
    findings = run_sast(parsed)
    assert any(f.rule_id == "py.path.traversal" for f in findings)


def test_detects_pathlib_constructor_variable() -> None:
    src = "from pathlib import Path\np = Path(user_input)\n"
    parsed = parse_python_file(_unit(src))
    findings = run_sast(parsed)
    assert any(f.rule_id == "py.path.traversal" for f in findings)


def test_no_false_positive_constant_path() -> None:
    src = 'data = open("/etc/config.yml").read()\n'
    parsed = parse_python_file(_unit(src))
    findings = run_sast(parsed)
    assert not any(f.rule_id == "py.path.open-variable" for f in findings)
