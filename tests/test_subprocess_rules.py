from __future__ import annotations

import hashlib
from pathlib import Path

from pyscanner.ingestion.ast_parse import parse_python_file
from pyscanner.ingestion.reader import CodeUnit
from pyscanner.sast.engine import run_sast


def _unit(path: Path, content: str) -> CodeUnit:
    return CodeUnit(
        path=path,
        content=content,
        content_sha256=hashlib.sha256(content.encode()).hexdigest(),
    )


def test_detects_subprocess_shell_true() -> None:
    src = "import subprocess\nsubprocess.run('ls', shell=True)\n"
    unit = _unit(Path("dummy.py"), src)
    parsed = parse_python_file(unit)
    findings = run_sast(parsed)
    assert any(f.rule_id == "py.subprocess.shell-true" for f in findings)


def test_detects_eval() -> None:
    src = "eval(user_input)\n"
    unit = _unit(Path("dummy.py"), src)
    parsed = parse_python_file(unit)
    findings = run_sast(parsed)
    assert any(f.rule_id == "py.injection.eval-exec" for f in findings)
