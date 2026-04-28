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


def test_detects_request_files_save() -> None:
    src = 'f = request.files["doc"]\nf.save("/uploads/" + f.filename)\n'
    parsed = parse_python_file(_unit(src))
    findings = run_sast(parsed)
    assert any(f.rule_id == "py.upload.unrestricted" for f in findings)


def test_detects_filename_attr_save() -> None:
    src = "fname = uploaded.filename\nfile.save(fname)\n"
    parsed = parse_python_file(_unit(src))
    findings = run_sast(parsed)
    assert any(f.rule_id == "py.upload.unrestricted" for f in findings)
