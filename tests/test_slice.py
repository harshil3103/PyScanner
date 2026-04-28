from __future__ import annotations

import hashlib
from pathlib import Path

from pyscanner.ingestion.ast_parse import parse_python_file
from pyscanner.ingestion.reader import CodeUnit
from pyscanner.models.raw import RawFinding
from pyscanner.slicer.slice_builder import build_slice_for_finding


def test_slice_contains_function_context() -> None:
    src = '''def foo():\n    x = 1\n    eval("1")\n'''
    unit = CodeUnit(
        path=Path("m.py"),
        content=src,
        content_sha256=hashlib.sha256(src.encode()).hexdigest(),
    )
    parsed = parse_python_file(unit)
    rf = RawFinding(
        file_path="m.py",
        start_line=3,
        end_line=3,
        rule_id="py.injection.eval-exec",
        message="eval",
    )
    sl = build_slice_for_finding(tree=parsed.stdlib_ast, source=parsed.source, finding=rf)
    assert "eval" in sl.snippet_text
    assert "def foo" in sl.snippet_text
