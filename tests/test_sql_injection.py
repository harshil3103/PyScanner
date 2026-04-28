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


def test_detects_fstring_sql_injection() -> None:
    src = 'import sqlite3\ncursor.execute(f"SELECT * FROM users WHERE id={uid}")\n'
    parsed = parse_python_file(_unit(src))
    findings = run_sast(parsed)
    assert any(f.rule_id == "py.sql.injection" for f in findings)


def test_detects_percent_format_sql_injection() -> None:
    src = 'cursor.execute("SELECT * FROM users WHERE name=%s" % name)\n'
    parsed = parse_python_file(_unit(src))
    findings = run_sast(parsed)
    assert any(f.rule_id == "py.sql.injection" for f in findings)


def test_detects_concat_sql_injection() -> None:
    src = 'cursor.execute("SELECT * FROM users WHERE id=" + user_id)\n'
    parsed = parse_python_file(_unit(src))
    findings = run_sast(parsed)
    assert any(f.rule_id == "py.sql.injection" for f in findings)


def test_detects_format_method_sql_injection() -> None:
    src = 'cursor.execute("SELECT * FROM users WHERE id={}".format(uid))\n'
    parsed = parse_python_file(_unit(src))
    findings = run_sast(parsed)
    assert any(f.rule_id == "py.sql.injection" for f in findings)


def test_no_false_positive_parameterized() -> None:
    src = 'cursor.execute("SELECT * FROM users WHERE id=?", (uid,))\n'
    parsed = parse_python_file(_unit(src))
    findings = run_sast(parsed)
    assert not any(f.rule_id == "py.sql.injection" for f in findings)
