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


def test_detects_markup_with_variable() -> None:
    src = "from markupsafe import Markup\nresult = Markup(user_input)\n"
    parsed = parse_python_file(_unit(src))
    findings = run_sast(parsed)
    assert any(f.rule_id == "py.xss.markup" for f in findings)


def test_detects_render_template_string() -> None:
    src = "from flask import render_template_string\nrender_template_string(user_template)\n"
    parsed = parse_python_file(_unit(src))
    findings = run_sast(parsed)
    assert any(f.rule_id == "py.xss.render-template-string" for f in findings)


def test_detects_mark_safe() -> None:
    src = "from django.utils.safestring import mark_safe\nmark_safe(user_html)\n"
    parsed = parse_python_file(_unit(src))
    findings = run_sast(parsed)
    assert any(f.rule_id == "py.xss.mark-safe" for f in findings)


def test_no_false_positive_constant_markup() -> None:
    src = 'from markupsafe import Markup\nresult = Markup("<b>bold</b>")\n'
    parsed = parse_python_file(_unit(src))
    findings = run_sast(parsed)
    assert not any(f.rule_id == "py.xss.markup" for f in findings)
