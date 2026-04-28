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


def test_detects_debug_true() -> None:
    src = "DEBUG = True\n"
    parsed = parse_python_file(_unit(src))
    findings = run_sast(parsed)
    assert any(f.rule_id == "py.config.debug-enabled" for f in findings)


def test_detects_cors_wildcard() -> None:
    src = "CORS_ALLOW_ALL_ORIGINS = True\n"
    parsed = parse_python_file(_unit(src))
    findings = run_sast(parsed)
    assert any(f.rule_id == "py.config.cors-wildcard" for f in findings)


def test_detects_allowed_hosts_wildcard() -> None:
    src = "ALLOWED_HOSTS = ['*']\n"
    parsed = parse_python_file(_unit(src))
    findings = run_sast(parsed)
    assert any(f.rule_id == "py.config.allowed-hosts-wildcard" for f in findings)


def test_detects_flask_debug_run() -> None:
    src = "app.run(debug=True)\n"
    parsed = parse_python_file(_unit(src))
    findings = run_sast(parsed)
    assert any(f.rule_id == "py.config.debug-enabled" for f in findings)


def test_detects_weak_secret_key() -> None:
    src = "SECRET_KEY = 'changeme'\n"
    parsed = parse_python_file(_unit(src))
    findings = run_sast(parsed)
    assert any(f.rule_id == "py.config.weak-secret-key" for f in findings)
