from __future__ import annotations

import ast
from collections.abc import Callable
from pathlib import Path

from pyscanner.ingestion.ast_parse import ParsedUnit
from pyscanner.models.raw import RawFinding
from pyscanner.sast.rules import (
    crypto,
    deserialization,
    file_upload,
    injection,
    misconfiguration,
    path_traversal,
    secrets,
    sql_injection,
    ssl_tls,
    subprocess_rules,
    supply_chain,
    xss,
)

RuleFn = Callable[[ast.AST, str, Path], list[RawFinding]]

_DEFAULT_RULES: tuple[RuleFn, ...] = (
    injection.collect,
    subprocess_rules.collect,
    deserialization.collect,
    secrets.collect,
    ssl_tls.collect,
    crypto.collect,
    sql_injection.collect,
    path_traversal.collect,
    xss.collect,
    file_upload.collect,
    misconfiguration.collect,
    supply_chain.collect,
)


def run_sast(
    unit: ParsedUnit,
    *,
    rule_packs: list[str] | None = None,
) -> list[RawFinding]:
    """Run registered rules on a parsed unit."""
    _ = rule_packs  # pack selection reserved for future
    findings: list[RawFinding] = []
    for rule in _DEFAULT_RULES:
        findings.extend(rule(unit.stdlib_ast, unit.source, unit.path))
    findings.sort(key=lambda f: (f.file_path, f.start_line, f.rule_id))
    return findings

