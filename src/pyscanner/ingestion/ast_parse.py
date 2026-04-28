from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

import libcst as cst

from pyscanner.ingestion.reader import CodeUnit


@dataclass
class ParsedUnit:
    path: Path
    source: str
    stdlib_ast: ast.AST
    libcst_module: cst.Module | None
    parse_ok: bool
    diagnostics: list[str]


def parse_python_file(unit: CodeUnit) -> ParsedUnit:
    diagnostics: list[str] = []
    try:
        tree = ast.parse(unit.content, filename=str(unit.path))
    except SyntaxError as e:
        diagnostics.append(f"ast parse error: {e}")
        tree = ast.Module(body=[], type_ignores=[])
    mod: cst.Module | None = None
    try:
        mod = cst.parse_module(unit.content)
    except cst.ParserSyntaxError as e:
        diagnostics.append(f"libcst parse error: {e}")
    return ParsedUnit(
        path=unit.path,
        source=unit.content,
        stdlib_ast=tree,
        libcst_module=mod,
        parse_ok=not diagnostics,
        diagnostics=diagnostics,
    )
