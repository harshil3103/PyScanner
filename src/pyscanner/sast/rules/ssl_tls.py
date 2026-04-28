from __future__ import annotations

import ast
from pathlib import Path

from pyscanner.models.raw import RawFinding


def collect(tree: ast.AST, source: str, file_path: Path) -> list[RawFinding]:
    out: list[RawFinding] = []

    class V(ast.NodeVisitor):
        def visit_Call(self, node: ast.Call) -> None:
            for kw in node.keywords:
                if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                    lineno = node.lineno
                    out.append(
                        RawFinding(
                            file_path=str(file_path),
                            start_line=lineno,
                            end_line=lineno,
                            rule_id="py.ssl.verify-false",
                            message="TLS certificate verification disabled (verify=False).",
                            evidence=_snippet(source, lineno),
                            tags=["misconfiguration"],
                            cwe_id="CWE-295",
                        )
                    )
            self.generic_visit(node)

    V().visit(tree)
    return out


def _snippet(source: str, line: int, ctx: int = 2) -> str:
    lines = source.splitlines()
    i = line - 1
    lo = max(0, i - ctx)
    hi = min(len(lines), i + ctx + 1)
    return "\n".join(lines[lo:hi])
