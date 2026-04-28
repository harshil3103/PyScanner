from __future__ import annotations

import ast
from pathlib import Path

from pyscanner.models.raw import RawFinding

_WEAK_HASH = frozenset({"md5", "sha1"})


def collect(tree: ast.AST, source: str, file_path: Path) -> list[RawFinding]:
    out: list[RawFinding] = []

    class V(ast.NodeVisitor):
        def visit_Call(self, node: ast.Call) -> None:
            if isinstance(node.func, ast.Attribute) and node.func.attr in _WEAK_HASH:
                if isinstance(node.func.value, ast.Name) and node.func.value.id == "hashlib":
                    lineno = node.lineno
                    out.append(
                        RawFinding(
                            file_path=str(file_path),
                            start_line=lineno,
                            end_line=lineno,
                            rule_id="py.crypto.weak-hash",
                            message=f"hashlib.{node.func.attr} is unsuitable for security-sensitive hashing.",
                            evidence=_snippet(source, lineno),
                            tags=["crypto"],
                            cwe_id="CWE-327",
                        )
                    )
            if isinstance(node.func, ast.Attribute) and node.func.attr == "choice":
                v = node.func.value
                if isinstance(v, ast.Name) and v.id == "random":
                    lineno = node.lineno
                    out.append(
                        RawFinding(
                            file_path=str(file_path),
                            start_line=lineno,
                            end_line=lineno,
                            rule_id="py.crypto.random-not-secrets",
                            message="random module is not cryptographically secure; use secrets module.",
                            evidence=_snippet(source, lineno),
                            tags=["crypto"],
                            cwe_id="CWE-330",
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
