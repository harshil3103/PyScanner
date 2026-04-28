from __future__ import annotations

import ast
from pathlib import Path

from pyscanner.models.raw import RawFinding


def collect(tree: ast.AST, source: str, file_path: Path) -> list[RawFinding]:
    out: list[RawFinding] = []

    class V(ast.NodeVisitor):
        def visit_Call(self, node: ast.Call) -> None:
            if self._is_pickle_loads(node):
                lineno = node.lineno
                out.append(
                    RawFinding(
                        file_path=str(file_path),
                        start_line=lineno,
                        end_line=lineno,
                        rule_id="py.pickle.loads",
                        message="pickle.loads on untrusted data can lead to RCE (CWE-502).",
                        evidence=_snippet(source, lineno),
                        tags=["deserialization"],
                        cwe_id="CWE-502",
                    )
                )
            if self._is_yaml_load(node):
                lineno = node.lineno
                out.append(
                    RawFinding(
                        file_path=str(file_path),
                        start_line=lineno,
                        end_line=lineno,
                        rule_id="py.yaml.unsafe-load",
                        message="yaml.load defaults to unsafe loader; use yaml.safe_load.",
                        evidence=_snippet(source, lineno),
                        tags=["deserialization"],
                        cwe_id="CWE-502",
                    )
                )
            self.generic_visit(node)

        @staticmethod
        def _is_pickle_loads(node: ast.Call) -> bool:
            f = node.func
            if isinstance(f, ast.Attribute) and f.attr in {"loads", "load"}:
                if isinstance(f.value, ast.Name) and f.value.id == "pickle":
                    return True
                if isinstance(f.value, ast.Attribute) and f.value.attr == "pickle":
                    return True
            return False

        @staticmethod
        def _is_yaml_load(node: ast.Call) -> bool:
            f = node.func
            if isinstance(f, ast.Attribute) and f.attr == "load":
                if isinstance(f.value, ast.Name) and f.value.id == "yaml":
                    return True
            return False

    V().visit(tree)
    return out


def _snippet(source: str, line: int, ctx: int = 2) -> str:
    lines = source.splitlines()
    i = line - 1
    lo = max(0, i - ctx)
    hi = min(len(lines), i + ctx + 1)
    return "\n".join(lines[lo:hi])
