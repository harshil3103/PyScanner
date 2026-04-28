from __future__ import annotations

import ast
from pathlib import Path

from pyscanner.models.raw import RawFinding


def collect(tree: ast.AST, source: str, file_path: Path) -> list[RawFinding]:
    out: list[RawFinding] = []

    class V(ast.NodeVisitor):
        def visit_Call(self, node: ast.Call) -> None:
            if self._is_subprocess_run_or_popen(node) and self._shell_true(node):
                lineno = node.lineno
                out.append(
                    RawFinding(
                        file_path=str(file_path),
                        start_line=lineno,
                        end_line=lineno,
                        rule_id="py.subprocess.shell-true",
                        message="subprocess with shell=True enables shell metacharacter injection.",
                        evidence=_snippet(source, lineno),
                        tags=["command_injection"],
                        cwe_id="CWE-78",
                    )
                )
            if isinstance(node.func, ast.Attribute) and node.func.attr == "system":
                if isinstance(node.func.value, ast.Name) and node.func.value.id == "os":
                    lineno = node.lineno
                    out.append(
                        RawFinding(
                            file_path=str(file_path),
                            start_line=lineno,
                            end_line=lineno,
                            rule_id="py.os.system",
                            message="os.system() passes a string to the shell; prefer subprocess list argv.",
                            evidence=_snippet(source, lineno),
                            tags=["command_injection"],
                            cwe_id="CWE-78",
                        )
                    )
            self.generic_visit(node)

        @staticmethod
        def _is_subprocess_run_or_popen(node: ast.Call) -> bool:
            f = node.func
            if isinstance(f, ast.Attribute) and f.attr in {"run", "Popen", "call", "check_call", "check_output"}:
                v = f.value
                if isinstance(v, ast.Name) and v.id == "subprocess":
                    return True
                if isinstance(v, ast.Attribute) and v.attr == "subprocess":
                    return True
            return False

        @staticmethod
        def _shell_true(node: ast.Call) -> bool:
            for kw in node.keywords:
                if kw.arg == "shell":
                    return isinstance(kw.value, ast.Constant) and kw.value.value is True
            return False

    V().visit(tree)
    return out


def _snippet(source: str, line: int, ctx: int = 2) -> str:
    lines = source.splitlines()
    i = line - 1
    lo = max(0, i - ctx)
    hi = min(len(lines), i + ctx + 1)
    return "\n".join(lines[lo:hi])
