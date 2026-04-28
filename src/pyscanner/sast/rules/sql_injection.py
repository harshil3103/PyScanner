from __future__ import annotations

import ast
from pathlib import Path

from pyscanner.models.raw import RawFinding

_SQL_EXEC_ATTRS = frozenset({"execute", "executemany", "executescript"})


def collect(tree: ast.AST, source: str, file_path: Path) -> list[RawFinding]:
    out: list[RawFinding] = []

    class V(ast.NodeVisitor):
        def visit_Call(self, node: ast.Call) -> None:
            # cursor.execute(...) / cursor.executemany(...) with dangerous args
            if isinstance(node.func, ast.Attribute) and node.func.attr in _SQL_EXEC_ATTRS:
                if node.args:
                    first_arg = node.args[0]
                    if _is_format_string(first_arg):
                        lineno = node.lineno
                        out.append(
                            RawFinding(
                                file_path=str(file_path),
                                start_line=lineno,
                                end_line=lineno,
                                rule_id="py.sql.injection",
                                message=(
                                    f"SQL query built with string formatting in {node.func.attr}(). "
                                    "Use parameterized queries instead."
                                ),
                                evidence=_snippet(source, lineno),
                                tags=["sql_injection"],
                                cwe_id="CWE-89",
                            )
                        )
                    elif _is_percent_format(first_arg):
                        lineno = node.lineno
                        out.append(
                            RawFinding(
                                file_path=str(file_path),
                                start_line=lineno,
                                end_line=lineno,
                                rule_id="py.sql.injection",
                                message=(
                                    f"SQL query built with %-formatting in {node.func.attr}(). "
                                    "Use parameterized queries instead."
                                ),
                                evidence=_snippet(source, lineno),
                                tags=["sql_injection"],
                                cwe_id="CWE-89",
                            )
                        )
                    elif _is_string_concat_with_var(first_arg):
                        lineno = node.lineno
                        out.append(
                            RawFinding(
                                file_path=str(file_path),
                                start_line=lineno,
                                end_line=lineno,
                                rule_id="py.sql.injection",
                                message=(
                                    f"SQL query built with string concatenation in {node.func.attr}(). "
                                    "Use parameterized queries instead."
                                ),
                                evidence=_snippet(source, lineno),
                                tags=["sql_injection"],
                                cwe_id="CWE-89",
                            )
                        )
            self.generic_visit(node)

    V().visit(tree)
    return out


def _is_format_string(node: ast.AST) -> bool:
    """Detect f-strings and .format() calls."""
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            return True
    return False


def _is_percent_format(node: ast.AST) -> bool:
    """Detect 'SELECT ... %s' % (var,) style formatting."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        if isinstance(node.left, ast.Constant) and isinstance(node.left.value, str):
            return True
    return False


def _is_string_concat_with_var(node: ast.AST) -> bool:
    """Detect 'SELECT ... ' + variable style concatenation."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        has_str = isinstance(node.left, ast.Constant) and isinstance(node.left.value, str)
        has_var = isinstance(node.right, ast.Name)
        if has_str and has_var:
            return True
        has_str_r = isinstance(node.right, ast.Constant) and isinstance(node.right.value, str)
        has_var_l = isinstance(node.left, ast.Name)
        if has_str_r and has_var_l:
            return True
        # Recursive: ("SELECT " + x) + " FROM ..."
        if isinstance(node.left, ast.BinOp):
            return _is_string_concat_with_var(node.left)
        if isinstance(node.right, ast.BinOp):
            return _is_string_concat_with_var(node.right)
    return False


def _snippet(source: str, line: int, ctx: int = 2) -> str:
    lines = source.splitlines()
    i = line - 1
    lo = max(0, i - ctx)
    hi = min(len(lines), i + ctx + 1)
    return "\n".join(lines[lo:hi])
