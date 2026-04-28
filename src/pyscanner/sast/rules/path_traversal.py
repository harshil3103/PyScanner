from __future__ import annotations

import ast
from pathlib import Path

from pyscanner.models.raw import RawFinding

_FILE_OPEN_NAMES = frozenset({"open", "file"})
_PATH_JOIN_ATTRS = frozenset({"join"})
_PATH_CONSTRUCTORS = frozenset({"Path", "PurePath", "PurePosixPath", "PureWindowsPath"})


def collect(tree: ast.AST, source: str, file_path: Path) -> list[RawFinding]:
    out: list[RawFinding] = []

    class V(ast.NodeVisitor):
        def visit_Call(self, node: ast.Call) -> None:
            # open(variable) — potential path traversal if variable is user-controlled
            if isinstance(node.func, ast.Name) and node.func.id in _FILE_OPEN_NAMES:
                if node.args and _has_variable_or_format(node.args[0]):
                    lineno = node.lineno
                    out.append(
                        RawFinding(
                            file_path=str(file_path),
                            start_line=lineno,
                            end_line=lineno,
                            rule_id="py.path.open-variable",
                            message=(
                                "open() called with a variable path. If user-controlled, "
                                "this may allow directory traversal (e.g. ../../etc/passwd)."
                            ),
                            evidence=_snippet(source, lineno),
                            tags=["path_traversal"],
                            cwe_id="CWE-22",
                        )
                    )

            # os.path.join(...) with variable components
            if isinstance(node.func, ast.Attribute) and node.func.attr in _PATH_JOIN_ATTRS:
                if isinstance(node.func.value, ast.Attribute):
                    # os.path.join(...)
                    if (
                        node.func.value.attr == "path"
                        and isinstance(node.func.value.value, ast.Name)
                        and node.func.value.value.id == "os"
                    ):
                        if any(_has_variable_or_format(a) for a in node.args):
                            lineno = node.lineno
                            out.append(
                                RawFinding(
                                    file_path=str(file_path),
                                    start_line=lineno,
                                    end_line=lineno,
                                    rule_id="py.path.traversal",
                                    message=(
                                        "os.path.join() with variable input. Validate paths "
                                        "to prevent directory traversal attacks."
                                    ),
                                    evidence=_snippet(source, lineno),
                                    tags=["path_traversal"],
                                    cwe_id="CWE-22",
                                )
                            )

            # Path(variable) / PurePath(variable) constructors
            if isinstance(node.func, ast.Name) and node.func.id in _PATH_CONSTRUCTORS:
                if node.args and _has_variable_or_format(node.args[0]):
                    lineno = node.lineno
                    out.append(
                        RawFinding(
                            file_path=str(file_path),
                            start_line=lineno,
                            end_line=lineno,
                            rule_id="py.path.traversal",
                            message=(
                                f"{node.func.id}() constructed with variable input. "
                                "Validate to prevent directory traversal."
                            ),
                            evidence=_snippet(source, lineno),
                            tags=["path_traversal"],
                            cwe_id="CWE-22",
                        )
                    )

            # Path(...) / operator with variables  
            self.generic_visit(node)

        def visit_BinOp(self, node: ast.BinOp) -> None:
            """Detect Path(...) / variable — Python pathlib division operator."""
            if isinstance(node.op, ast.Div):
                if _involves_path_call(node.left) and isinstance(node.right, ast.Name):
                    lineno = node.lineno
                    out.append(
                        RawFinding(
                            file_path=str(file_path),
                            start_line=lineno,
                            end_line=lineno,
                            rule_id="py.path.traversal",
                            message=(
                                "Path division operator (/) with variable input. "
                                "Validate to prevent directory traversal."
                            ),
                            evidence=_snippet(source, lineno),
                            tags=["path_traversal"],
                            cwe_id="CWE-22",
                        )
                    )
            self.generic_visit(node)

    V().visit(tree)
    return out


def _has_variable_or_format(node: ast.AST) -> bool:
    """Check if an argument contains a variable reference or f-string."""
    if isinstance(node, ast.Name):
        return True
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp):
        return _has_variable_or_format(node.left) or _has_variable_or_format(node.right)
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            return True
    return False


def _involves_path_call(node: ast.AST) -> bool:
    """Check if node is a Path() constructor or involves one."""
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        return node.func.id in _PATH_CONSTRUCTORS
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        return _involves_path_call(node.left)
    return False


def _snippet(source: str, line: int, ctx: int = 2) -> str:
    lines = source.splitlines()
    i = line - 1
    lo = max(0, i - ctx)
    hi = min(len(lines), i + ctx + 1)
    return "\n".join(lines[lo:hi])
