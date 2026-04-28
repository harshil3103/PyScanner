from __future__ import annotations

import ast
from pathlib import Path

from pyscanner.models.raw import RawFinding

_UNSAFE_FLASK_FUNCS = frozenset({"Markup", "render_template_string"})
_UNSAFE_DJANGO_FUNCS = frozenset({"mark_safe"})


def collect(tree: ast.AST, source: str, file_path: Path) -> list[RawFinding]:
    out: list[RawFinding] = []

    class V(ast.NodeVisitor):
        def visit_Call(self, node: ast.Call) -> None:
            func_name = _get_func_name(node)

            # Flask: Markup(variable) or Markup(f"...")
            if func_name == "Markup":
                if node.args and _has_variable_or_format(node.args[0]):
                    lineno = node.lineno
                    out.append(
                        RawFinding(
                            file_path=str(file_path),
                            start_line=lineno,
                            end_line=lineno,
                            rule_id="py.xss.markup",
                            message=(
                                "Markup() with dynamic content bypasses Jinja2 auto-escaping "
                                "and may introduce XSS."
                            ),
                            evidence=_snippet(source, lineno),
                            tags=["xss"],
                            cwe_id="CWE-79",
                        )
                    )

            # Flask: render_template_string(user_input)
            if func_name == "render_template_string":
                if node.args and _has_variable_or_format(node.args[0]):
                    lineno = node.lineno
                    out.append(
                        RawFinding(
                            file_path=str(file_path),
                            start_line=lineno,
                            end_line=lineno,
                            rule_id="py.xss.render-template-string",
                            message=(
                                "render_template_string() with dynamic input can lead to "
                                "server-side template injection (SSTI) and XSS."
                            ),
                            evidence=_snippet(source, lineno),
                            tags=["xss", "ssti"],
                            cwe_id="CWE-79",
                        )
                    )

            # Django: mark_safe(variable)
            if func_name == "mark_safe":
                if node.args and _has_variable_or_format(node.args[0]):
                    lineno = node.lineno
                    out.append(
                        RawFinding(
                            file_path=str(file_path),
                            start_line=lineno,
                            end_line=lineno,
                            rule_id="py.xss.mark-safe",
                            message=(
                                "mark_safe() with dynamic content bypasses Django auto-escaping "
                                "and may introduce XSS."
                            ),
                            evidence=_snippet(source, lineno),
                            tags=["xss"],
                            cwe_id="CWE-79",
                        )
                    )

            # Response with text/html content-type and variable body
            if func_name in ("Response", "make_response"):
                if node.args and _has_variable_or_format(node.args[0]):
                    has_html_content_type = False
                    for kw in node.keywords:
                        if kw.arg == "content_type" or kw.arg == "mimetype":
                            if isinstance(kw.value, ast.Constant) and "html" in str(kw.value.value).lower():
                                has_html_content_type = True
                    if has_html_content_type:
                        lineno = node.lineno
                        out.append(
                            RawFinding(
                                file_path=str(file_path),
                                start_line=lineno,
                                end_line=lineno,
                                rule_id="py.xss.response-html",
                                message=(
                                    "Returning dynamic content as text/html without escaping "
                                    "may introduce XSS."
                                ),
                                evidence=_snippet(source, lineno),
                                tags=["xss"],
                                cwe_id="CWE-79",
                            )
                        )

            self.generic_visit(node)

    V().visit(tree)
    return out


def _get_func_name(node: ast.Call) -> str:
    """Extract the terminal function name from a call node."""
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return ""


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


def _snippet(source: str, line: int, ctx: int = 2) -> str:
    lines = source.splitlines()
    i = line - 1
    lo = max(0, i - ctx)
    hi = min(len(lines), i + ctx + 1)
    return "\n".join(lines[lo:hi])
