from __future__ import annotations

import ast
from dataclasses import dataclass


@dataclass
class Span:
    start: int
    end: int


def enclosing_function_lines(tree: ast.AST, line: int) -> Span | None:
    """Return 1-based line span of smallest function/class containing line."""
    best: Span | None = None

    class V(ast.NodeVisitor):
        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            nonlocal best
            if hasattr(node, "end_lineno") and node.end_lineno:
                if node.lineno <= line <= node.end_lineno:
                    cand = Span(node.lineno, node.end_lineno)
                    if best is None or (cand.end - cand.start) < (best.end - best.start):
                        best = cand
            self.generic_visit(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            nonlocal best
            if hasattr(node, "end_lineno") and node.end_lineno:
                if node.lineno <= line <= node.end_lineno:
                    cand = Span(node.lineno, node.end_lineno)
                    if best is None or (cand.end - cand.start) < (best.end - best.start):
                        best = cand
            self.generic_visit(node)

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            nonlocal best
            if hasattr(node, "end_lineno") and node.end_lineno:
                if node.lineno <= line <= node.end_lineno:
                    cand = Span(node.lineno, node.end_lineno)
                    if best is None or (cand.end - cand.start) < (best.end - best.start):
                        best = cand
            self.generic_visit(node)

    V().visit(tree)
    return best
