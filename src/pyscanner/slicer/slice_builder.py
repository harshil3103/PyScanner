from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass, field

from pyscanner.models.raw import RawFinding
from pyscanner.slicer.budgets import estimate_tokens, trim_to_budget
from pyscanner.slicer.scope_graph import enclosing_function_lines


@dataclass
class ProgramSlice:
    slice_id: str
    file_path: str
    line_spans: list[tuple[int, int]]
    snippet_text: str
    slice_reason: str
    estimated_tokens: int
    imports: list[str] = field(default_factory=list)


def _top_imports(tree: ast.AST, max_lines: int = 40) -> list[str]:
    body = getattr(tree, "body", None)
    if not isinstance(body, list):
        return []
    out: list[str] = []
    for node in body[:80]:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            try:
                out.append(ast.unparse(node))
            except AttributeError:
                pass
        if len(out) >= max_lines:
            break
    return out


def build_slice_for_finding(
    *,
    tree: ast.AST,
    source: str,
    finding: RawFinding,
    token_budget: int = 4000,
) -> ProgramSlice:
    """Build a minimal code slice around a raw finding."""
    lines = source.splitlines()
    n = len(lines)
    anchor = finding.start_line
    span = enclosing_function_lines(tree, anchor)
    if span:
        lo, hi = span.start - 1, span.end
        lo = max(0, lo)
        hi = min(n, hi)
        snippet = "\n".join(lines[lo:hi])
        reason = "enclosing_function_or_class"
        line_spans = [(lo + 1, hi)]
    else:
        ctx = 6
        lo = max(0, anchor - 1 - ctx)
        hi = min(n, anchor + ctx)
        snippet = "\n".join(lines[lo:hi])
        reason = "window_fallback"
        line_spans = [(lo + 1, hi)]

    imports = _top_imports(tree)
    header = "\n".join(imports[:30])
    body = f"# --- slice: {finding.rule_id} ---\n{snippet}"
    composed = f"{header}\n\n{body}" if header else body
    composed = trim_to_budget(composed, token_budget)
    est = estimate_tokens(composed)
    digest = hashlib.sha256(composed.encode()).hexdigest()[:24]
    sid = f"sha256:{digest}"
    return ProgramSlice(
        slice_id=sid,
        file_path=finding.file_path,
        line_spans=line_spans,
        snippet_text=composed,
        slice_reason=reason,
        estimated_tokens=est,
        imports=imports,
    )
