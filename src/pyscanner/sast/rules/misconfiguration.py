from __future__ import annotations

import ast
import re
from pathlib import Path

from pyscanner.models.raw import RawFinding

_DEBUG_PATTERN = re.compile(r"^\s*DEBUG\s*=\s*True\s*$", re.MULTILINE)
_CORS_PATTERN = re.compile(r"^\s*CORS_ALLOW_ALL_ORIGINS\s*=\s*True\s*$", re.MULTILINE)
_HOSTS_PATTERN = re.compile(r"ALLOWED_HOSTS\s*=\s*\[\s*['\"]?\*['\"]?\s*\]", re.MULTILINE)
_WEAK_SECRET = re.compile(
    r"SECRET_KEY\s*=\s*['\"](.{0,16})['\"]",
    re.MULTILINE,
)


def collect(tree: ast.AST, source: str, file_path: Path) -> list[RawFinding]:
    out: list[RawFinding] = []
    lines = source.splitlines()

    # Line-based regex checks for configuration patterns
    for i, line in enumerate(lines, start=1):
        if _DEBUG_PATTERN.match(line):
            out.append(RawFinding(
                file_path=str(file_path), start_line=i, end_line=i,
                rule_id="py.config.debug-enabled",
                message="DEBUG = True in production code exposes detailed error pages and stack traces.",
                evidence=line.strip(), tags=["misconfiguration"], cwe_id="CWE-16",
            ))
        if _CORS_PATTERN.match(line):
            out.append(RawFinding(
                file_path=str(file_path), start_line=i, end_line=i,
                rule_id="py.config.cors-wildcard",
                message="CORS_ALLOW_ALL_ORIGINS = True allows any origin, risking CSRF and data leaks.",
                evidence=line.strip(), tags=["misconfiguration"], cwe_id="CWE-16",
            ))

    # Multi-line regex checks
    for m in _HOSTS_PATTERN.finditer(source):
        lineno = source[:m.start()].count("\n") + 1
        out.append(RawFinding(
            file_path=str(file_path), start_line=lineno, end_line=lineno,
            rule_id="py.config.allowed-hosts-wildcard",
            message="ALLOWED_HOSTS = ['*'] disables host header validation (Django).",
            evidence=m.group().strip(), tags=["misconfiguration"], cwe_id="CWE-16",
        ))

    for m in _WEAK_SECRET.finditer(source):
        secret_val = m.group(1)
        if len(secret_val) < 16 or secret_val in ("changeme", "secret", "please-change-me", "your-secret-key"):
            lineno = source[:m.start()].count("\n") + 1
            out.append(RawFinding(
                file_path=str(file_path), start_line=lineno, end_line=lineno,
                rule_id="py.config.weak-secret-key",
                message="SECRET_KEY is too short or a known placeholder. Use a strong random key.",
                evidence="SECRET_KEY = [REDACTED]", tags=["misconfiguration"], cwe_id="CWE-16",
            ))

    # AST check: app.run(debug=True) for Flask
    class V(ast.NodeVisitor):
        def visit_Call(self, node: ast.Call) -> None:
            if isinstance(node.func, ast.Attribute) and node.func.attr == "run":
                for kw in node.keywords:
                    if kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        out.append(RawFinding(
                            file_path=str(file_path), start_line=node.lineno, end_line=node.lineno,
                            rule_id="py.config.debug-enabled",
                            message="app.run(debug=True) exposes the Werkzeug debugger which allows RCE.",
                            evidence=_snippet(source, node.lineno), tags=["misconfiguration"], cwe_id="CWE-16",
                        ))
            self.generic_visit(node)

    V().visit(tree)
    return out


def _snippet(source: str, line: int, ctx: int = 2) -> str:
    lines = source.splitlines()
    i = line - 1
    lo = max(0, i - ctx)
    hi = min(len(lines), i + ctx + 1)
    return "\n".join(lines[lo:hi])
