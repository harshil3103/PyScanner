from __future__ import annotations

import ast
import re
from pathlib import Path

from pyscanner.models.raw import RawFinding

_GENERIC_SECRET = re.compile(
    r"(api_key|apikey|secret_key|private_key)\s*=\s*['\"]([^'\"]{12,})['\"]",
    re.I,
)
_SECRET_REGEXES = (
    (re.compile(r"(AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID)\s*=\s*['\"]([^'\"]+)['\"]"), "py.secrets.aws-cred"),
    (_GENERIC_SECRET, "py.secrets.generic-assignment"),
    (re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"), "py.secrets.private-key"),
)


def collect(tree: ast.AST, source: str, file_path: Path) -> list[RawFinding]:
    out: list[RawFinding] = []
    lines = source.splitlines()
    for i, line in enumerate(lines, start=1):
        for pat, rule_id in _SECRET_REGEXES:
            if pat.search(line):
                out.append(
                    RawFinding(
                        file_path=str(file_path),
                        start_line=i,
                        end_line=i,
                        rule_id=rule_id,
                        message="Possible hardcoded secret or credential material.",
                        evidence=line.strip()[:200],
                        tags=["secrets"],
                        cwe_id="CWE-798",
                    )
                )
                break

    class V(ast.NodeVisitor):
        def visit_Constant(self, node: ast.Constant) -> None:
            if isinstance(node.value, str) and len(node.value) > 24 and _looks_like_token(node.value):
                lineno = getattr(node, "lineno", 1)
                out.append(
                    RawFinding(
                        file_path=str(file_path),
                        start_line=lineno,
                        end_line=lineno,
                        rule_id="py.secrets.long-string",
                        message="Long high-entropy string literal; verify not a secret.",
                        evidence="[redacted-length-string]",
                        tags=["secrets"],
                        cwe_id="CWE-798",
                    )
                )
            self.generic_visit(node)

    V().visit(tree)
    return out


def _looks_like_token(s: str) -> bool:
    if not s.isalnum():
        return False
    # crude entropy proxy
    return len(set(s)) > len(s) * 0.35
