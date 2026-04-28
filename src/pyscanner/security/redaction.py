from __future__ import annotations

import re

_PATTERNS = (
    re.compile(r"(api[_-]?key|token|secret|password)\s*[:=]\s*['\"]?[\w\-]{8,}", re.I),
    re.compile(r"sk-[a-zA-Z0-9]{20,}"),
    re.compile(r"Bearer\s+[a-zA-Z0-9_\-\.]+"),
)


def redact_secrets(text: str) -> str:
    """Best-effort redaction for logs and persisted snippets."""
    out = text
    for pat in _PATTERNS:
        out = pat.sub(lambda m: m.group(0)[:4] + "…[REDACTED]", out)
    return out
