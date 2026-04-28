from __future__ import annotations

import hashlib
from pathlib import Path

from pydantic import BaseModel, Field


class CodeUnit(BaseModel):
    path: Path
    content: str
    content_sha256: str
    parse_ok: bool = True
    encoding: str = "utf-8"
    diagnostics: list[str] = Field(default_factory=list)


def read_file_unit(path: Path, *, max_bytes: int = 2_000_000) -> CodeUnit:
    path = path.resolve()
    raw = path.read_bytes()
    if len(raw) > max_bytes:
        return CodeUnit(
            path=path,
            content="",
            content_sha256=hashlib.sha256(raw).hexdigest(),
            parse_ok=False,
            diagnostics=[f"file exceeds max_bytes={max_bytes}"],
        )
    text = raw.decode("utf-8", errors="replace")
    digest = hashlib.sha256(raw).hexdigest()
    return CodeUnit(path=path, content=text, content_sha256=digest)
