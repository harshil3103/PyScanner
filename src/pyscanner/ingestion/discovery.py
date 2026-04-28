from __future__ import annotations

import fnmatch
from pathlib import Path

_SKIP_DIR_PARTS = frozenset(
    {
        ".git",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        "dist",
        "build",
    },
)


def _ignored(path: Path, root: Path, extra_ignores: list[str]) -> bool:
    if any(p in _SKIP_DIR_PARTS for p in path.parts):
        return True
    rel = path.relative_to(root).as_posix()
    for pattern in extra_ignores:
        if fnmatch.fnmatch(rel, pattern):
            return True
    return False


def discover_python_files(
    root: Path,
    *,
    extra_ignore_globs: list[str] | None = None,
) -> list[Path]:
    """Return sorted list of *.py files under root respecting ignore globs."""
    root = root.resolve()
    ignores = extra_ignore_globs or []
    out: list[Path] = []
    if root.is_file() and root.suffix == ".py":
        return [root]
    for p in root.rglob("*.py"):
        if p.is_file() and not _ignored(p, root, ignores):
            out.append(p)
    return sorted(out)
