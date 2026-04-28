from __future__ import annotations

import ast
from pathlib import Path

from pyscanner.models.raw import RawFinding

_SAVE_ATTRS = frozenset({"save"})
_UNSAFE_COPY_FUNCS = frozenset({"move", "copy", "copy2", "copyfile"})


def collect(tree: ast.AST, source: str, file_path: Path) -> list[RawFinding]:
    out: list[RawFinding] = []
    upload_filenames: set[str] = set()

    class GatherUploads(ast.NodeVisitor):
        def visit_Assign(self, node: ast.Assign) -> None:
            if isinstance(node.value, ast.Attribute) and node.value.attr == "filename":
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        upload_filenames.add(t.id)
            self.generic_visit(node)

    class V(ast.NodeVisitor):
        def visit_Call(self, node: ast.Call) -> None:
            if isinstance(node.func, ast.Attribute) and node.func.attr in _SAVE_ATTRS:
                if node.args and _involves_upload(node.args[0], upload_filenames):
                    out.append(RawFinding(
                        file_path=str(file_path), start_line=node.lineno, end_line=node.lineno,
                        rule_id="py.upload.unrestricted",
                        message="File saved with uploaded filename without extension validation.",
                        evidence=_snippet(source, node.lineno), tags=["file_upload"], cwe_id="CWE-434",
                    ))

            if isinstance(node.func, ast.Attribute) and node.func.attr in _UNSAFE_COPY_FUNCS:
                if isinstance(node.func.value, ast.Name) and node.func.value.id == "shutil":
                    if any(_involves_upload(a, upload_filenames) for a in node.args):
                        out.append(RawFinding(
                            file_path=str(file_path), start_line=node.lineno, end_line=node.lineno,
                            rule_id="py.upload.no-validation",
                            message=f"shutil.{node.func.attr}() with uploaded file without validation.",
                            evidence=_snippet(source, node.lineno), tags=["file_upload"], cwe_id="CWE-434",
                        ))

            if isinstance(node.func, ast.Attribute) and node.func.attr == "save":
                val = node.func.value
                if isinstance(val, ast.Subscript):
                    if isinstance(val.value, ast.Attribute) and val.value.attr == "files":
                        out.append(RawFinding(
                            file_path=str(file_path), start_line=node.lineno, end_line=node.lineno,
                            rule_id="py.upload.unrestricted",
                            message="Uploaded file saved directly from request.files without secure_filename().",
                            evidence=_snippet(source, node.lineno), tags=["file_upload"], cwe_id="CWE-434",
                        ))
            self.generic_visit(node)

    GatherUploads().visit(tree)
    V().visit(tree)
    return out


def _involves_upload(node: ast.AST, names: set[str]) -> bool:
    if isinstance(node, ast.Name) and node.id in names:
        return True
    if isinstance(node, ast.Attribute) and node.attr == "filename":
        return True
    if isinstance(node, ast.Call):
        return any(_involves_upload(a, names) for a in node.args)
    if isinstance(node, ast.BinOp):
        return _involves_upload(node.left, names) or _involves_upload(node.right, names)
    return False


def _snippet(source: str, line: int, ctx: int = 2) -> str:
    lines = source.splitlines()
    i = line - 1
    lo = max(0, i - ctx)
    hi = min(len(lines), i + ctx + 1)
    return "\n".join(lines[lo:hi])
