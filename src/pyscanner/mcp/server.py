from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from pyscanner.config.settings import ScanConfig
from pyscanner.core.pipeline import run_scan

server = Server("pyscanner")


@server.list_tools()
async def _list_tools() -> list[Tool]:
    return [
        Tool(
            name="scan_path",
            description="Run PyScanner on a filesystem path (file or directory).",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "offline": {"type": "boolean", "default": True},
                },
                "required": ["path"],
            },
        ),
        Tool(
            name="scan_snippet",
            description="Scan a Python code snippet for vulnerabilities.",
            inputSchema={
                "type": "object",
                "properties": {
                    "code": {"type": "string"},
                    "offline": {"type": "boolean", "default": True},
                },
                "required": ["code"],
            },
        ),
    ]


@server.call_tool()
async def _call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name == "scan_path":
        p = Path(arguments["path"]).expanduser().resolve()
        offline = bool(arguments.get("offline", True))
        cfg = ScanConfig(offline=offline, enable_slm=False, enable_llm=False)
        report = run_scan(p, cfg)
        return [TextContent(type="text", text=report.model_dump_json(indent=2))]
    if name == "scan_snippet":
        code = str(arguments["code"])
        offline = bool(arguments.get("offline", True))
        cfg = ScanConfig(offline=offline, enable_slm=False, enable_llm=False)
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as tmp:
            tmp.write(code)
            tmp_path = Path(tmp.name)
        try:
            report = run_scan(tmp_path, cfg)
        finally:
            tmp_path.unlink(missing_ok=True)
        return [TextContent(type="text", text=report.model_dump_json(indent=2))]
    raise ValueError(f"unknown tool {name}")


def run_mcp() -> None:
    async def _main() -> None:
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())

    asyncio.run(_main())
