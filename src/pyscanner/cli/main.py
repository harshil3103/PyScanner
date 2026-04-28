from __future__ import annotations

from pathlib import Path
from typing import Annotated, Literal

import typer

from pyscanner.config.settings import ScanConfig, get_settings
from pyscanner.core.pipeline import run_scan
from pyscanner.persistence.sqlite_store import SqliteStore
from pyscanner.reporting.csv_report import write_csv_report
from pyscanner.reporting.html.render import write_html_report
from pyscanner.reporting.json_report import write_json_report
from pyscanner.reporting.markdown_report import write_markdown_report
from pyscanner.reporting.sarif import write_sarif_report
from pyscanner.security.secrets_manager import SecretStore

app = typer.Typer(help="PyScanner AI Security Review Assistant")


@app.command()
def scan(
    target: Annotated[Path, typer.Argument(exists=True, readable=True, help="File or directory")],
    format: Annotated[
        Literal["text", "json", "sarif", "html", "markdown", "csv"],
        typer.Option("--format", "-f", help="Output format"),
    ] = "text",
    offline: Annotated[bool, typer.Option(help="Disable cloud LLM and remote calls")] = True,
    no_slm: Annotated[bool, typer.Option(help="Disable local SLM triage")] = False,
    llm: Annotated[bool, typer.Option(help="Enable cloud LLM for uncertain findings")] = False,
    provider: Annotated[str | None, typer.Option(help="openai|anthropic|gemini")] = None,
    db: Annotated[Path | None, typer.Option(help="SQLite path for storing scans")] = None,
    fix: Annotated[bool, typer.Option(help="Suggest fixes (LLM only; experimental)")] = False,
) -> None:
    """Scan a Python file or directory."""
    if fix and not llm:
        typer.echo("--fix requires --llm", err=True)
        raise typer.Exit(code=2)
    effective_offline = offline
    if llm and effective_offline:
        typer.secho("Note: --llm enables network access; turning off offline mode.", fg="yellow")
        effective_offline = False
    llm_provider = provider if provider in ("openai", "anthropic", "gemini") else None
    if llm and not llm_provider:
        typer.secho("Warning: --llm without --provider defaults to None; set PYSCANNER secrets.", fg="yellow")
    cfg = ScanConfig(
        offline=effective_offline,
        enable_slm=not no_slm,
        enable_llm=llm,
        llm_provider=llm_provider,
    )
    settings = get_settings()
    store = SqliteStore(db) if db else None
    sec_store = SecretStore(
        key_file=settings.config_dir / "fernet.key",
        secrets_file=settings.config_dir / "secrets.json",
    )
    report = run_scan(target.resolve(), cfg, store=store, secret_store=sec_store if llm else None)
    out_path = Path("pyscanner-report")
    if format == "json":
        p = out_path.with_suffix(".json")
        write_json_report(report, p)
        typer.echo(str(p))
    elif format == "sarif":
        p = out_path.with_suffix(".sarif")
        write_sarif_report(report, p)
        typer.echo(str(p))
    elif format == "html":
        p = out_path.with_suffix(".html")
        write_html_report(report, p)
        typer.echo(str(p))
    elif format == "markdown":
        p = out_path.with_suffix(".md")
        write_markdown_report(report, p)
        typer.echo(str(p))
    elif format == "csv":
        p = out_path.with_suffix(".csv")
        write_csv_report(report, p)
        typer.echo(str(p))
    else:
        from pyscanner.cli.output import print_console_report

        print_console_report(report)


@app.command()
def history(
    limit: Annotated[int, typer.Option(help="Number of recent scans to show")] = 10,
    db: Annotated[Path | None, typer.Option(help="SQLite path")] = None,
) -> None:
    """View previous scan scores and trends."""
    if not db:
        typer.secho("Error: --db is required to view history.", fg="red")
        raise typer.Exit(code=1)
        
    store = SqliteStore(db)
    reports = store.get_history(limit)
    if not reports:
        typer.echo("No scan history found.")
        return
        
    from rich.console import Console
    from rich.table import Table
    console = Console()
    table = Table(title="PyScanner History")
    table.add_column("Scan ID")
    table.add_column("Date")
    table.add_column("Files")
    table.add_column("Issues")
    table.add_column("Score", justify="right")
    
    for r in reports:
        score_colors = {"Excellent": "green", "Good": "blue", "Risky": "yellow", "Critical": "red"}
        score_color = score_colors.get(r.score_label, "white")
        table.add_row(
            r.scan_id[:8],
            r.started_at.strftime("%Y-%m-%d %H:%M"),
            str(r.metrics.files_scanned),
            str(len(r.findings)),
            f"[{score_color}]{r.security_score} ({r.score_label})[/{score_color}]",
        )
    console.print(table)


@app.command()
def feedback(
    scan_id: Annotated[str, typer.Argument(help="Scan ID")],
    file_path: Annotated[str, typer.Argument(help="File path of the finding")],
    line: Annotated[int, typer.Argument(help="Line number of the finding")],
    note: Annotated[str, typer.Option(help="Optional note explaining why this is a false positive")] = "",
    db: Annotated[Path | None, typer.Option(help="SQLite path")] = None,
) -> None:
    """Mark a specific finding as a false positive."""
    if not db:
        typer.secho("Error: --db is required to store feedback.", fg="red")
        raise typer.Exit(code=1)
        
    store = SqliteStore(db)
    success = store.mark_feedback(scan_id, file_path, line, is_fp=True, note=note)
    
    if success:
        typer.secho(f"Successfully marked {file_path}:{line} as a false positive.", fg="green")
    else:
        typer.secho("Finding not found. Please check scan ID, file path, and line number.", fg="red")


@app.command()
def mcp() -> None:
    """Run MCP stdio server (requires: pip install 'pyscanner[mcp]')."""
    try:
        from pyscanner.mcp.server import run_mcp

        run_mcp()
    except ImportError as e:
        typer.echo(f"MCP extras not installed: {e}", err=True)
        raise typer.Exit(code=1) from e
