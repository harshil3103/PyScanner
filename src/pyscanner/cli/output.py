from __future__ import annotations

from rich.console import Console
from rich.panel import Panel

from pyscanner.models.findings import ScanReport

_SEV_COLORS = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "blue",
}

_SCORE_COLORS = {
    "Excellent": "bold green",
    "Good": "bold blue",
    "Risky": "bold yellow",
    "Critical": "bold red",
}

def print_console_report(report: ScanReport) -> None:
    console = Console()
    console.print("\n")

    # --- Header Panel ---
    score_color = _SCORE_COLORS.get(report.score_label, "white")
    
    # Calculate severity counts
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in report.findings:
        counts[f.severity_label] += 1
        
    summary_text = (
        f"[bold]Scan ID:[/bold] {report.scan_id}\n"
        f"[bold]Files Scanned:[/bold] {report.metrics.files_scanned}\n"
        f"[bold]Total Findings:[/bold] {len(report.findings)}\n"
        f"[bold]Duration:[/bold] {report.duration_ms} ms\n\n"
        f"[{score_color}][bold]Security Score:[/bold] "
        f"{report.security_score}/100 ({report.score_label})[/{score_color}]\n\n"
        f"[bold red]Critical:[/bold red] {counts['critical']} | "
        f"[red]High:[/red] {counts['high']} | "
        f"[yellow]Medium:[/yellow] {counts['medium']} | "
        f"[blue]Low:[/blue] {counts['low']}"
    )
    
    console.print(Panel(summary_text, title="[bold cyan]PyScanner AI Security Review[/bold cyan]", border_style="cyan"))

    if not report.findings:
        console.print(Panel("[bold green]No vulnerabilities found! Great job.[/bold green]", border_style="green"))
        return

    # --- Findings Details ---
    console.print("\n[bold]Detailed Findings:[/bold]")
    
    for i, f in enumerate(report.findings, start=1):
        color = _SEV_COLORS.get(f.severity_label, "white")
        
        # Title bar
        title = f"[{color}][{f.severity_label.upper()}][/] {f.vulnerability_type} "
        title += f"(Confidence: {int(f.confidence_score * 100)}%)"
        
        detail_lines = []
        detail_lines.append(f"[bold]Location:[/bold] {f.file_path}:{f.line_number}")
        
        if f.owasp_category:
            detail_lines.append(f"[bold]OWASP:[/bold] {f.owasp_category}")
        if f.cwe_id:
            detail_lines.append(f"[bold]CWE:[/bold] {f.cwe_id}")
            
        detail_lines.append("")
        
        # Explanation (handling multiline/impact if present)
        expl_parts = f.explanation.split("Impact: ")
        detail_lines.append(f"[bold]Issue:[/bold] {expl_parts[0].strip()}")
        if len(expl_parts) > 1:
            detail_lines.append(f"[bold]Impact:[/bold] {expl_parts[1].strip()}")
            
        if f.evidence:
            detail_lines.append("")
            detail_lines.append("[dim]--- Snippet ---[/dim]")
            snippet = f.evidence.replace("\n", "\n  ")
            detail_lines.append(f"[italic]{snippet}[/italic]")
            detail_lines.append("[dim]-----------------[/dim]")
            
        if f.remediation_suggestion:
            detail_lines.append("")
            detail_lines.append(f"[bold green]Fix Recommendation:[/bold green] {f.remediation_suggestion}")
            
        if f.remediation_code:
            detail_lines.append("")
            detail_lines.append("[bold cyan]Suggested Code:[/bold cyan]")
            code_lines = f.remediation_code.split("\n")
            for line in code_lines:
                detail_lines.append(f"  {line}")

        finding_panel = Panel("\n".join(detail_lines), title=title, border_style=color, title_align="left")
        console.print(finding_panel)
        console.print("")
        
    console.print(
        f"[dim]Run with --format html|markdown|csv for exportable reports. "
        f"Scanned {report.metrics.files_scanned} files in {report.duration_ms}ms.[/dim]\n"
    )
