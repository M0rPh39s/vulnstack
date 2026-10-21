"""Terminal (rich) rendering of a scan result.

Renders a concise, readable report: a header, the technology inventory with
evidence, CVE findings grouped by match classification, database freshness and
a final summary. Uncertainty is shown prominently and severities use consistent
labels. Source-provided severity is used as-is; missing severity is shown as
UNKNOWN (never silently treated as LOW).
"""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from vulnstack.cve.search import Classification
from vulnstack.scanner import ScanResult

_SEVERITY_STYLE = {
    "CRITICAL": "bold white on red",
    "HIGH": "bold red",
    "MEDIUM": "yellow",
    "LOW": "green",
    "NONE": "dim",
    "UNKNOWN": "dim cyan",
}

_CLASS_ORDER = [
    (Classification.MATCHED_AFFECTED_RANGE, "Version matches an affected range", "bold red"),
    (Classification.VERSION_UNKNOWN, "Potentially relevant — version unknown (verify)", "yellow"),
    (Classification.PRODUCT_MAPPING_AMBIGUOUS, "Product mapping ambiguous (verify)", "yellow"),
    (Classification.AFFECTED_RANGE_UNAVAILABLE, "No affected-range data (verify)", "yellow"),
    (Classification.SOURCE_DATA_INCOMPLETE, "Source data incomplete (verify)", "yellow"),
    (Classification.VERSION_NOT_MATCHED, "Detected version not in affected range", "dim"),
]


def _severity_text(severity: str | None) -> Text:
    sev = (severity or "UNKNOWN").upper()
    return Text(sev, style=_SEVERITY_STYLE.get(sev, "dim"))


def render(result: ScanResult, console: Console | None = None, *, show_unmatched: bool = False) -> None:
    console = console or Console()

    header = Text()
    header.append("VulnStack", style="bold cyan")
    header.append(f"  v{result.tool_version}\n")
    header.append(f"Target:    {result.target}\n")
    if result.final_url and result.final_url != result.target:
        header.append(f"Final URL: {result.final_url}\n")
    header.append(f"Scanned:   {result.timestamp}\n")
    status_style = "green" if result.status == "ok" else "bold red"
    header.append("Status:    ")
    header.append(result.status.upper(), style=status_style)
    console.print(Panel(header, border_style="cyan"))

    if result.status == "error":
        for err in result.errors:
            console.print(f"[bold red]Error:[/bold red] {err}")
        return

    # --- Technology inventory ---------------------------------------------
    tech_table = Table(title="Detected technologies", title_style="bold", expand=True)
    tech_table.add_column("Technology", style="bold")
    tech_table.add_column("Category")
    tech_table.add_column("Version")
    tech_table.add_column("Confidence")
    tech_table.add_column("Evidence", overflow="fold")
    if result.technologies:
        for t in result.technologies:
            version = t.version or "[dim]unknown[/dim]"
            if t.conflicting_versions:
                version += f" [yellow](conflicts: {', '.join(t.conflicting_versions)})[/yellow]"
            tech_table.add_row(
                t.name,
                t.category,
                version,
                t.confidence,
                "; ".join(t.evidence[:3]),
            )
    else:
        tech_table.add_row("[dim]none detected[/dim]", "", "", "", "")
    console.print(tech_table)

    if result.search_report and result.search_report.unresolved:
        console.print(
            "[dim]No local product mapping for: "
            + ", ".join(result.search_report.unresolved)
            + " (fingerprinted, but not correlated to CVE products)[/dim]"
        )

    # --- Findings grouped by classification -------------------------------
    if result.database and not result.database.initialized:
        console.print()
        for w in result.warnings:
            console.print(f"[yellow]⚠[/yellow]  {w}")
        _render_summary(result, console)
        return

    grouped: dict[Classification, list] = {}
    for f in result.findings:
        grouped.setdefault(f.classification, []).append(f)

    any_shown = False
    for classification, label, style in _CLASS_ORDER:
        if classification == Classification.VERSION_NOT_MATCHED and not show_unmatched:
            continue
        findings = grouped.get(classification, [])
        if not findings:
            continue
        any_shown = True
        table = Table(title=f"[{style}]{label}[/] ({len(findings)})", title_justify="left", expand=True)
        table.add_column("CVE", style="bold", no_wrap=True)
        table.add_column("Severity")
        table.add_column("CVSS")
        table.add_column("Product")
        table.add_column("Detail", overflow="fold")
        for f in findings:
            cvss = f"{f.cvss_score} ({f.cvss_version})" if f.cvss_score is not None else "n/a"
            product = ", ".join(
                sorted({f"{mp.cpe_vendor}:{mp.cpe_product}" for mp in f.matched_products})
            )
            detail = f.matched_products[0].detail if f.matched_products else ""
            table.add_row(f.cve_id, _severity_text(f.severity), cvss, product, detail)
        console.print(table)

    # Only claim "no candidates" when a correlation search actually ran (not
    # under --no-cve and not against an empty database).
    if not any_shown and result.search_report is not None:
        console.print("[green]No candidate CVEs found in the local database for the detected technologies.[/green]")

    for w in result.warnings:
        console.print(f"[yellow]⚠[/yellow]  {w}")

    _render_summary(result, console)


def _render_summary(result: ScanResult, console: Console) -> None:
    summary = result.summary()
    db = result.database
    console.print()
    line = Text("Summary: ", style="bold")
    line.append(f"{summary['technologies_detected']} technologies, ")
    line.append(f"{summary['findings_total']} findings")
    console.print(line)
    counts = summary["findings_by_classification"]
    if counts:
        matched = counts.get("MATCHED_AFFECTED_RANGE", 0)
        parts = [f"Confirmed version matches: [bold red]{matched}[/bold red]"]
        parts += [f"{k}: {v}" for k, v in counts.items() if k != "MATCHED_AFFECTED_RANGE"]
        console.print("  " + "  ·  ".join(parts))
    if db and db.initialized:
        freshness = db.last_successful_sync or "never"
        stale = " [yellow](possibly outdated)[/yellow]" if db.stale else ""
        console.print(f"  Database: {db.total_cves} CVEs · last sync: {freshness}{stale}")
    console.print(
        "[dim]Note: a structured version match indicates a potentially affected component, "
        "not proof of exploitability.[/dim]"
    )
