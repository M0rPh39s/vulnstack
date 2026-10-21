"""Command-line interface for VulnStack.

Exit-code policy (documented in the README):

* ``0``  — the operation completed successfully. A scan that *finds*
  vulnerabilities still exits 0; findings are a result, not an error.
* ``1``  — a runtime error (invalid/blocked target, network failure, provider
  error, database problem, etc.). A user-friendly message is printed; the
  stack trace is shown only with ``--verbose``.
* ``2``  — invalid command-line usage (argparse).

The CLI never prints stack traces by default and never emits secrets.
"""

from __future__ import annotations

import argparse
import sys
import traceback
from pathlib import Path

from rich.console import Console
from rich.progress import BarColumn, Progress, TextColumn, TimeElapsedColumn
from rich.table import Table

from vulnstack import __version__, config as config_mod, paths
from vulnstack.cve import cve_json, nvd  # noqa: F401  (register providers)
from vulnstack.cve import providers
from vulnstack.cve.database import Database
from vulnstack.cve.updater import Updater
from vulnstack.logging_config import configure_logging
from vulnstack.reports import html_report, json_report, terminal
from vulnstack.scanner import scan as run_scan

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2

_err_console = Console(stderr=True)


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulnstack",
        description="Non-AI website technology fingerprinting and known-vulnerability "
        "correlation for Debian-based Linux.",
        epilog="Run 'vulnstack <command> --help' for command-specific options.",
    )
    parser.add_argument("--version", action="version", version=f"vulnstack {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true", help="enable diagnostic output")
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    # scan
    p_scan = sub.add_parser("scan", help="fingerprint a site and correlate local CVEs")
    p_scan.add_argument("url", help="target URL (http/https)")
    p_scan.add_argument("--no-cve", action="store_true", help="skip CVE correlation")
    p_scan.add_argument("--format", choices=config_mod.VALID_FORMATS, help="output format")
    p_scan.add_argument("--output", help="write the report to a file")
    p_scan.add_argument("--timeout", type=float, help="request timeout in seconds")
    p_scan.add_argument("--show-unmatched", action="store_true",
                        help="also show CVEs whose version did not match")
    p_scan.add_argument("--allow-private", action="store_true",
                        help="allow scanning private/loopback targets (unsafe; off by default)")
    p_scan.add_argument("-v", "--verbose", action="store_true")

    # technologies
    p_tech = sub.add_parser("technologies", help="fingerprint technologies only")
    p_tech.add_argument("url", help="target URL (http/https)")
    p_tech.add_argument("--format", choices=config_mod.VALID_FORMATS, help="output format")
    p_tech.add_argument("--output", help="write the report to a file")
    p_tech.add_argument("--timeout", type=float, help="request timeout in seconds")
    p_tech.add_argument("--allow-private", action="store_true")
    p_tech.add_argument("-v", "--verbose", action="store_true")

    # cve
    p_cve = sub.add_parser("cve", help="search/show CVEs in the local database")
    cve_sub = p_cve.add_subparsers(dest="cve_command", metavar="<subcommand>")
    p_cve_search = cve_sub.add_parser("search", help="free-text search the local database")
    p_cve_search.add_argument("query", help="search term")
    p_cve_search.add_argument("--limit", type=int, default=25, help="max results (default 25)")
    p_cve_search.add_argument("-v", "--verbose", action="store_true")
    p_cve_show = cve_sub.add_parser("show", help="show a single CVE record")
    p_cve_show.add_argument("cve_id", help="e.g. CVE-2021-41773")
    p_cve_show.add_argument("-v", "--verbose", action="store_true")

    # db
    p_db = sub.add_parser("db", help="manage the local vulnerability database")
    db_sub = p_db.add_subparsers(dest="db_command", metavar="<subcommand>")
    p_db_update = db_sub.add_parser("update", help="update the database (incremental by default)")
    p_db_update.add_argument("--full", action="store_true", help="full synchronization/rebuild")
    p_db_update.add_argument("--source", default=None, help="data source (default: nvd)")
    p_db_update.add_argument("--bootstrap-days", type=int, default=30,
                             help="window for the first incremental run (default 30)")
    p_db_update.add_argument("--cvelist-path", default=None,
                             help="local path for the 'cvelist' source")
    p_db_update.add_argument("-v", "--verbose", action="store_true")
    p_db_status = db_sub.add_parser("status", help="show database status")
    p_db_status.add_argument("-v", "--verbose", action="store_true")
    p_db_stats = db_sub.add_parser("stats", help="show database statistics")
    p_db_stats.add_argument("-v", "--verbose", action="store_true")
    p_db_clear = db_sub.add_parser("clear", help="delete all local vulnerability data")
    p_db_clear.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    p_db_clear.add_argument("-v", "--verbose", action="store_true")

    # config
    p_config = sub.add_parser("config", help="configuration")
    cfg_sub = p_config.add_subparsers(dest="config_command", metavar="<subcommand>")
    p_cfg_show = cfg_sub.add_parser("show", help="show effective configuration")
    p_cfg_show.add_argument("-v", "--verbose", action="store_true")

    # cache
    p_cache = sub.add_parser("cache", help="manage the scan cache")
    cache_sub = p_cache.add_subparsers(dest="cache_command", metavar="<subcommand>")
    p_cache_clear = cache_sub.add_parser("clear", help="clear the cache")
    p_cache_clear.add_argument("-v", "--verbose", action="store_true")

    return parser


# ---------------------------------------------------------------------------
# Command implementations
# ---------------------------------------------------------------------------

def _apply_overrides(cfg: config_mod.Config, args: argparse.Namespace) -> None:
    if getattr(args, "timeout", None) is not None:
        cfg.timeout = args.timeout
    if getattr(args, "format", None):
        cfg.default_format = args.format
    if getattr(args, "allow_private", False):
        cfg.allow_private_targets = True
    cfg.validate()


def _write_or_print(content: str, output: str | None, console: Console) -> None:
    if output:
        path = Path(output).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        console.print(f"[green]Report written to[/green] {path}")
    else:
        # Print machine-readable formats raw (no rich markup interpretation).
        print(content)


def cmd_scan(args: argparse.Namespace, cfg: config_mod.Config, console: Console) -> int:
    _apply_overrides(cfg, args)
    result = run_scan(args.url, config=cfg, no_cve=args.no_cve)
    fmt = cfg.default_format
    if fmt == "json":
        _write_or_print(json_report.render(result), args.output, console)
    elif fmt == "html":
        _write_or_print(html_report.render(result), args.output, console)
    else:
        terminal.render(result, console, show_unmatched=getattr(args, "show_unmatched", False))
    return EXIT_OK if result.status == "ok" else EXIT_ERROR


def cmd_technologies(args: argparse.Namespace, cfg: config_mod.Config, console: Console) -> int:
    _apply_overrides(cfg, args)
    result = run_scan(args.url, config=cfg, no_cve=True)
    fmt = cfg.default_format
    if fmt == "json":
        _write_or_print(json_report.render(result), args.output, console)
    elif fmt == "html":
        _write_or_print(html_report.render(result), args.output, console)
    else:
        terminal.render(result, console)
    return EXIT_OK if result.status == "ok" else EXIT_ERROR


def cmd_cve_search(args: argparse.Namespace, cfg: config_mod.Config, console: Console) -> int:
    db = Database(cfg.database_path)
    if not db.is_initialized():
        console.print("[yellow]Local database is not initialized.[/yellow] "
                      "Run 'vulnstack db update' first.")
        return EXIT_ERROR
    rows = db.search_by_text(args.query, limit=args.limit)
    db.close()
    if not rows:
        console.print(f"No local records matched [bold]{args.query}[/bold].")
        return EXIT_OK
    table = Table(title=f"Local CVE search: '{args.query}' ({len(rows)} shown)")
    table.add_column("CVE", style="bold", no_wrap=True)
    table.add_column("Severity")
    table.add_column("CVSS")
    table.add_column("Published")
    table.add_column("Description", overflow="fold")
    for r in rows:
        desc = (r.get("description") or "")[:120]
        table.add_row(
            r["cve_id"],
            r.get("severity") or "UNKNOWN",
            str(r.get("cvss_score") if r.get("cvss_score") is not None else "n/a"),
            (r.get("published") or "")[:10],
            desc,
        )
    console.print(table)
    console.print("[dim]Free-text results are discovery aids, not structured version matches.[/dim]")
    return EXIT_OK


def cmd_cve_show(args: argparse.Namespace, cfg: config_mod.Config, console: Console) -> int:
    db = Database(cfg.database_path)
    if not db.is_initialized():
        console.print("[yellow]Local database is not initialized.[/yellow]")
        return EXIT_ERROR
    record = db.get_vulnerability(args.cve_id)
    db.close()
    if record is None:
        console.print(f"[yellow]{args.cve_id.upper()} not found in the local database.[/yellow]")
        return EXIT_ERROR
    console.print(f"[bold cyan]{record['cve_id']}[/bold cyan]")
    console.print(f"Severity: {record.get('severity') or 'UNKNOWN'} · "
                  f"CVSS {record.get('cvss_score')} ({record.get('cvss_version')}) · "
                  f"Status: {record.get('status')} · Source: {record.get('source')}")
    console.print(f"Published: {record.get('published')} · Modified: {record.get('last_modified')}")
    if record.get("weaknesses"):
        console.print(f"Weaknesses: {', '.join(record['weaknesses'])}")
    console.print()
    console.print(record.get("description") or "")
    console.print()
    if record.get("affected_products"):
        table = Table(title="Affected products")
        table.add_column("Vendor")
        table.add_column("Product")
        table.add_column("Version")
        table.add_column("Ranges", overflow="fold")
        for p in record["affected_products"]:
            ranges = []
            for rng in p.get("ranges", []):
                parts = []
                if rng.get("version_start"):
                    op = ">=" if rng.get("version_start_type") == "including" else ">"
                    parts.append(f"{op}{rng['version_start']}")
                if rng.get("version_end"):
                    op = "<=" if rng.get("version_end_type") == "including" else "<"
                    parts.append(f"{op}{rng['version_end']}")
                ranges.append(" ".join(parts) or "—")
            table.add_row(
                p.get("cpe_vendor") or p.get("vendor") or "—",
                p.get("cpe_product") or p.get("product") or "—",
                p.get("version") or "*",
                "; ".join(ranges) or "—",
            )
        console.print(table)
    if record.get("references"):
        console.print("References:")
        for ref in record["references"][:20]:
            console.print(f"  • {ref['url']}")
    return EXIT_OK


def _progress_callback(progress: Progress, task_id):
    def cb(processed: int, total: int | None) -> None:
        if total is not None:
            progress.update(task_id, total=total, completed=processed)
        else:
            progress.update(task_id, completed=processed)
    return cb


def cmd_db_update(args: argparse.Namespace, cfg: config_mod.Config, console: Console) -> int:
    source = args.source or cfg.default_source
    provider_kwargs: dict = {}
    if source == "nvd":
        provider_kwargs["api_key"] = config_mod.nvd_api_key()
    if source == "cvelist":
        import os
        provider_kwargs["path"] = args.cvelist_path or os.environ.get("VULNSTACK_CVELIST_PATH")
    try:
        provider = providers.get_provider(source, **provider_kwargs)
    except providers.ProviderError as exc:
        console.print(f"[red]{exc}[/red]")
        return EXIT_ERROR

    db = Database(cfg.database_path)
    db.initialize()
    updater = Updater(db, provider)

    console.print("[bold]VulnStack vulnerability database updater[/bold]")
    console.print(f"Source: {source}")
    last = db.last_successful_sync(source)
    console.print(f"Last successful synchronization: {last or 'never'}")
    if config_mod.nvd_api_key() and source == "nvd":
        console.print("[dim]Using NVD_API_KEY from the environment.[/dim]")
    console.print("Fetching records..." if not args.full else "Performing full synchronization...")

    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Processing records", total=None)
        result = updater.run(
            full=args.full,
            bootstrap_days=args.bootstrap_days,
            progress=_progress_callback(progress, task),
        )
    db.close()

    console.print()
    console.print(f"Records inserted: {result.inserted}")
    console.print(f"Records updated:  {result.updated}")
    console.print(f"Errors:           {result.errors}")
    for note in result.notes:
        console.print(f"[yellow]Note:[/yellow] {note}")
    style = "green" if result.status == "success" else "red"
    console.print(f"Synchronization status: [{style}]{result.status}[/{style}] — {result.message}")
    return EXIT_OK if result.status == "success" else EXIT_ERROR


def cmd_db_status(args: argparse.Namespace, cfg: config_mod.Config, console: Console) -> int:
    db = Database(cfg.database_path)
    table = Table(title="VulnStack database status")
    table.add_column("Property", style="bold")
    table.add_column("Value")
    table.add_row("Database location", str(db.path))
    if not db.is_initialized():
        table.add_row("Initialized", "[yellow]no[/yellow]")
        console.print(table)
        console.print("Run 'vulnstack db update --full' (or 'vulnstack db update') to populate it.")
        db.close()
        return EXIT_OK
    table.add_row("Initialized", "[green]yes[/green]")
    table.add_row("Schema version", str(db.schema_version()))
    table.add_row("Total CVE records", str(db.count_vulnerabilities()))
    table.add_row("Affected-product mappings", str(db.count_affected_products()))
    table.add_row("Affected-version ranges", str(db.count_version_ranges()))
    size_mb = db.file_size_bytes() / (1024 * 1024)
    table.add_row("Approximate size", f"{size_mb:.2f} MiB")
    sources = db.all_sources()
    if sources:
        for s in sources:
            table.add_row(f"Source: {s['name']}", "")
            table.add_row("  Last successful sync", s["last_source_modified"] or s["last_sync_time"] or "never")
            table.add_row("  Last status", s["last_status"] or "—")
            if s["last_error"]:
                table.add_row("  Last error", s["last_error"])
    else:
        table.add_row("Configured sources", "none synchronized yet")
    console.print(table)
    db.close()
    return EXIT_OK


def cmd_db_stats(args: argparse.Namespace, cfg: config_mod.Config, console: Console) -> int:
    db = Database(cfg.database_path)
    if not db.is_initialized() or db.count_vulnerabilities() == 0:
        console.print("[yellow]No vulnerability records available.[/yellow] "
                      "Run 'vulnstack db update' first.")
        db.close()
        return EXIT_OK
    sev = db.severity_breakdown()
    years = db.year_breakdown()
    db.close()

    sev_table = Table(title="CVEs by severity")
    sev_table.add_column("Severity", style="bold")
    sev_table.add_column("Count", justify="right")
    for k, v in sev.items():
        sev_table.add_row(k, str(v))
    console.print(sev_table)

    year_table = Table(title="CVEs by year")
    year_table.add_column("Year", style="bold")
    year_table.add_column("Count", justify="right")
    for k, v in list(years.items())[:20]:
        year_table.add_row(k, str(v))
    console.print(year_table)
    return EXIT_OK


def cmd_db_clear(args: argparse.Namespace, cfg: config_mod.Config, console: Console) -> int:
    db = Database(cfg.database_path)
    if not db.is_initialized():
        console.print("Database is not initialized; nothing to clear.")
        db.close()
        return EXIT_OK
    count = db.count_vulnerabilities()
    if not args.yes:
        console.print(
            f"[bold red]This will permanently delete {count} CVE records[/bold red] "
            f"and all sync metadata from:\n  {db.path}"
        )
        console.print("[dim]Configuration and cache files are NOT affected.[/dim]")
        try:
            answer = input("Type 'yes' to confirm: ").strip().lower()
        except EOFError:
            answer = ""
        if answer != "yes":
            console.print("Aborted.")
            db.close()
            return EXIT_OK
    db.clear()
    db.close()
    console.print(f"[green]Cleared {count} records.[/green] "
                  "Cached sync metadata was also removed; the schema was kept.")
    return EXIT_OK


def cmd_config_show(args: argparse.Namespace, cfg: config_mod.Config, console: Console) -> int:
    table = Table(title="VulnStack effective configuration")
    table.add_column("Setting", style="bold")
    table.add_column("Value")
    for key, value in cfg.to_public_dict().items():
        table.add_row(key, str(value))
    table.add_row("config_file", str(config_mod.config_file_location()))
    # Report secret presence without revealing it.
    table.add_row("NVD_API_KEY", "set (redacted)" if config_mod.nvd_api_key() else "not set")
    console.print(table)
    console.print("[dim]Precedence: defaults < config file < environment variables < CLI options.[/dim]")
    return EXIT_OK


def cmd_cache_clear(args: argparse.Namespace, cfg: config_mod.Config, console: Console) -> int:
    from vulnstack.cache import Cache

    cache = Cache(cfg.cache_dir, ttl_seconds=cfg.cache_ttl_seconds)
    removed = cache.clear()
    console.print(f"[green]Cleared {removed} cache entries[/green] from {cache.directory}")
    return EXIT_OK


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

_DISPATCH = {
    "scan": cmd_scan,
    "technologies": cmd_technologies,
}


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    verbose = getattr(args, "verbose", False)
    configure_logging(verbose)
    console = Console()

    if args.command is None:
        parser.print_help()
        return EXIT_USAGE

    try:
        cfg = config_mod.load_config()
    except ValueError as exc:
        _err_console.print(f"[red]Configuration error:[/red] {exc}")
        return EXIT_ERROR

    try:
        if args.command == "scan":
            return cmd_scan(args, cfg, console)
        if args.command == "technologies":
            return cmd_technologies(args, cfg, console)
        if args.command == "cve":
            if args.cve_command == "search":
                return cmd_cve_search(args, cfg, console)
            if args.cve_command == "show":
                return cmd_cve_show(args, cfg, console)
            parser.parse_args([args.command, "--help"])
            return EXIT_USAGE
        if args.command == "db":
            if args.db_command == "update":
                return cmd_db_update(args, cfg, console)
            if args.db_command == "status":
                return cmd_db_status(args, cfg, console)
            if args.db_command == "stats":
                return cmd_db_stats(args, cfg, console)
            if args.db_command == "clear":
                return cmd_db_clear(args, cfg, console)
            parser.parse_args([args.command, "--help"])
            return EXIT_USAGE
        if args.command == "config":
            if args.config_command == "show":
                return cmd_config_show(args, cfg, console)
            parser.parse_args([args.command, "--help"])
            return EXIT_USAGE
        if args.command == "cache":
            if args.cache_command == "clear":
                return cmd_cache_clear(args, cfg, console)
            parser.parse_args([args.command, "--help"])
            return EXIT_USAGE
    except KeyboardInterrupt:
        _err_console.print("\n[yellow]Interrupted.[/yellow]")
        return EXIT_ERROR
    except Exception as exc:  # pragma: no cover - top-level safety net
        if verbose:
            _err_console.print(traceback.format_exc())
        else:
            _err_console.print(f"[red]Error:[/red] {exc}")
        return EXIT_ERROR

    parser.print_help()
    return EXIT_USAGE


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
