#!/usr/bin/env python3
"""
main.py -- ZeroDay AI Entry Point

Usage:
    python main.py                        # Interactive menu
    python main.py scan <target>          # Scan a target
    python main.py scan --model codellama <target>
    python main.py fetch-cves             # Download CVE data
    python main.py doctor                 # Check environment readiness
    python main.py dashboard              # Launch web dashboard
    python main.py history                # Show scan history
"""
from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

# Fix Windows terminal encoding for rich output
if sys.platform == "win32":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore
        sys.stderr.reconfigure(encoding="utf-8")  # type: ignore
    except Exception:
        pass

import click
from rich.console import Console
from rich.table import Table

# Ensure project root is on path
sys.path.insert(0, str(Path(__file__).parent))

console = Console()


@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx):
    """
    \b
     _____                ____              ___    ____
    |__  / ___ _ __ ___  |  _ \\  __ _ _   _|_ _| / ___|
      / / / _ \\ '__/ _ \\ | | | |/ _` | | | || |  \\___ \\
     / /_|  __/ | | (_) || |_| | (_| | |_| || |   ___) |
    /____|\\____|_|  \\___/ |____/ \\__,_|\\__, |___| |____/
                                        |___/
    Autonomous AI Vulnerability Research Agent
    """
    if ctx.invoked_subcommand is None:
        # No subcommand — launch interactive menu
        asyncio.run(_launch_interactive())


@cli.command()
@click.argument("target")
@click.option(
    "--model", "-m",
    default="",
    help="Ollama model to use (e.g. qwen2.5-coder:7b, codellama, llama3)",
)
@click.option(
    "--output", "-o",
    default="reports",
    show_default=True,
    help="Directory to save reports",
)
@click.option(
    "--no-interactive",
    is_flag=True,
    default=False,
    help="Run fully automated without interactive prompts",
)
@click.option(
    "--no-static",
    is_flag=True,
    default=False,
    help="Skip static analysis phase",
)
@click.option(
    "--no-llm",
    is_flag=True,
    default=False,
    help="Skip LLM reasoning phase",
)
@click.option(
    "--no-fuzz",
    is_flag=True,
    default=False,
    help="Skip web fuzzing phase",
)
@click.option(
    "--no-network",
    is_flag=True,
    default=False,
    help="Skip network scanning phase",
)
@click.option(
    "--zero-day",
    is_flag=True,
    default=False,
    help="Enable zero-day hypothesis mode (deeper LLM analysis)",
)
def scan(
    target: str,
    model: str,
    output: str,
    no_interactive: bool,
    no_static: bool,
    no_llm: bool,
    no_fuzz: bool,
    no_network: bool,
    zero_day: bool,
):
    """Scan a TARGET for security vulnerabilities.

    TARGET can be:
    \b
      - A file or directory path  (source code scan)
      - A URL like http://app.com (web scan)
      - An IP address             (network scan)
    """
    from cli.interactive import InteractiveCLI

    cli_app = InteractiveCLI(model=model, output_dir=output)

    asyncio.run(
        cli_app.start_scan(
            target,
            interactive=not no_interactive,
            run_static=not no_static,
            run_llm=not no_llm,
            run_fuzzer=not no_fuzz,
            run_network=not no_network,
            zero_day_mode=zero_day,
        )
    )


@cli.command("fetch-cves")
@click.option(
    "--days", "-d",
    default=365,
    show_default=True,
    help="How many days back to fetch CVEs",
)
@click.option(
    "--force", "-f",
    is_flag=True,
    default=False,
    help="Force refresh even if cache is fresh",
)
def fetch_cves(days: int, force: bool):
    """Download latest CVE data from NVD into the local knowledge base."""
    from core.config import get_config
    from knowledge.cve_loader import fetch_cves as _fetch

    cfg = get_config()
    _fetch(
        api_key=cfg.nvd_api_key,
        days_back=days,
        cache_path=Path(cfg.knowledge.cve_cache_path),
        force_refresh=force,
    )


@cli.command("import-learning")
@click.argument("file_path")
@click.option("--clean", is_flag=True, help="Use AI to clean/distill the exploit logic")
def import_learning(file_path: str, clean: bool):
    """Import external exploit datasets (CSV/JSON/JSONL) into AI memory."""
    from knowledge.importer import ExploitImporter
    
    importer = ExploitImporter()
    importer.run(file_path, use_ai_cleaning=clean)


@cli.command()
def dashboard():
    """Launch the ZeroDay AI web dashboard (http://localhost:8000)."""
    import subprocess
    from core.config import get_config

    cfg = get_config()
    dashboard_url = f"http://{cfg.api_server.host}:{cfg.api_server.port}"

    console.print("[cyan]Starting ZeroDay AI Dashboard server...[/cyan]")
    console.print(
        "\n[bold green]✓ Dashboard and API running at[/bold green] "
        f"[bold]{dashboard_url}[/bold]"
    )
    console.print("[dim]Press Ctrl+C to stop[/dim]\n")

    # Start FastAPI backend which now embeds the dashboard UI natively
    try:
        subprocess.run(
            [sys.executable, "-m", "uvicorn", "api.server:app",
             "--host", cfg.api_server.host, "--port", str(cfg.api_server.port)],
            cwd=Path(__file__).parent,
            check=True
        )
    except KeyboardInterrupt:
        console.print("\n[yellow]Dashboard shutting down...[/yellow]")


@cli.command("delete-scan")
@click.argument("scan_id")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation")
def delete_scan(scan_id: str, yes: bool):
    """Delete a scan and all associated findings/tasks."""
    import asyncio
    from core.database import get_session, init_db
    from core.models import Scan
    from sqlalchemy import delete

    async def _delete():
        await init_db()
        async with get_session() as session:
            # Find the full ID if a prefix was given
            from sqlalchemy import select
            res = await session.execute(select(Scan).where(Scan.id.startswith(scan_id)))
            scan = res.scalars().first()
            if not scan:
                console.print(f"[red]Scan {scan_id} not found.[/red]")
                return

            if not yes:
                if not click.confirm(f"Are you sure you want to delete scan {scan.id[:8]} ({scan.target})?"):
                    return

            await session.delete(scan)
            await session.commit()
            console.print(f"[green]✓ Deleted scan {scan.id[:8]} and all associated data.[/green]")

    asyncio.run(_delete())


@cli.command("cleanup-scans")
def cleanup_scans():
    """Mark scans stuck in 'running' state for >24h as 'failed'."""
    import asyncio
    from datetime import datetime, timedelta
    from core.database import get_session, init_db
    from core.models import Scan, ScanStatus
    from sqlalchemy import select, update

    async def _cleanup():
        await init_db()
        stale_threshold = datetime.utcnow() - timedelta(hours=24)
        async with get_session() as session:
            stmt = (
                update(Scan)
                .where(Scan.status == ScanStatus.RUNNING)
                .where(Scan.created_at < stale_threshold)
                .values(status=ScanStatus.FAILED, notes="Auto-marked as failed (stale)")
            )
            result = await session.execute(stmt)
            await session.commit()
            console.print(f"[green]✓ Cleaned up {result.rowcount} stale scans.[/green]")

    asyncio.run(_cleanup())


@cli.command()
def doctor():
    """Run environment checks and show whether the tool is ready to scan well."""
    from core.config import get_config
    from core.diagnostics import build_health_report

    report = build_health_report(get_config())
    status_style = {
        "ok": "green",
        "warn": "yellow",
        "fail": "red",
    }

    summary = Table(title="ZeroDay AI Health Check", header_style="bold cyan")
    summary.add_column("Area")
    summary.add_column("Status")
    summary.add_column("Details")
    summary.add_row(
        "Overall",
        f"[{status_style[report['summary_status']]}]{report['summary_status'].upper()}[/{status_style[report['summary_status']]}]",
        f"Python {report['python']['version']} | Model {report['config']['model']}",
    )
    summary.add_row(
        "Database",
        f"[{status_style[report['database']['status']]}]{report['database']['status'].upper()}[/{status_style[report['database']['status']]}]",
        report["database"]["path"],
    )
    summary.add_row(
        "Ollama",
        f"[{status_style[report['ollama']['status']]}]{report['ollama']['status'].upper()}[/{status_style[report['ollama']['status']]}]",
        f"reachable={report['ollama']['reachable']} model_present={report['ollama']['configured_model_present']}",
    )
    console.print(summary)

    counts = Table(title="Status Counts", header_style="bold cyan")
    counts.add_column("Type")
    counts.add_column("Count", justify="right")
    for key in ("ok", "warn", "fail"):
        counts.add_row(key.upper(), str(report["counts"][key]), style=status_style[key])
    console.print(counts)

    for section_name in ("core_modules", "optional_modules", "external_tools"):
        section = Table(title=section_name.replace("_", " ").title(), header_style="bold cyan")
        section.add_column("Name")
        section.add_column("Status")
        section.add_column("Path / Notes")
        for item in report[section_name]:
            status = item["status"]
            section.add_row(
                item["name"],
                f"[{status_style[status]}]{status.upper()}[/{status_style[status]}]",
                item.get("path", "") or ("installed" if item.get("present") else "missing"),
            )
        console.print(section)

    if report["ollama"]["available_models"]:
        console.print(
            f"[dim]Available Ollama models: {', '.join(report['ollama']['available_models'])}[/dim]"
        )


@cli.command()
@click.option("--limit", "-n", default=10, show_default=True)
def history(limit: int):
    """Show recent scan history."""

    async def _show():
        from core.database import get_session, init_db
        from sqlalchemy import select
        from sqlalchemy.orm import selectinload
        from core.models import Scan

        await init_db()
        async with get_session() as session:
            result = await session.execute(
                select(Scan).options(selectinload(Scan.findings)).order_by(Scan.created_at.desc()).limit(limit)
            )
            scans = result.scalars().all()

        if not scans:
            console.print("[dim]No scans found.[/dim]")
            return

        table = Table(title="Scan History", header_style="bold cyan")
        table.add_column("ID", style="dim", width=10)
        table.add_column("Target", max_width=45)
        table.add_column("Status")
        table.add_column("Findings", justify="right")
        table.add_column("Date")

        for s in scans:
            sty = "green" if s.status.value == "completed" else "yellow"
            table.add_row(
                s.id[:8],
                s.target,
                f"[{sty}]{s.status.value}[/{sty}]",
                str(s.finding_count),
                str(s.created_at)[:16] if s.created_at else "—",
            )
        console.print(table)

    asyncio.run(_show())


# ─── Helpers ──────────────────────────────────────────────────────────

async def _launch_interactive():
    from cli.interactive import InteractiveCLI
    app = InteractiveCLI()
    await app.start()


if __name__ == "__main__":
    cli()
