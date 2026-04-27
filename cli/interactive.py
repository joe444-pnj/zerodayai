"""
cli/interactive.py — Interactive CLI Session

Provides the full interactive experience for ZeroDay AI:
- Target configuration wizard
- Per-phase interactive checkpoints
- Live finding display
- Scan history browser
"""
from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
from typing import List, Optional

from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

from cli.banner import print_banner
from core.config import Config, get_config
from core.database import get_session, init_db
from core.models import Finding, Scan, Severity

console = Console()

_SEV_COLORS = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "green",
    "info": "cyan",
}


class InteractiveCLI:
    """Full interactive CLI session manager."""

    def __init__(self, model: str = "", output_dir: str = "reports"):
        self.config = get_config()
        self._ollama_available = False
        if model:
            self.config.ollama.model = model
        if output_dir:
            self.config.reporting.output_dir = output_dir

    # ─── Main Entry ───────────────────────────────────────────────────

    async def start(self) -> None:
        """Launch the interactive welcome menu."""
        os.system("cls" if os.name == "nt" else "clear")
        print_banner(self.config.ollama.model)

        # Check Ollama availability
        await self._check_ollama()
        
        # Cleanup stale scans
        await self._cleanup_stale_scans()

        while True:
            choice = self._main_menu()
            if choice == "1":
                await self._wizard_new_scan()
            elif choice == "2":
                await self._view_scan_history()
            elif choice == "3":
                self._show_config()
            elif choice == "4":
                self._show_help()
            elif choice == "q":
                console.print("[dim]Goodbye.[/dim]")
                break

    async def start_scan(
        self,
        target: str,
        interactive: bool = True,
        run_static: bool = True,
        run_llm: bool = True,
        run_fuzzer: bool = True,
        run_network: bool = True,
        zero_day_mode: bool = False,
    ) -> None:
        """Start scan directly from CLI args (non-wizard mode)."""
        print_banner(self.config.ollama.model)
        await self._check_ollama()
        await self._run_scan(
            target, interactive=interactive,
            run_static=run_static,
            run_llm=run_llm, run_fuzzer=run_fuzzer,
            run_network=run_network, zero_day_mode=zero_day_mode,
        )

    # ─── Main Menu ────────────────────────────────────────────────────

    def _main_menu(self) -> str:
        console.print()
        console.print(Panel(
            "[bold][1][/bold] 🔍 New Scan\n"
            "[bold][2][/bold] 📋 Scan History\n"
            "[bold][3][/bold] ⚙️  Configuration\n"
            "[bold][4][/bold] ❓ Help\n"
            "[bold][q][/bold] Quit",
            title="[bold cyan]ZeroDay AI — Main Menu[/bold cyan]",
            border_style="cyan",
            width=50,
        ))
        return Prompt.ask(
            "\n[bold cyan]Select[/bold cyan]",
            choices=["1", "2", "3", "4", "q"],
            default="1",
        )

    # ─── Scan Wizard ──────────────────────────────────────────────────

    async def _wizard_new_scan(self) -> None:
        console.print()
        console.rule("[bold cyan]🔍 New Scan Setup[/bold cyan]")

        # Target input
        console.print(
            "\n[dim]Target can be:[/dim]\n"
            "  • A directory or file path (source code scan)\n"
            "  • A URL like http://example.com (web scan)\n"
            "  • An IP address like 192.168.1.1 (network scan)\n"
        )
        target = Prompt.ask("[bold]Enter target[/bold]").strip()
        if not target:
            return

        # Scan label
        label = Prompt.ask("[dim]Scan label (optional)[/dim]", default="")

        # Model selection
        console.print(f"\n[dim]Current model:[/dim] [cyan]{self.config.ollama.model}[/cyan]")
        change_model = Confirm.ask("Change Ollama model?", default=False)
        if change_model:
            model = Prompt.ask(
                "Model name",
                default=self.config.ollama.model,
            )
            self.config.ollama.model = model

        # Agent selection
        console.print("\n[bold]Select agents to run:[/bold]")
        run_static  = Confirm.ask("  Static analysis (Bandit, Semgrep, secrets scan)", default=True)
        
        llm_prompt = "  LLM code reasoning (Ollama)"
        if not self._ollama_available:
            llm_prompt += " [yellow](Ollama server not found)[/yellow]"
        run_llm = Confirm.ask(llm_prompt, default=self._ollama_available)
        run_fuzzer  = Confirm.ask("  Web fuzzer (HTTP)", default=True)
        run_network = Confirm.ask("  Network scanner", default=True)

        # Zero-day hypothesis mode
        zd_mode = Confirm.ask("\nEnable zero-day hypothesis mode (deeper, slower)?", default=False)

        # Confirm and start
        console.print()
        console.print(Panel(
            f"[bold]Target:[/bold]  {target}\n"
            f"[bold]Model:[/bold]   {self.config.ollama.model}\n"
            f"[bold]Agents:[/bold]  "
            f"{'Static ' if run_static else ''}"
            f"{'LLM ' if run_llm else ''}"
            f"{'Fuzzer ' if run_fuzzer else ''}"
            f"{'Network' if run_network else ''}\n"
            f"[bold]Zero-Day:[/bold] {'Yes' if zd_mode else 'No'}",
            title="[bold green]Scan Configuration[/bold green]",
            border_style="green",
        ))

        if not Confirm.ask("\n[bold]Start scan?[/bold]", default=True):
            return

        await self._run_scan(
            target, label=label,
            run_static=run_static, run_llm=run_llm,
            run_fuzzer=run_fuzzer, run_network=run_network,
            zero_day_mode=zd_mode,
        )

    # ─── Scan Execution ───────────────────────────────────────────────

    async def _run_scan(
        self,
        target: str,
        label: str = "",
        interactive: bool = True,
        run_static: bool = True,
        run_llm: bool = True,
        run_fuzzer: bool = True,
        run_network: bool = True,
        zero_day_mode: bool = False,
    ) -> None:
        from core.orchestrator import Orchestrator

        orch = Orchestrator(
            self.config,
            interactive=interactive,
            run_static=run_static,
            run_llm=run_llm,
            run_fuzzer=run_fuzzer,
            run_network=run_network,
            deep_analysis=zero_day_mode,
        )

        try:
            scan = await orch.run(target, label=label)
            console.print(
                f"\n[bold green]✓ Scan complete![/bold green] "
                f"ID: {scan.id[:8]} | "
                f"Findings: {len(orch.all_findings)}"
            )

            # Offer to open report
            report_dir = Path(self.config.reporting.output_dir) / scan.id[:8]
            if report_dir.exists():
                console.print(f"[dim]Reports saved to: {report_dir}[/dim]")
                if Confirm.ask("Open Markdown report?", default=False):
                    md = report_dir / "report.md"
                    if md.exists():
                        if sys.platform == "win32":
                            os.startfile(str(md))
                        else:
                            os.system(f"less {md}")

        except KeyboardInterrupt:
            console.print("\n[yellow]Scan interrupted.[/yellow]")

    # ─── Scan History ─────────────────────────────────────────────────

    async def _view_scan_history(self) -> None:
        console.rule("[bold cyan]📋 Scan History[/bold cyan]")
        await init_db()

        async with get_session() as session:
            from sqlalchemy import select
            from sqlalchemy.orm import selectinload
            result = await session.execute(
                select(Scan).options(selectinload(Scan.findings)).order_by(Scan.created_at.desc()).limit(20)
            )
            scans: List[Scan] = result.scalars().all()

        if not scans:
            console.print("[dim]No scans found.[/dim]")
            return

        table = Table(
            title="Recent Scans",
            show_header=True,
            header_style="bold cyan",
        )
        table.add_column("ID", style="dim", width=10)
        table.add_column("Target", max_width=40)
        table.add_column("Status")
        table.add_column("Findings", justify="right")
        table.add_column("Date")

        for s in scans:
            status_style = "green" if s.status.value == "completed" else "yellow"
            table.add_row(
                s.id[:8],
                s.target[:40],
                f"[{status_style}]{s.status.value}[/{status_style}]",
                str(s.finding_count),
                str(s.created_at)[:16] if s.created_at else "—",
            )

        console.print(table)

        # Drill into a scan
        action = Prompt.ask(
            "\nEnter scan ID to [bold]view[/bold], or 'del <id>' to [bold red]delete[/bold red] (Enter to go back)",
            default="",
        )
        if not action:
            return

        is_delete = action.startswith("del ")
        scan_id = action[4:].strip() if is_delete else action.strip()

        async with get_session() as session:
            from sqlalchemy import select
            from sqlalchemy.orm import selectinload
            result = await session.execute(
                select(Scan).options(selectinload(Scan.findings)).where(Scan.id.startswith(scan_id))
            )
            scan = result.scalars().first()
            
            if not scan:
                console.print(f"[red]Scan {scan_id} not found.[/red]")
                return

            if is_delete:
                if Confirm.ask(f"Really delete scan {scan.id[:8]} ({scan.target})?", default=False):
                    await session.delete(scan)
                    await session.commit()
                    console.print("[green]✓ Deleted.[/green]")
            else:
                self._display_findings(scan.findings)

    async def _cleanup_stale_scans(self) -> None:
        """Mark scans stuck in 'running' for >24h as 'failed'."""
        from datetime import datetime, timedelta
        from core.models import ScanStatus
        from sqlalchemy import update
        
        stale_threshold = datetime.utcnow() - timedelta(hours=24)
        async with get_session() as session:
            stmt = (
                update(Scan)
                .where(Scan.status == ScanStatus.RUNNING)
                .where(Scan.created_at < stale_threshold)
                .values(status=ScanStatus.FAILED, notes="Auto-marked as failed (stale)")
            )
            await session.execute(stmt)
            await session.commit()

    def _display_findings(self, findings: List[Finding]) -> None:
        """Pretty-print findings table."""
        if not findings:
            console.print("[dim]No findings.[/dim]")
            return

        table = Table(show_header=True, header_style="bold")
        table.add_column("#", width=4, justify="right")
        table.add_column("Sev", width=8)
        table.add_column("Category", width=18)
        table.add_column("Title", max_width=50)
        table.add_column("File/URL", max_width=30)

        for i, f in enumerate(findings, 1):
            sev = f.severity.value
            style = _SEV_COLORS.get(sev, "white")
            loc = f.file_path or f.url or "—"
            table.add_row(
                str(i),
                f"[{style}]{sev.upper()}[/{style}]",
                f.category.value if f.category else "—",
                f.title[:50],
                str(loc)[-30:],
            )

        console.print(table)

        # View detail
        idx = Prompt.ask(
            "View finding details (number, or Enter to go back)", default=""
        )
        if idx.isdigit():
            i = int(idx) - 1
            if 0 <= i < len(findings):
                self._display_finding_detail(findings[i])

    def _display_finding_detail(self, f: Finding) -> None:
        sev = f.severity.value
        style = _SEV_COLORS.get(sev, "white")
        content = (
            f"[bold]Severity:[/bold] [{style}]{sev.upper()}[/{style}]\n"
            f"[bold]Category:[/bold] {f.category.value if f.category else '—'}\n"
            f"[bold]Agent:[/bold]    {f.agent.value if f.agent else '—'}\n"
        )
        if f.file_path:
            content += f"[bold]File:[/bold]     {f.file_path}"
            if f.line_number:
                content += f"  (line {f.line_number})"
            content += "\n"
        if f.url:
            content += f"[bold]URL:[/bold]      {f.url}\n"
        if f.cve_ids:
            content += f"[bold]CVEs:[/bold]     {f.cve_ids}\n"
        if f.cvss_score:
            content += f"[bold]CVSS:[/bold]     {f.cvss_score}\n"
        content += f"\n[bold]Description:[/bold]\n{f.description}\n"
        if f.code_snippet:
            content += f"\n[bold]Code:[/bold]\n[dim]{f.code_snippet[:500]}[/dim]\n"
        if f.poc:
            content += f"\n[bold]PoC:[/bold]\n{f.poc}\n"
        if f.remediation:
            content += f"\n[bold]Remediation:[/bold]\n{f.remediation}\n"

        # Layer 6: Evidence Preview
        if f.raw_output:
            try:
                import json
                evidence = json.loads(f.raw_output)
                if isinstance(evidence, dict) and "request" in evidence:
                    content += "\n[bold cyan]─── Captured Evidence ───[/bold cyan]\n"
                    content += f"[bold blue]Request:[/bold blue]\n[dim]{evidence['request'][:1000]}[/dim]\n"
                    content += f"\n[bold blue]Response:[/bold blue]\n[dim]{evidence['response'][:1000]}[/dim]\n"
            except Exception:
                pass

        console.print(Panel(content, title=f"[bold]{f.title}[/bold]", border_style=style))

    # ─── Config Display ────────────────────────────────────────────────

    def _show_config(self) -> None:
        console.rule("[bold cyan]⚙️  Configuration[/bold cyan]")
        cfg = self.config
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Key", style="bold cyan")
        table.add_column("Value")
        table.add_row("Ollama Host", cfg.ollama.host)
        table.add_row("Ollama Model", cfg.ollama.model)
        table.add_row("Temperature", str(cfg.ollama.temperature))
        table.add_row("Timeout", f"{cfg.ollama.timeout}s")
        table.add_row("Output Dir", cfg.reporting.output_dir)
        table.add_row("DB Path", cfg.database.path)
        table.add_row("Fuzzer Workers", str(cfg.fuzzer.concurrency))
        console.print(table)
        Prompt.ask("\n[dim]Press Enter to continue[/dim]", default="")

    # ─── Help ──────────────────────────────────────────────────────────

    def _show_help(self) -> None:
        console.print(Panel(
            "[bold cyan]Usage:[/bold cyan]\n\n"
            "  [bold]python main.py scan <target>[/bold]\n"
            "      Scan a target (path, URL, or IP)\n\n"
            "  [bold]python main.py scan --model codellama <target>[/bold]\n"
            "      Use a specific Ollama model\n\n"
            "  [bold]python main.py fetch-cves[/bold]\n"
            "      Download latest CVE data from NVD\n\n"
            "  [bold]python main.py dashboard[/bold]\n"
            "      Launch the web dashboard\n\n"
            "[bold cyan]Supported Ollama Models:[/bold cyan]\n"
            "  deepseek-coder-v2  (recommended)\n"
            "  codellama\n"
            "  llama3\n"
            "  mistral\n"
            "  gemma2\n\n"
            "[bold cyan]Install a model:[/bold cyan]\n"
            "  ollama pull qwen2.5-coder:7b",
            title="[bold]Help[/bold]",
            border_style="dim",
        ))
        Prompt.ask("\n[dim]Press Enter to continue[/dim]", default="")

    # ─── Ollama Check ─────────────────────────────────────────────────

    async def _check_ollama(self) -> None:
        from agents.llm.ollama_client import OllamaClient
        client = OllamaClient(self.config.ollama.host, self.config.ollama.model)

        if not client.is_available():
            self._ollama_available = False
            console.print(Panel(
                "[bold red]⚠ Ollama server not detected.[/bold red]\n\n"
                "Start Ollama with: [bold]ollama serve[/bold]\n"
                "Then pull a model: [bold]ollama pull qwen2.5-coder:7b[/bold]\n\n"
                "[dim]Static analysis and network scanning will still work without Ollama.[/dim]",
                title="[yellow]Ollama Not Running[/yellow]",
                border_style="yellow",
            ))
        else:
            self._ollama_available = True
            models = client.list_models()
            model_str = ", ".join(models[:5]) if models else "none installed"
            console.print(
                f"[green]✓ Ollama connected[/green] — "
                f"Available models: [cyan]{model_str}[/cyan]"
            )
            if client.ensure_model():
                self.config.ollama.model = client.model
