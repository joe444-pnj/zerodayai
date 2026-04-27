"""
agents/base.py — Abstract Base Agent

All scanning agents inherit from BaseAgent. Provides lifecycle hooks,
finding emission, and logging helpers.
"""

from __future__ import annotations

import asyncio
import uuid
from abc import ABC, abstractmethod
from datetime import datetime
from typing import AsyncGenerator, Callable, List, Optional

from rich.console import Console

from core.models import AgentTask, AgentType, Finding, Scan, ScanStatus

console = Console()


class BaseAgent(ABC):
    """Abstract base class for all ZeroDay AI agents."""

    agent_type: AgentType  # Subclasses must set this

    def __init__(self, config, session=None):
        """
        Args:
            config: The global Config object.
            session: Optional SQLAlchemy async session for persisting findings.
        """
        self.config = config
        self.session = session
        self.findings: List[Finding] = []
        self._task: Optional[AgentTask] = None
        self._on_finding_callbacks: List[Callable[[Finding], None]] = []
        self._stopped = False

    # ─── Lifecycle ───────────────────────────────────────────────────

    async def run(self, scan_id: str, target: str, **kwargs) -> List[Finding]:
        """Entry point — orchestrator calls this."""
        self._stopped = False
        self._task = AgentTask(
            scan_id=scan_id,
            agent=self.agent_type,
            status=ScanStatus.RUNNING,
            sub_target=target,
            started_at=datetime.utcnow(),
        )

        if self.session:
            self.session.add(self._task)
            await self._safe_commit()

        try:
            await self.execute(scan_id, target, **kwargs)
            if self._task:
                self._task.status = ScanStatus.COMPLETED
                self._task.findings_count = len(self.findings)
                self._task.finished_at = datetime.utcnow()
        except asyncio.CancelledError:
            if self._task:
                self._task.status = ScanStatus.PAUSED
                self._task.finished_at = datetime.utcnow()
            raise
        except Exception as exc:
            if self._task:
                self._task.status = ScanStatus.FAILED
                self._task.error_msg = str(exc)
                self._task.finished_at = datetime.utcnow()
            raise
        finally:
            if self.session and self._task:
                await self._safe_commit()

        return self.findings

    @abstractmethod
    async def execute(self, scan_id: str, target: str, **kwargs) -> None:
        """Subclasses implement their scanning logic here."""
        ...

    def stop(self) -> None:
        """Signal the agent to stop gracefully."""
        self._stopped = True

    # ─── Finding Emission ────────────────────────────────────────────

    async def emit_finding(self, finding: Finding) -> None:
        """Register a finding, persist it, and fire callbacks."""
        finding.id = str(uuid.uuid4())
        finding.created_at = datetime.utcnow()

        self.findings.append(finding)

        if self.session:
            self.session.add(finding)
            
            if finding.poc and not finding.false_positive:
                from core.models import AgentLearning
                from sqlalchemy import select
                pattern = finding.code_snippet or finding.url or finding.title
                if pattern:
                    existing = await self.session.execute(
                        select(AgentLearning).where(AgentLearning.pattern_context == pattern)
                    )
                    if not existing.scalars().first():
                        learning = AgentLearning(
                            pattern_context=pattern,
                            outcome_notes=f"Found {finding.title} with PoC:\n{finding.poc}",
                            is_false_positive=0
                        )
                        self.session.add(learning)

            await self._safe_commit()
            self.session.expunge(finding)

        for cb in self._on_finding_callbacks:
            cb(finding)

        self._log_finding(finding)

    async def _safe_commit(self) -> None:
        """Commit the session, rolling back on failure to avoid poisoning it."""
        try:
            await self.session.commit()
        except Exception:
            await self.session.rollback()
            raise

    def on_finding(self, callback: Callable[[Finding], None]) -> None:
        """Register a callback triggered when a finding is emitted."""
        self._on_finding_callbacks.append(callback)

    # ─── Helpers ─────────────────────────────────────────────────────

    def _log_finding(self, finding: Finding) -> None:
        emoji = finding.severity_emoji()
        sev = finding.severity.upper()
        console.print(
            f"  {emoji} [{sev}] {finding.title}",
            style=self._severity_style(finding.severity.value),
        )

    @staticmethod
    def _severity_style(severity: str) -> str:
        return {
            "critical": "bold red",
            "high":     "red",
            "medium":   "yellow",
            "low":      "green",
            "info":     "cyan",
        }.get(severity, "white")

    def log(self, msg: str, style: str = "dim") -> None:
        console.print(f"  [dim][{self.agent_type.upper()}][/dim] {msg}", style=style)

    def log_info(self, msg: str) -> None:
        self.log(f"[cyan]{msg}[/cyan]")

    def log_warn(self, msg: str) -> None:
        self.log(f"[yellow]⚠ {msg}[/yellow]")

    def log_error(self, msg: str) -> None:
        self.log(f"[red]✗ {msg}[/red]")
