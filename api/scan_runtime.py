"""
api/scan_runtime.py -- in-process scan manager for API-triggered runs

Provides a lightweight runtime layer so the web API can start scans,
stream events, and cancel in-flight work without depending on the CLI.
"""
from __future__ import annotations

import asyncio
import copy
import json
import os
import sys
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from core.config import get_config
from core.orchestrator import Orchestrator

if sys.platform == "win32":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        sys.stderr.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass


@dataclass
class ScanRuntime:
    scan_id: str
    target: str
    label: str
    output_dir: str = ""
    status: str = "queued"
    phase: str = "queued"
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    finding_count: int = 0
    model: str = ""
    error: str = ""
    reports: Dict[str, str] = field(default_factory=dict)
    events: list[dict] = field(default_factory=list)
    sequence: int = 0
    waiter: asyncio.Condition = field(default_factory=asyncio.Condition)
    task: Optional[asyncio.Task] = None

    @property
    def is_terminal(self) -> bool:
        return self.status in {"completed", "failed", "paused", "cancelled"}

    def snapshot(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "label": self.label,
            "status": self.status,
            "phase": self.phase,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "finding_count": self.finding_count,
            "model": self.model,
            "output_dir": self.output_dir,
            "error": self.error,
            "reports": self.reports,
            "active": bool(self.task and not self.task.done()),
            "last_event_id": self.sequence,
        }


class ScanManager:
    """Tracks live scans and exposes structured event streams."""

    def __init__(self) -> None:
        self._scans: Dict[str, ScanRuntime] = {}

    def get(self, scan_id: str) -> Optional[ScanRuntime]:
        return self._scans.get(scan_id)

    def _notify_waiters(self, runtime: ScanRuntime) -> None:
        async def _notify() -> None:
            async with runtime.waiter:
                runtime.waiter.notify_all()

        try:
            asyncio.create_task(_notify())
        except RuntimeError:
            pass

    def publish(self, scan_id: str, event: Dict[str, Any]) -> None:
        runtime = self._scans.get(scan_id)
        if not runtime:
            return

        runtime.sequence += 1
        payload = {
            "id": runtime.sequence,
            "scan_id": scan_id,
            "timestamp": datetime.utcnow().isoformat(),
            **event,
        }
        runtime.events.append(payload)
        runtime.events = runtime.events[-500:]

        event_type = payload.get("type", "")
        message = payload.get("message", "")
        if event_type == "scan_started":
            runtime.status = "running"
            runtime.phase = "initializing"
            runtime.started_at = payload["timestamp"]
            runtime.model = payload.get("model", runtime.model)
        elif event_type == "phase_started":
            runtime.phase = payload.get("phase", runtime.phase)
            runtime.status = "running"
        elif event_type == "phase_completed":
            runtime.phase = payload.get("phase", runtime.phase)
            runtime.finding_count = payload.get("finding_count", runtime.finding_count)
        elif event_type == "finding":
            runtime.finding_count = payload.get("finding_count", runtime.finding_count + 1)
        elif event_type == "scan_completed":
            runtime.status = "completed"
            runtime.phase = "completed"
            runtime.finished_at = payload["timestamp"]
            runtime.finding_count = payload.get("finding_count", runtime.finding_count)
            runtime.reports = self._report_paths(scan_id, runtime.output_dir)
        elif event_type == "scan_failed":
            runtime.status = "failed"
            runtime.phase = "failed"
            runtime.finished_at = payload["timestamp"]
            runtime.error = payload.get("error", message)
        elif event_type == "scan_cancelled":
            runtime.status = "paused"
            runtime.phase = "paused"
            runtime.finished_at = payload["timestamp"]
        elif event_type == "cancel_requested":
            runtime.status = "cancelling"

        self._notify_waiters(runtime)

    def _report_paths(self, scan_id: str, output_dir: str = "") -> Dict[str, str]:
        root = output_dir or get_config().reporting.output_dir
        output_dir = Path(root) / scan_id[:8]
        return {
            "json": str(output_dir / "report.json"),
            "markdown": str(output_dir / "report.md"),
        }

    async def start_scan(
        self,
        *,
        target: str,
        label: str = "",
        model: str = "",
        output_dir: str = "",
        run_static: bool = True,
        run_llm: bool = True,
        run_fuzzer: bool = True,
        run_network: bool = True,
        zero_day_mode: bool = False,
    ) -> ScanRuntime:
        scan_id = str(uuid.uuid4())
        runtime = ScanRuntime(
            scan_id=scan_id,
            target=target,
            label=label or f"Scan of {target}",
            output_dir=output_dir or get_config().reporting.output_dir,
            model=model or get_config().ollama.model,
        )
        self._scans[scan_id] = runtime
        self.publish(
            scan_id,
            {
                "type": "queued",
                "message": f"Queued scan for {target}",
                "target": target,
                "label": runtime.label,
            },
        )

        async def _runner() -> None:
            config = copy.deepcopy(get_config())
            if model:
                config.ollama.model = model
            if output_dir:
                config.reporting.output_dir = output_dir

            orchestrator = Orchestrator(
                config,
                interactive=False,
                run_static=run_static,
                run_llm=run_llm,
                run_fuzzer=run_fuzzer,
                run_network=run_network,
                deep_analysis=zero_day_mode,
                event_callback=lambda event: self.publish(scan_id, event),
                scan_id=scan_id,
            )
            try:
                await orchestrator.run(target, label=label)
            except asyncio.CancelledError:
                self.publish(scan_id, {"type": "scan_cancelled", "message": "Scan cancelled."})
            except Exception as exc:
                self.publish(scan_id, {"type": "scan_failed", "message": str(exc), "error": str(exc)})
            finally:
                runtime.reports = self._report_paths(scan_id, runtime.output_dir)

        runtime.task = asyncio.create_task(_runner())
        return runtime

    async def cancel_scan(self, scan_id: str) -> bool:
        runtime = self._scans.get(scan_id)
        if not runtime or not runtime.task or runtime.task.done():
            return False
        self.publish(scan_id, {"type": "cancel_requested", "message": "Cancellation requested."})
        runtime.task.cancel()
        return True

    async def stream(self, scan_id: str, after: int = 0):
        runtime = self._scans.get(scan_id)
        if not runtime:
            raise KeyError(scan_id)

        cursor = after
        while True:
            sent = False
            for event in runtime.events:
                if event["id"] <= cursor:
                    continue
                cursor = event["id"]
                sent = True
                yield self._format_sse(event)

            if runtime.is_terminal and not sent:
                break

            try:
                async with runtime.waiter:
                    await asyncio.wait_for(runtime.waiter.wait(), timeout=15)
            except asyncio.TimeoutError:
                yield ": keep-alive\n\n"

    @staticmethod
    def _format_sse(event: Dict[str, Any]) -> str:
        return (
            f"id: {event['id']}\n"
            f"event: {event.get('type', 'message')}\n"
            f"data: {json.dumps(event, default=str)}\n\n"
        )

    async def shutdown(self) -> None:
        tasks = [runtime.task for runtime in self._scans.values() if runtime.task and not runtime.task.done()]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)


scan_manager = ScanManager()
