"""
agents/fuzzer/fuzzer_agent.py — Fuzzer Agent Orchestrator

Wraps the HTTP fuzzer and future binary/protocol fuzzers into
the BaseAgent lifecycle. Routes findings into the DB.
"""
from __future__ import annotations

import asyncio
from typing import Dict, List

from agents.base import BaseAgent
from agents.fuzzer.http_fuzzer import HTTPFuzzer
from core.models import AgentType, Finding, FindingCategory, Scan, Severity

_SEV_MAP = {
    "critical": Severity.CRITICAL, "high": Severity.HIGH,
    "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO,
}
_CAT_MAP = {c.value: c for c in FindingCategory}


class FuzzerAgent(BaseAgent):
    """Fuzzer agent — tests runtime behavior of web apps and services."""

    agent_type = AgentType.FUZZER

    async def execute(self, scan_id: str, target: str, **kwargs) -> None:
        """
        target: base URL or file path.
        kwargs:
            mode: "http" | "file" | "guided" | "discover" (default: http)
            param_name: str (for guided)
            payloads: List[str] (for guided)
            vuln_type: str (for guided)
        """
        mode = kwargs.get("mode", "http")

        if mode == "http":
            await self._run_http_fuzzer(scan_id, target)
        elif mode == "guided":
            await self._run_guided_fuzzer(scan_id, target, **kwargs)
        elif mode == "discover":
            await self._run_discovery(scan_id, target)

    async def _run_guided_fuzzer(self, scan_id: str, url: str, **kwargs) -> None:
        param_name = kwargs.get("param_name", "")
        payloads = kwargs.get("payloads", [])
        vuln_type = kwargs.get("vuln_type", "custom")

        self.log_info(f"Guided fuzzing on {url} (param: {param_name})")
        fuzzer = HTTPFuzzer(self.config)
        
        try:
            results = await fuzzer.fuzz_guided(url, param_name, payloads, vuln_type)
            for res in results:
                await self._convert_and_emit(scan_id, res)
        finally:
            await fuzzer.close()

    async def _run_discovery(self, scan_id: str, url: str) -> None:
        self.log_info(f"Discovery crawl: {url}")
        fuzzer = HTTPFuzzer(self.config)
        try:
            self.endpoints = await fuzzer.discover(url)
            # Baseline findings are emitted by fuzzer.discover via on_finding if we set it up
            # But here we just want to emit headers for the AI to see
        finally:
            await fuzzer.close()

    async def _run_http_fuzzer(self, scan_id: str, url: str) -> None:
        self.log_info(f"HTTP fuzzing: {url}")

        fuzzer = HTTPFuzzer(self.config)

        # Use a queue + single worker so findings are persisted serially
        # through the shared session (no more concurrent commit races).
        queue: asyncio.Queue[Dict | None] = asyncio.Queue()

        async def _worker():
            while True:
                raw = await queue.get()
                if raw is None:
                    break
                try:
                    await self._convert_and_emit(scan_id, raw)
                except Exception as exc:
                    self.log_error(f"Failed to persist finding: {exc}")
                finally:
                    queue.task_done()

        worker_task = asyncio.create_task(_worker())

        def _on_raw_finding(raw: Dict) -> None:
            queue.put_nowait(raw)

        try:
            await fuzzer.scan(url, on_finding=_on_raw_finding)
            # Wait for all queued findings to be processed
            await queue.join()
        finally:
            # Signal worker to exit and wait for it
            await queue.put(None)
            await worker_task
            await fuzzer.close()

        self.log_info(f"HTTP fuzzing complete — {len(self.findings)} finding(s)")

    async def verify_payload(self, url: str, method: str, param: str, payload: str, expected: str) -> bool:
        """Sends a specific payload and verifies success via HTTPFuzzer."""
        self.log_info(f"Fuzzer proving: {method} {url} with {param}={payload}")
        from core.utils.url import is_valid_url
        if not is_valid_url(url):
            self.log_error(f"Malformed URL discarded: {url}")
            return False

        fuzzer = HTTPFuzzer(self.config)
        try:
            import httpx
            # Prep data/params
            params = {}
            data = {}
            if method.upper() == "GET":
                params = {param: payload}
            else:
                data = {param: payload}
            
            evidence = {"request": f"{method} {url}", "response": "No response"}
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=10) as client:
                if method.upper() == "POST":
                    resp = await client.post(url, data=data, params=params)
                else:
                    resp = await client.get(url, params=params)
                
                evidence["request"] = f"{resp.request.method} {resp.request.url}\n{resp.request.headers}\n\n{resp.request.read().decode(errors='replace')}"
                evidence["response"] = f"HTTP {resp.status_code}\n{resp.headers}\n\n{resp.text[:5000]}" # Limit size

                success = fuzzer.is_success(resp, expected)
                if success:
                    self.log_info(f"[bold green]PROVED![/bold green] Success indicator found.")
                else:
                    self.log_warn(f"Failed to prove vulnerability with this payload.")
                return success, evidence
        except Exception as e:
            self.log_error(f"Fuzzer prove failed: {e}")
            return False, {"error": str(e)}
        finally:
            await fuzzer.close()

    async def _convert_and_emit(self, scan_id: str, raw: Dict) -> None:
        sev = _SEV_MAP.get(raw.get("severity", "info"), Severity.INFO)
        cat = _CAT_MAP.get(raw.get("category", "other"), FindingCategory.OTHER)

        finding = Finding(
            scan_id=scan_id,
            agent=AgentType.FUZZER,
            category=cat,
            severity=sev,
            title=raw.get("title", "Fuzzer Finding"),
            description=raw.get("description", ""),
            url=raw.get("url"),
            parameter=raw.get("parameter"),
            payload=raw.get("payload"),
            poc=raw.get("poc"),
            remediation=raw.get("remediation"),
            confidence=raw.get("confidence", 0.75),
            raw_output=str(raw),
        )
        await self.emit_finding(finding)
