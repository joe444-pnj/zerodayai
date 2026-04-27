"""
core/orchestrator.py — Master Scan Orchestrator

Coordinates all agents, handles interactive prompts between phases,
tracks scan state, and generates final reports.

Key upgrades:
  - Global dedup via hash(endpoint + category)
  - Verification agent re-tests with variant payloads
  - Tech detection for smarter payload selection
  - Structured PoC format with execute + retry
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional, Any, Set
from sqlalchemy import select
from urllib.parse import urljoin, urlparse

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from agents.fuzzer.fuzzer_agent import FuzzerAgent
from agents.llm.llm_planner import LLMPlanner
from agents.llm.llm_analyzer import LLMAnalyzer
from agents.llm.llm_exploiter import LLMExploiter
from agents.llm.llm_verifier import LLMVerifier
from agents.llm.verification_agent import VerificationAgent
from agents.llm.finding_verifier import FindingVerifier
from agents.llm.chain_synthesizer import ChainSynthesizer
from agents.llm.rag import CVEKnowledgeBase, get_knowledge_base, get_learning_base
from agents.network.network_agent import NetworkAgent
from agents.static.static_agent import StaticAgent
from agents.tools import ResponseAnalyzer, TechDetector, PayloadIntelligence, FindingCorrelator
from core.config import Config
from core.database import get_session, init_db
from core.finding_quality import summarize_trust
from core.models import AgentType, Finding, Scan, ScanStatus, Severity, AgentLearning, FindingCategory
from core.report import ReportGenerator
from core.utils.json_sanitizer import sanitize_planner_output, sanitize_poc_output, sanitize_confidence
from core.utils.url import normalize_url, build_exploit_url, extract_base_url, is_valid_url

console = Console()

# Severity color map for display
_SEV_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH:     "red",
    Severity.MEDIUM:   "yellow",
    Severity.LOW:      "green",
    Severity.INFO:     "cyan",
}


class Orchestrator:
    """Master controller coordinating all ZeroDay AI agents."""

    def __init__(
        self,
        config: Config,
        interactive: bool = True,
        run_static: bool = True,
        run_llm: bool = True,
        run_fuzzer: bool = True,
        run_network: bool = True,
        deep_analysis: bool = False,
        event_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        scan_id: Optional[str] = None,
    ):
        self.config = config
        self.interactive = interactive
        self.run_static_phase = run_static
        self.run_llm_phase = run_llm
        self.run_fuzzer_phase = run_fuzzer
        self.run_network_phase = run_network
        self.deep_analysis = deep_analysis
        self.event_callback = event_callback
        self.scan_id: Optional[str] = scan_id
        self.all_findings: List[Finding] = []
        self._kb: Optional[CVEKnowledgeBase] = None
        self._seen_dedup_keys: Set[str] = set()  # Global dedup
        self._tech_stack: Dict = {}  # Cached tech detection result
        self.endpoints: List[Any] = []
        self._finding_verifier: Optional[FindingVerifier] = None
        self._chain_synthesizer: Optional[ChainSynthesizer] = None

    def _emit_event(self, event_type: str, message: str = "", **data: Any) -> None:
        """Publish structured scan events for API consumers."""
        if not self.event_callback:
            return
        payload = {
            "type": event_type,
            "message": message,
            "scan_id": self.scan_id,
            "timestamp": datetime.utcnow().isoformat(),
            **data,
        }
        try:
            self.event_callback(payload)
        except Exception:
            pass

    def _record_finding(self, finding: Finding) -> None:
        """Track findings centrally so live observers see them immediately."""
        self.all_findings.append(finding)
        self._emit_event(
            "finding",
            finding.title,
            finding_id=finding.id,
            title=finding.title,
            severity=finding.severity.value if getattr(finding, "severity", None) else "info",
            category=finding.category.value if getattr(finding, "category", None) else "other",
            agent=finding.agent.value if getattr(finding, "agent", None) else "unknown",
            confidence=finding.confidence,
            finding_count=len(self.all_findings),
        )

    def log_info(self, msg: str) -> None:
        console.print(f"  [cyan][INFO][/cyan] {msg}")
        self._emit_event("log", msg, level="info")

    def log_warn(self, msg: str) -> None:
        console.print(f"  [yellow][WARN][/yellow] {msg}")
        self._emit_event("log", msg, level="warn")

    def log_error(self, msg: str) -> None:
        console.print(f"  [red][ERROR][/red] {msg}")
        self._emit_event("log", msg, level="error")

    async def _emit_orch_finding(self, finding: Finding) -> None:
        """Helper to emit findings from the orchestrator logic with global dedup."""
        # Global dedup: hash by (endpoint_path + category)
        url_or_path = finding.url or finding.file_path or ""
        path = urlparse(url_or_path).path if url_or_path.startswith("http") else url_or_path
        cat_val = finding.category.value if hasattr(finding.category, 'value') else str(finding.category)
        dedup_key = hashlib.md5(f"{path}||{cat_val}".encode()).hexdigest()
        
        if dedup_key in self._seen_dedup_keys:
            self.log_info(f"Dedup: Skipping duplicate finding for {path} [{cat_val}]")
            return
        self._seen_dedup_keys.add(dedup_key)

        # Sanitize confidence
        finding.confidence = sanitize_confidence(finding.confidence)

        finding.scan_id = self.scan_id
        finding.id = str(uuid.uuid4())
        finding.created_at = datetime.utcnow()

        # ── Finding Verification Gate ──
        # Second-opinion check to filter false positives before persistence
        if self._finding_verifier:
            try:
                finding_dict = {
                    "category": finding.category.value if hasattr(finding.category, 'value') else str(finding.category),
                    "title": finding.title,
                    "description": finding.description,
                    "url": finding.url,
                    "payload": finding.payload,
                    "poc": finding.poc,
                    "code_snippet": finding.code_snippet,
                    "raw_output": finding.raw_output,
                    "confidence": finding.confidence,
                }
                is_real, adjusted_conf, reason = await self._finding_verifier.verify(finding_dict)
                
                if not is_real:
                    self.log_info(f"Verification REJECTED: {finding.title} — {reason}")
                    finding.false_positive = 1
                    finding.confidence = adjusted_conf
                else:
                    finding.confidence = adjusted_conf
            except Exception as e:
                self.log_warn(f"Verification gate error: {e} — allowing finding through")

        # ── CVE Enrichment ──
        if self._kb and self._kb.loaded:
            try:
                self._kb.enrich_finding(finding)
            except Exception:
                pass

        self._record_finding(finding)
        
        async with get_session() as session:
            session.add(finding)
            # Add to memory if it's a true positive with PoC
            if finding.poc and not finding.false_positive:
                pattern = finding.code_snippet or finding.url or finding.title
                existing = await session.execute(
                    select(AgentLearning).where(AgentLearning.pattern_context == pattern)
                )
                if not existing.scalars().first():
                    learning = AgentLearning(
                        pattern_context=pattern,
                        outcome_notes=f"Found {finding.title} with PoC:\n{finding.poc}",
                        is_false_positive=0
                    )
                    session.add(learning)
            await session.commit()

    # ─── Entry Point ──────────────────────────────────────────────────

    async def run(self, target: str, label: str = "") -> Scan:
        """Main entry — runs the full scan pipeline."""
        await init_db()

        # Load knowledge base
        self._kb = get_knowledge_base(self.config.knowledge.cve_cache_path)

        # Initialize verification gate and chain synthesizer
        self._finding_verifier = FindingVerifier(self.config)
        self._chain_synthesizer = ChainSynthesizer(self.config)

        # Create scan record
        self.scan_id = self.scan_id or str(uuid.uuid4())
        async with get_session() as session:
            scan = Scan(
                id=self.scan_id,
                target=target,
                label=label or f"Scan of {target}",
                status=ScanStatus.RUNNING,
                started_at=datetime.utcnow(),
                config_snapshot=json.dumps({"model": self.config.ollama.model}),
            )
            session.add(scan)
            await session.commit()

        console.print(
            Panel(
                f"[bold cyan]Scan ID:[/bold cyan] {self.scan_id[:8]}\n"
                f"[bold cyan]Target: [/bold cyan] {target}\n"
                f"[bold cyan]Model:  [/bold cyan] {self.config.ollama.model}",
                title="[bold green]🔍 ZeroDay AI — Scan Started[/bold green]",
                border_style="green",
            )
        )
        self._emit_event(
            "scan_started",
            f"Scan started for {target}",
            target=target,
            label=label or f"Scan of {target}",
            model=self.config.ollama.model,
        )

        # Detect target type
        target_types = self._detect_target_types(target)
        console.print(f"[dim]Detected target types: {', '.join(target_types)}[/dim]\n")
        was_cancelled = False
        failure_message: Optional[str] = None
        should_reraise = False

        try:
            # ── STATE 1: ASSET_DISCOVERY ──────────────────────────────
            if "web" in target_types:
                await self._run_phase("Phase: Asset Discovery", self._run_discovery, target)

            # ── STATE 2: VULSIBILITY MODELING ────────────────────────
            if self.run_static_phase and "code" in target_types:
                await self._run_phase("Phase: Vulnerability Modeling", self._run_static, target)

            # ── STATE 3: ATTACK PLANNING (LLM Grounded) ───────────────
            if self.run_llm_phase and ("code" in target_types or "web" in target_types):
                # Prioritize endpoints before planning
                self._prioritize_endpoints()
                await self._run_phase("Phase: Attack Planning", self._run_llm, target)

            # ── STATE 4: PRECISION ATTACK (Fuzzing) ───────────────────
            if self.run_fuzzer_phase and "web" in target_types and self.config.fuzzer.run_fuzzer:
                await self._run_phase("Phase: Precision Attack", self._run_fuzzer, target)

            # ── STATE 5: NETWORK RECONNAISSANCE ───────────────────────
            if self.run_network_phase and "network" in target_types:
                await self._run_phase("Phase: Network Reconnaissance", self._run_network, target)

        except asyncio.CancelledError:
            was_cancelled = True
            console.print("[yellow]Scan paused.[/yellow]")
            self._emit_event("scan_cancelled", "Scan paused by cancellation request.")
        except Exception as exc:
            failure_message = str(exc)
            should_reraise = True
            self.log_error(f"Scan failed: {exc}")

        # ── Attack Chain Synthesis ──
        if not was_cancelled and not failure_message and self._chain_synthesizer and len(self.all_findings) >= 2:
            try:
                await self._run_chain_synthesis()
            except Exception as e:
                self.log_error(f"Chain synthesis failed: {e}")

        # Finalize
        await self._finalize_scan(cancelled=was_cancelled, failure_message=failure_message)
        async with get_session() as session:
            scan = await session.get(Scan, self.scan_id)

        if should_reraise:
            raise RuntimeError(failure_message or "Scan failed")

        return scan

    # ─── Phase Runner ─────────────────────────────────────────────────

    async def _run_phase(self, phase_name: str, coro_fn, target: str) -> None:
        """Run a scan phase with interactive checkpoint afterward."""
        console.rule(f"[bold cyan]Phase: {phase_name}[/bold cyan]")
        before = len(self.all_findings)
        self._emit_event("phase_started", phase_name, phase=phase_name, finding_count=before)

        await coro_fn(target)

        new_findings = self.all_findings[before:]
        if new_findings:
            self._print_findings_summary(new_findings, phase_name)

        self._emit_event(
            "phase_completed",
            phase_name,
            phase=phase_name,
            new_findings=len(new_findings),
            finding_count=len(self.all_findings),
        )

        if self.interactive and new_findings:
            await self._interactive_checkpoint(phase_name, new_findings)

    # ─── Individual Agent Runners ─────────────────────────────────────

    async def _run_static(self, target: str) -> None:
        async with get_session() as session:
            agent = StaticAgent(self.config, session)
            agent.on_finding(self._record_finding)
            await agent.run(self.scan_id, target)

    async def _run_discovery(self, target: str) -> None:
        """Phase 0: Map the website structure and baseline headers."""
        async with get_session() as session:
            agent = FuzzerAgent(self.config, session)
            agent.on_finding(self._record_finding)
            # This will store the discovered endpoints in the agent instance 
            # and emit baseline findings (headers/cookies)
            await agent.run(self.scan_id, target, mode="discover")
            
            # --- NEW: JS Surface Mapping ---
            if target.startswith(("http://", "https://")):
                try:
                    from core.discovery.js_surface_mapper import js_surface_mapper
                    import json
                    self.log_info("Running JS Surface Mapper to find hidden endpoints & GraphQL...")
                    # Generate mapping
                    js_target = target if not target.endswith('/') else target[:-1]
                    mapping_json = js_surface_mapper(
                        base_url=js_target,
                        entry_paths=["/"],
                        max_assets=15, 
                        include_sourcemaps=True
                    )
                    mapping_data = json.loads(mapping_json)
                    
                    # Target might be normalized differently in the output origins
                    js_endpoints = []
                    for origin, eps in mapping_data.get("endpoints", {}).items():
                        js_endpoints.extend(eps)
                        
                    gql_endpoints = mapping_data.get("graphql", {}).get("endpoints", [])
                    ws_endpoints = mapping_data.get("ws_sse", [])
                    
                    found = set(js_endpoints + gql_endpoints + ws_endpoints)
                    if found:
                        self.log_info(f"JS Mapper found {len(found)} hidden paths!")
                        
                        if not hasattr(agent, "endpoints"):
                            agent.endpoints = []
                            
                        # Extract existing paths correctly accounting for both dicts and Endpoint objects
                        existing_paths = set()
                        for ep in agent.endpoints:
                            if isinstance(ep, dict):
                                existing_paths.add(ep.get("path"))
                            elif hasattr(ep, "path"):
                                existing_paths.add(getattr(ep, "path"))
                                
                        for p in found:
                            if p not in existing_paths:
                                agent.endpoints.append({
                                    "path": p,
                                    "method": "GET",
                                    "params": [],
                                    "type": "general"
                                })
                except Exception as e:
                    self.log_warn(f"JS Surface Mapper failed: {e}")
            
            self.endpoints = list(getattr(agent, "endpoints", []))
            self._last_discovery = self.endpoints

    async def _run_llm(self, target: str) -> None:
        # Check if Ollama is available before starting
        from agents.llm.ollama_client import OllamaClient
        client = OllamaClient(self.config.ollama.host, self.config.ollama.model)
        if not client.is_available():
            self.log_error("Ollama server is unreachable. Skipping LLM reasoning phase.")
            return

        # Handle Web / URL targets (AI-Led)
        if target.startswith(("http://", "https://")):
            try:
                await self._run_llm_for_web(target)
            except Exception as e:
                self.log_error(f"AI Web analysis failed: {e}")
            return

        # Handle Code targets (Recursive file analysis)
        path = Path(target)
        files = list(path.rglob("*")) if path.is_dir() else [path]
        code_files = [
            f for f in files
            if f.is_file() and f.suffix in (
                ".py", ".js", ".ts", ".php", ".java", ".c", ".cpp", ".go", ".rb", ".sol",
            )
        ]

        from agents.static.static_agent import LANG_MAP
        async with get_session() as session:
            planner = LLMPlanner(self.config, session)
            analyzer = LLMAnalyzer(self.config, session)
            lb = get_learning_base()
            max_files = 50 if self.deep_analysis else 20

            for code_file in code_files[:max_files]:
                lang = LANG_MAP.get(code_file.suffix, "text")
                try:
                    code = code_file.read_text(errors="replace")
                    
                    # 1. Planner generates hypotheses
                    self.log_info(f"Planning for {code_file.name}...")
                    past_lx = lb.search_past_experiences(code[:1000])
                    hypotheses = await planner.plan("[]", code, past_lx)

                    for hyp in hypotheses:
                        hyp_type = str(hyp.get("type", "")).strip()
                        entry_point = hyp.get("entry_point") or hyp.get("endpoint") or str(code_file)
                        if not hyp_type or hyp.get("confidence", 0) < 0.6:
                            continue
                        
                        self.log_info(f"Analyzing hypothesis: {hyp_type} at {entry_point}")
                        analysis = await analyzer.analyze(code, hyp)
                        
                        if analysis.get("is_vulnerable") and analysis.get("confidence", 0) > 0.6:
                            category = self._map_vuln_category(hyp_type)
                            severity = Severity.HIGH if analysis.get("confidence", 0) >= 0.85 else Severity.MEDIUM
                            if category == FindingCategory.COMMAND_INJECTION and analysis.get("confidence", 0) >= 0.85:
                                severity = Severity.CRITICAL

                            finding = Finding(
                                scan_id=self.scan_id,
                                agent=AgentType.LLM,
                                category=category,
                                severity=severity,
                                title=f"AI confirmed {hyp_type} in {code_file.name}",
                                description=analysis.get("reasoning", "") or hyp.get("reasoning", ""),
                                file_path=str(code_file),
                                code_snippet=analysis.get("data_flow", ""),
                                confidence=analysis.get("confidence", 0.8),
                                raw_output=json.dumps(
                                    {"hypothesis": hyp, "analysis": analysis, "entry_point": entry_point},
                                    default=str,
                                ),
                            )
                            await self._emit_orch_finding(finding)

                except Exception as e:
                    console.print(f"[dim]Security Reasoning skip {code_file.name}: {e}[/dim]")

    async def _run_llm_for_web(self, target: str) -> None:
        """AI-Led reasoning on web endpoints with structured PoC + retry + verification."""
        endpoints = self.endpoints or getattr(self, "_last_discovery", [])
        if not endpoints:
            from core.discovery.asset_modeler import Endpoint, EndpointType

            endpoints = [
                Endpoint(path=target, method="GET", params=[], type=EndpointType.GENERAL)
            ]
        self.endpoints = list(endpoints)
        
        target_base = extract_base_url(target)
        
        async with get_session() as session:
            planner = LLMPlanner(self.config, session)
            exploiter = LLMExploiter(self.config, session)
            verifier = VerificationAgent(self.config, session)
            lb = get_learning_base()

            # ── Step 0: Tech Detection ─────────────────────────────
            if not self._tech_stack:
                self.log_info("Detecting technology stack...")
                self._tech_stack = await TechDetector.detect(target)
                techs = self._tech_stack.get("technologies", [])
                risks = self._tech_stack.get("risk_factors", [])
                if techs:
                    console.print(f"  [cyan]Tech Stack:[/cyan] {', '.join(techs)}")
                if risks:
                    console.print(f"  [bold red]Risk Factors:[/bold red] {', '.join(risks)}")

            # ── Step 1: AI Attack Planning ──────────────────────────
            self.log_info("AI is analyzing classified site map to plan targeted attacks...")
            
            serialized_endpoints = []
            valid_paths = []
            for endpoint in endpoints:
                if hasattr(endpoint, "path"):
                    ep_path = endpoint.path
                    ep_method = endpoint.method
                    ep_params = endpoint.params
                    ep_type = endpoint.type.value if hasattr(endpoint.type, "value") else str(endpoint.type)
                else:
                    ep_path = endpoint.get("path", target)
                    ep_method = endpoint.get("method", "GET")
                    ep_params = endpoint.get("params", [])
                    ep_type = endpoint.get("type", "general")

                serialized_endpoints.append(
                    {"path": ep_path, "method": ep_method, "params": ep_params, "type": ep_type}
                )
                valid_paths.append(ep_path)

            assets_json = json.dumps(serialized_endpoints, indent=2)
            past_lx = lb.search_past_experiences(assets_json, top_k=5)

            # ── NEW: Endpoint-specific RAG intelligence ──
            endpoint_intelligence = {}
            for ep in serialized_endpoints[:15]:  # Cap to avoid slow startup
                ep_path = ep.get("path", "")
                ep_params = ep.get("params", [])
                intel = lb.search_for_endpoint(ep_path, ep_params, top_k=3)
                if intel:
                    endpoint_intelligence[ep_path] = intel
            
            if endpoint_intelligence:
                self.log_info(f"RAG: Loaded intelligence for {len(endpoint_intelligence)} endpoints from past scans")
            
            # Inject endpoint intelligence into the planner's past experiences
            enriched_past = past_lx
            if endpoint_intelligence:
                intel_summary = "\n".join(
                    f"[{path}]: {intel[:200]}" 
                    for path, intel in list(endpoint_intelligence.items())[:5]
                )
                enriched_past = f"{past_lx}\n\n<endpoint_specific_intelligence>\n{intel_summary}\n</endpoint_specific_intelligence>"
            
            raw_hypotheses = await planner.plan(
                asset_model_json=assets_json,
                code_chunk="[Web target - Classified Site Structure Analysis]",
                past_experiences=enriched_past,
                valid_endpoints=valid_paths
            )

            if not raw_hypotheses:
                self.log_warn("AI planner found no attack hypotheses for this target.")
                return

            self.log_info(f"AI generated {len(raw_hypotheses)} attack hypotheses.")

            # ── Step 2: For each hypothesis → Generate PoC → Execute → Verify ──
            for i, vuln in enumerate(raw_hypotheses, 1):
                endpoint = vuln.get('endpoint', '')
                vuln_type = vuln.get('type', 'Unknown')
                confidence = sanitize_confidence(vuln.get('confidence', 0))

                console.rule(f"[yellow]Hypothesis {i}/{len(raw_hypotheses)}: {vuln_type} at {endpoint}[/yellow]")
                console.print(f"  Confidence: {confidence:.0%} | Method: {vuln.get('method', 'GET')} | Param: {vuln.get('param', '?')}")

                # ── Step 2a: Generate structured PoC ────────────────
                self.log_info("Generating structured PoC...")
                poc = await exploiter.generate_exploit(
                    confirmed_vuln=vuln,
                    endpoint_info=f"Target: {target_base}, Endpoint: {endpoint}",
                    target_base=target_base,
                )

                if poc.get("confidence", 0) < 0.3:
                    self.log_warn(f"Exploiter returned low-confidence PoC ({poc.get('confidence', 0):.0%}), skipping.")
                    continue

                # Show the structured PoC
                console.print(f"  [dim]PoC: {poc.get('name', '?')} → {poc.get('method', '?')} {poc.get('endpoint', '?')}[/dim]")
                console.print(f"  [dim]Payload: {poc.get('payload', {})}[/dim]")
                console.print(f"  [dim]Success indicator: {poc.get('success_indicator', 'N/A')}[/dim]")

                # ── Step 2b: Execute with retry ─────────────────────
                self.log_info("Executing PoC with retry logic...")
                success, evidence, winning_poc = await exploiter.execute_with_retry(
                    target_base=target_base,
                    poc=poc,
                    max_retries=5,
                )

                if not success:
                    self.log_warn(f"PoC execution failed for {vuln_type} at {endpoint}. Skipping.")
                    continue

                # ── Step 2c: Verification Agent — re-test with variants ──
                self.log_info("Running Verification Agent...")
                verification = await verifier.verify_finding(
                    target_base=target_base,
                    finding=None,  # Finding not created yet
                    poc=winning_poc,
                    min_confirmations=2,
                    max_variants=6,
                )

                ver_status = verification.get("status", "UNVERIFIED")
                ver_confirms = verification.get("confirmations", 0)
                ver_total = verification.get("total_tested", 0)

                # Determine severity based on verification + type
                if ver_status == "CONFIRMED":
                    sev = Severity.CRITICAL if vuln_type.lower() in ("command injection", "rce") else Severity.HIGH
                    title_prefix = "CONFIRMED"
                elif ver_status == "LIKELY_REAL":
                    sev = Severity.HIGH
                    title_prefix = "LIKELY"
                else:
                    sev = Severity.MEDIUM
                    title_prefix = "UNVERIFIED"

                # ── Step 2d: Build curl and emit finding ────────────
                curl_cmd = winning_poc.get("curl", "")
                poc_json = json.dumps(winning_poc, indent=2, default=str)
                
                finding = Finding(
                    scan_id=self.scan_id,
                    agent=AgentType.LLM,
                    category=self._map_vuln_category(vuln_type),
                    severity=sev,
                    title=f"{title_prefix}: {vuln_type} at {endpoint}",
                    description=(
                        f"{vuln.get('reasoning', '')}\n\n"
                        f"Verification: {ver_status} ({ver_confirms}/{ver_total} vectors confirmed)\n"
                        f"Evidence chain: {'; '.join(verification.get('evidence_chain', [])[:3])}"
                    ),
                    url=normalize_url(target_base, endpoint),
                    parameter=vuln.get('param', ''),
                    payload=json.dumps(winning_poc.get('payload', {})),
                    confidence=sanitize_confidence(winning_poc.get('confidence', 0.8)),
                    poc=f"{curl_cmd}\n\n--- Structured PoC ---\n{poc_json}",
                    raw_output=json.dumps({
                        "poc": winning_poc,
                        "verification": verification,
                        "evidence": evidence,
                    }, default=str),
                )
                await self._emit_orch_finding(finding)
                
                # Store for training
                input_ctx = f"Endpoint: {endpoint}\nMethod: {vuln.get('method', 'GET')}\nParams: {vuln.get('param', '')}"
                await self._store_training_data(input_ctx, finding)

            # ── Step 3: Attack Chain Correlation ────────────────────
            chains = FindingCorrelator.correlate(self.all_findings)
            if chains:
                console.print(f"\n  [bold red]⚡ Attack Chains Detected:[/bold red]")
                for chain in chains:
                    console.print(f"    🔗 {chain['chain_name']}: {chain['description']}")

    async def _fetch_page_source(self, url: str) -> str:
        """Fetch page source for the Analyzer."""
        try:
            import httpx
            async with httpx.AsyncClient(timeout=10, verify=False) as client:
                resp = await client.get(url)
                return resp.text[:5000] # Limit size for LLM
        except Exception:
            return "[Failed to fetch source]"

    async def _store_training_data(self, code: str, finding: Finding) -> None:
        """Saves confirmed vulnerabilities to training_data.jsonl for future fine-tuning."""
        try:
            data = {
                "instruction": f"Find {finding.category} vulnerability and generate PoC",
                "input": f"Code:\n{code[:2000]}\nContext: {finding.file_path}",
                "output": json.dumps({
                    "title": finding.title,
                    "description": finding.description,
                    "poc": finding.poc,
                    "exploit_script": finding.raw_output
                })
            }
            with open("training_data.jsonl", "a", encoding="utf-8") as f:
                f.write(json.dumps(data) + "\n")
        except Exception as e:
            self.log_error(f"Failed to save training data: {e}")

    async def _run_fuzzer(self, target: str) -> None:
        if not self.config.fuzzer.run_fuzzer: # Add check for skip
             return
        url = target if target.startswith("http") else f"http://{target}"
        async with get_session() as session:
            agent = FuzzerAgent(self.config, session)
            agent.on_finding(self._record_finding)
            await agent.run(self.scan_id, url, mode="http")

    async def _run_network(self, target: str) -> None:
        host = target.removeprefix("http://").removeprefix("https://").split("/")[0]
        async with get_session() as session:
            agent = NetworkAgent(self.config, session)
            agent.on_finding(self._record_finding)
            await agent.run(self.scan_id, host)

    async def _run_chain_synthesis(self) -> None:
        """Synthesize attack chains from all findings after scan completes."""
        real_findings = [f for f in self.all_findings if not getattr(f, 'false_positive', 0)]
        
        if len(real_findings) < 2:
            return

        console.rule("[bold red]⚡ Attack Chain Synthesis[/bold red]")
        self.log_info(f"Analyzing {len(real_findings)} findings for multi-step attack chains...")

        chains = await self._chain_synthesizer.synthesize(real_findings)

        if not chains:
            self.log_info("No attack chains identified.")
            return

        console.print(f"\n  [bold red]🔗 {len(chains)} Attack Chain(s) Detected:[/bold red]")
        
        for i, chain in enumerate(chains, 1):
            cvss = chain.get('cvss', 0)
            cvss_color = "bold red" if cvss >= 9.0 else "red" if cvss >= 7.0 else "yellow"
            
            console.print(f"\n  [{cvss_color}]Chain {i}: {chain['name']}[/{cvss_color}]")
            console.print(f"    CVSS: {cvss:.1f} | Source: {chain.get('source', 'unknown')}")
            console.print(f"    Impact: {chain.get('impact', 'N/A')}")
            
            for step in chain.get('steps', []):
                if isinstance(step, dict):
                    step_num = step.get('step', '') or step.get('category', '')
                    action = step.get('action', '') or step.get('finding', '')
                    console.print(f"      → {step_num}: {action}")

            # Emit chain as a CRITICAL finding
            chain_finding = Finding(
                scan_id=self.scan_id,
                agent=AgentType.LLM,
                category=FindingCategory.OTHER,
                severity=Severity.CRITICAL if cvss >= 9.0 else Severity.HIGH,
                title=f"Attack Chain: {chain['name']}",
                description=(
                    f"Impact: {chain.get('impact', 'N/A')}\n\n"
                    f"Steps:\n" + "\n".join(
                        f"  {s.get('step', s.get('category', ''))}: {s.get('action', s.get('finding', ''))}"
                        for s in chain.get('steps', []) if isinstance(s, dict)
                    )
                ),
                confidence=chain.get('confidence', 0.8),
                cvss_score=cvss,
                raw_output=json.dumps(chain, default=str),
            )
            await self._emit_orch_finding(chain_finding)

    # ─── Interactive Checkpoints ──────────────────────────────────────

    async def _interactive_checkpoint(
        self, phase_name: str, new_findings: List[Finding]
    ) -> None:
        """Ask user what to do after each phase."""
        console.print()
        console.print(
            Panel(
                f"Phase [bold]{phase_name}[/bold] complete.\n"
                f"Found [bold]{len(new_findings)}[/bold] new issue(s).",
                title="[bold yellow]⚡ Interactive Checkpoint[/bold yellow]",
                border_style="yellow",
            )
        )

        # Show numbered finding list
        for i, f in enumerate(new_findings[:10], 1):
            emoji = f.severity_emoji()
            console.print(f"  [{i}] {emoji} {f.severity.upper():8} {f.title[:70]}")

        console.print()
        console.print("[bold]Options:[/bold]")
        console.print("  [1] Generate PoC for a finding")
        console.print("  [2] Deep-dive (zero-day hypothesis) on a finding")
        console.print("  [3] Mark a finding as false-positive")
        console.print("  [4] Continue to next phase")
        console.print("  [5] Stop and generate report now")
        console.print()

        choice = Prompt.ask(
            "[bold cyan]Your choice[/bold cyan]",
            choices=["1", "2", "3", "4", "5"],
            default="4",
        )

        if choice == "1":
            await self._interactive_poc(new_findings)
        elif choice == "2":
            await self._interactive_deep_dive(new_findings)
        elif choice == "3":
            await self._interactive_mark_fp(new_findings)
        elif choice == "5":
            raise asyncio.CancelledError()

    async def _interactive_poc(self, findings: List[Finding]) -> None:
        idx = int(Prompt.ask("Finding number for PoC", default="1")) - 1
        if 0 <= idx < len(findings):
            finding = findings[idx]
            async with get_session() as session:
                exploiter = LLMExploiter(self.config, session)
                
                # Extract target base from finding URL or scan target
                target_base = ""
                if finding.url:
                    target_base = extract_base_url(finding.url)
                
                analysis = {
                    "reasoning": finding.description,
                    "data_flow": finding.code_snippet or "",
                    "type": finding.category.value if hasattr(finding.category, 'value') else str(finding.category),
                }
                
                poc = await exploiter.generate_exploit(
                    confirmed_vuln=analysis,
                    endpoint_info=finding.url or finding.file_path or "",
                    target_base=target_base,
                )
                
                # Display structured PoC
                curl_cmd = poc.get("curl", "")
                poc_display = curl_cmd if curl_cmd else json.dumps(poc, indent=2, default=str)
                
                if poc_display:
                    console.print(Panel(poc_display, title=f"PoC: {finding.title}", border_style="red"))
                    finding.poc = poc_display
                    
                    # If we have a target, try executing it
                    if target_base and poc.get("endpoint"):
                        should_exec = Confirm.ask("Execute this PoC?", default=False)
                        if should_exec:
                            success, evidence, winning = await exploiter.execute_with_retry(target_base, poc)
                            if success:
                                console.print("[bold green]✓ PoC execution SUCCEEDED![/bold green]")
                                console.print(f"  Evidence: {evidence.get('indicator_found', 'N/A')}")
                            else:
                                console.print("[red]✗ PoC execution failed.[/red]")
                    
                    from sqlalchemy import select
                    pattern = finding.code_snippet or finding.url or finding.title
                    existing = await session.execute(
                        select(AgentLearning).where(AgentLearning.pattern_context == pattern)
                    )
                    if not existing.scalars().first():
                        learning = AgentLearning(
                            pattern_context=pattern,
                            outcome_notes=f"Successful PoC for {finding.title}:\n{poc_display}",
                            is_false_positive=0
                        )
                        session.add(learning)

    async def _interactive_deep_dive(self, findings: List[Finding]) -> None:
        idx = int(Prompt.ask("Finding number to deep-dive", default="1")) - 1
        if 0 <= idx < len(findings):
            finding = findings[idx]
            if finding.file_path and finding.code_snippet:
                async with get_session() as session:
                    planner = LLMPlanner(self.config, session)
                    analyzer = LLMAnalyzer(self.config, session)
                    
                    hypotheses = await planner.plan("[]", finding.code_snippet, "")
                    for hyp in hypotheses:
                        analysis = await analyzer.analyze(finding.code_snippet, hyp)
                        if analysis.get("is_vulnerable"):
                            self.log_info(f"Deep-dive confirmed vulnerability: {hyp['type']}")
                            # Further logic could go here to emit a new finding

    async def _interactive_mark_fp(self, findings: List[Finding]) -> None:
        idx = int(Prompt.ask("Finding number to mark false-positive", default="1")) - 1
        if 0 <= idx < len(findings):
            finding = findings[idx]
            finding.false_positive = 1
            console.print(f"[yellow]Marked finding #{idx+1} as false-positive.[/yellow]")
            
            async with get_session() as session:
                from sqlalchemy import select
                pattern = finding.code_snippet or finding.url or finding.title
                existing = await session.execute(
                    select(AgentLearning).where(AgentLearning.pattern_context == pattern)
                )
                if not existing.scalars().first():
                    learning = AgentLearning(
                        pattern_context=pattern,
                        outcome_notes=f"Marked as False Positive by user interaction.",
                        is_false_positive=1
                    )
                    session.add(learning)

    # ─── Finalization ─────────────────────────────────────────────────

    async def _finalize_scan(
        self,
        cancelled: bool = False,
        failure_message: Optional[str] = None,
    ) -> None:
        """Update scan status, print summary, generate reports."""
        async with get_session() as session:
            scan = await session.get(Scan, self.scan_id)
            if scan:
                if failure_message:
                    scan.status = ScanStatus.FAILED
                    scan.notes = failure_message
                else:
                    scan.status = ScanStatus.PAUSED if cancelled else ScanStatus.COMPLETED
                scan.finished_at = datetime.utcnow()
                await session.commit()

        if failure_message:
            self._emit_event("scan_failed", failure_message, error=failure_message, finding_count=len(self.all_findings))
            return

        self._print_final_summary()
        report_paths = await self._generate_reports() or []
        self._emit_event(
            "scan_completed",
            "Scan completed successfully.",
            cancelled=cancelled,
            finding_count=len(self.all_findings),
            report_paths=report_paths,
        )

    def _print_final_summary(self) -> None:
        real = [f for f in self.all_findings if not f.false_positive]
        console.rule("[bold green]Scan Complete[/bold green]")

        table = Table(title="Finding Severity Breakdown", show_header=True, header_style="bold cyan")
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")

        for sev in Severity:
            count = sum(1 for f in real if f.severity == sev)
            if count:
                table.add_row(
                    f"{sev.value.upper()}",
                    str(count),
                    style=_SEV_STYLE.get(sev, "white"),
                )

        table.add_row("TOTAL", str(len(real)), style="bold")
        console.print(table)

        trust = summarize_trust(real)
        trust_table = Table(title="Finding Trust Breakdown", show_header=True, header_style="bold cyan")
        trust_table.add_column("Tier", style="bold")
        trust_table.add_column("Count", justify="right")
        trust_table.add_row("VERIFIED", str(trust.get("verified", 0)), style="green")
        trust_table.add_row("STRONG", str(trust.get("strong", 0)), style="cyan")
        trust_table.add_row("MODERATE", str(trust.get("moderate", 0)), style="yellow")
        trust_table.add_row("WEAK", str(trust.get("weak", 0)), style="red")
        console.print(trust_table)

    async def _generate_reports(self) -> List[str]:
        gen = ReportGenerator(self.config)
        real = [f for f in self.all_findings if not f.false_positive]
        async with get_session() as session:
            scan = await session.get(Scan, self.scan_id)
            paths = await gen.generate(scan, real)
        for p in paths:
            console.print(f"[green]📄 Report saved:[/green] {p}")

    # ─── Helpers ──────────────────────────────────────────────────────

    _VULN_CATEGORY_MAP = {
        "sql injection": FindingCategory.SQL_INJECTION,
        "sqli": FindingCategory.SQL_INJECTION,
        "command injection": FindingCategory.COMMAND_INJECTION,
        "cmd injection": FindingCategory.COMMAND_INJECTION,
        "rce": FindingCategory.COMMAND_INJECTION,
        "xss": FindingCategory.XSS,
        "cross-site scripting": FindingCategory.XSS,
        "reflected xss": FindingCategory.XSS,
        "stored xss": FindingCategory.XSS,
        "ssrf": FindingCategory.SSRF,
        "server-side request forgery": FindingCategory.SSRF,
        "csrf": FindingCategory.CSRF,
        "ssti": FindingCategory.SSTI,
        "server-side template injection": FindingCategory.SSTI,
        "lfi": FindingCategory.PATH_TRAVERSAL,
        "local file inclusion": FindingCategory.PATH_TRAVERSAL,
        "path traversal": FindingCategory.PATH_TRAVERSAL,
        "directory traversal": FindingCategory.PATH_TRAVERSAL,
        "xxe": FindingCategory.XXE,
        "auth bypass": FindingCategory.AUTH_BYPASS,
        "authentication bypass": FindingCategory.AUTH_BYPASS,
        "broken access": FindingCategory.BROKEN_ACCESS,
        "idor": FindingCategory.BROKEN_ACCESS,
        "open redirect": FindingCategory.OPEN_REDIRECT,
        "deserialization": FindingCategory.DESERIALIZATION,
        "insecure deserialization": FindingCategory.DESERIALIZATION,
        "hardcoded credentials": FindingCategory.HARDCODED_CREDS,
        "hardcoded creds": FindingCategory.HARDCODED_CREDS,
        "sensitive exposure": FindingCategory.SENSITIVE_EXPOSURE,
        "information disclosure": FindingCategory.SENSITIVE_EXPOSURE,
        "weak crypto": FindingCategory.WEAK_CRYPTO,
        "misconfiguration": FindingCategory.MISCONFIGURATION,
        "buffer overflow": FindingCategory.BUFFER_OVERFLOW,
        "race condition": FindingCategory.RACE_CONDITION,
        "privilege escalation": FindingCategory.PRIVILEGE_ESCALATION,
    }

    def _map_vuln_category(self, vuln_type: str) -> FindingCategory:
        """Map a free-text vulnerability type string to a FindingCategory enum."""
        if not vuln_type:
            return FindingCategory.OTHER
        
        text = vuln_type.strip().lower()
        
        # Direct match
        if text in self._VULN_CATEGORY_MAP:
            return self._VULN_CATEGORY_MAP[text]
        
        # Try enum value match
        try:
            return FindingCategory(text)
        except ValueError:
            pass
        
        # Fuzzy match
        for key, cat in self._VULN_CATEGORY_MAP.items():
            if key in text or text in key:
                return cat
        
        return FindingCategory.OTHER

    def _detect_target_types(self, target: str) -> List[str]:
        types = []
        if target.startswith(("http://", "https://")):
            types.extend(["web", "network"])
        elif Path(target).exists():
            types.append("code")
        elif re.match(r"^(\d{1,3}\.){3}\d{1,3}$", target):
            types.append("network")
        else:
            types.extend(["code", "web", "network"])
        return types

    def _prioritize_endpoints(self) -> None:
        """Rank endpoints by risk scores (Layer 2 Prioritization)."""
        if not self.endpoints:
            return
            
        # Prioritize based on EndpointType risk weights
        # CONSOLE > COMMAND > AUTH > FILE > SEARCH > REST > GENERAL
        weights = {
            "console": 10.0,
            "command": 8.0,
            "auth": 7.0,
            "file": 6.0,
            "search": 5.0,
            "rest": 3.0,
            "general": 1.0
        }
        
        for ep in self.endpoints:
            from core.discovery.asset_modeler import Endpoint
            if isinstance(ep, Endpoint):
                ep.risk_score = weights.get(ep.type.value, 1.0)
                # Boost if params exist
                if ep.params: ep.risk_score += 2.0
        
        # Sort in-place
        self.endpoints.sort(key=lambda x: getattr(x, 'risk_score', 0), reverse=True)
        top_asset = self.endpoints[0].path if hasattr(self.endpoints[0], "path") else self.endpoints[0].get("path", "?")
        self.log_info(f"Prioritized attack surface: top asset is {top_asset}")

    def _print_findings_summary(self, findings: List[Finding], phase: str) -> None:
        console.print(
            f"\n[bold]  {phase} found {len(findings)} issue(s)[/bold]"
        )
        # Bug Fix: Extract values early to avoid DetachedInstanceError
        try:
            crits = sum(1 for f in findings if f.severity == Severity.CRITICAL)
            highs = sum(1 for f in findings if f.severity == Severity.HIGH)
            if crits:
                console.print(f"  [bold red]🔴 {crits} CRITICAL[/bold red]")
            if highs:
                console.print(f"  [red]🟠 {highs} HIGH[/red]")
        except Exception:
             # Fallback if findings are somehow still detached
             pass

import re
