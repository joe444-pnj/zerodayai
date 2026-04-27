"""
agents/fuzzer/http_fuzzer.py — HTTP Web Application Fuzzer

Crawls web targets and fuzzes endpoints with generated payloads.
Detects reflections, errors, anomalies, and security header issues.
"""
from __future__ import annotations

import asyncio
import re
import time
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlencode, urljoin, urlparse, urlunsplit, parse_qs, urlunparse

import uuid
import json
import httpx
from bs4 import BeautifulSoup
from rich.console import Console

from agents.fuzzer.mutation import (
    BOUNDARY_STRINGS,
    encode_variants,
    generate_cmd_injection,
    generate_lfi,
    generate_sqli,
    generate_ssrf,
    generate_ssti,
    generate_xss,
)
from core.discovery.asset_modeler import AttackSurface, Endpoint, EndpointType, SurfaceClassifier

try:
    from agents.fuzzer.oob_server import OOBDetector
    OOB_AVAILABLE = True
except ImportError:
    OOB_AVAILABLE = False

console = Console()

# Security headers that MUST be present
REQUIRED_SECURITY_HEADERS = {
    "Strict-Transport-Security": "Missing HSTS header",
    "X-Content-Type-Options":   "Missing X-Content-Type-Options (MIME-sniffing)",
    "X-Frame-Options":          "Missing X-Frame-Options (clickjacking risk)",
    "Content-Security-Policy":  "Missing Content-Security-Policy (XSS risk)",
    "X-XSS-Protection":        "Missing X-XSS-Protection header",
    "Referrer-Policy":          "Missing Referrer-Policy header",
    "Permissions-Policy":       "Missing Permissions-Policy header",
}

# Headers that SHOULD NOT be present (info disclosure)
DISCLOSURE_HEADERS = {
    "Server", "X-Powered-By", "X-AspNet-Version",
    "X-AspNetMvc-Version", "X-Generator", "Via",
}

# Error signatures that indicate successful injection
ERROR_PATTERNS = [
    # SQL errors
    (re.compile(r"(SQL syntax|mysql_fetch|ORA-\d+|SQLiteException|pg_query|"
                r"SQLSTATE|Microsoft OLE DB|Unclosed quotation|Incorrect syntax|MariaDB|PostgreSQL|JDBC Driver)", re.I),
     "sql_injection", "SQL Error Detected — Possible SQLi"),
    # PHP errors
    (re.compile(r"(Fatal error:|Warning:|Parse error:|Notice:)\s+.{0,200}(in|on line)", re.I),
     "sensitive_exposure", "PHP Error Disclosure"),
    # Stack traces
    (re.compile(r"(Traceback \(most recent|at [\w$\.]+\([\w]+\.java:\d+\)|"
                r"System\.NullReferenceException|at [\w\.]+\([\w\.]+\:\d+\))", re.I),
     "sensitive_exposure", "Stack Trace Disclosure"),
    # SSTI
    (re.compile(r"\b49\b"), "ssti", "Possible SSTI — Expression Evaluated (7*7=49)"),
    # Path disclosure
    (re.compile(r"(C:\\|/var/www|/home/\w+|/usr/local|/opt/|/etc/passwd|/etc/shadow|C:\\Windows\\)", re.I),
     "path_traversal", "Sensitive File/Path Disclosure"),
    # XML errors (XXE indicator)
    (re.compile(r"(XML\s+(?:parsing|parser)\s+error|ENTITY\s+['\"]|<!ENTITY|external\s+entity|entity\s+expansion|DTD\s+validation\s+error)", re.I),
     "xxe", "XML Entity Processing — Possible XXE"),
    # LFI
    (re.compile(r"root:x:0:0:|\[boot loader\]", re.I), "lfi", "Confirmed LFI — Sensitive File Read"),
    # Command Injection
    (re.compile(r"uid=\d+\(\w+\) gid=\d+\(\w+\)|Volume Serial Number is", re.I), "cmd_injection", "Confirmed RCE — Command Output Detected"),
]


class HTTPFuzzer:
    """Asynchronous HTTP fuzzer for web application vulnerability discovery."""

    def __init__(self, config):
        self.config = config
        fc = self.config.fuzzer
        self._findings = []
        self._on_finding = None
        self._visited = set()
        self._request_count = 0
        self._seen_finding_keys = set()
        self._base_url = None
        self._baseline_times = {} # Path -> average response time
        self._sem = asyncio.Semaphore(fc.concurrency)
        self._http = httpx.AsyncClient(
            verify=fc.verify_ssl,
            follow_redirects=fc.follow_redirects,
            headers={"User-Agent": fc.user_agent},
        )
        # OOB (blind vulnerability) detection
        self._oob: Optional[OOBDetector] = None
        oob_cfg = getattr(fc, 'oob', None)
        if OOB_AVAILABLE and oob_cfg and getattr(oob_cfg, 'enabled', False):
            self._oob = OOBDetector(config)

    async def _probe_sinks(self, path: str, method: str, params: List[str]) -> Dict[str, str]:
        """Probes parameters with a canary to identify 'hot' sinks before fuzzing."""
        sinks = {}
        target_url = urljoin(self._base_url, path)
        
        for param in params:
            canary = f"ZD_CANARY_{uuid.uuid4().hex[:6]}"
            payload_data = {param: canary}
            
            try:
                start = time.monotonic()
                if method.upper() == "POST":
                    resp = await self._http.post(target_url, data=payload_data, timeout=5)
                else:
                    resp = await self._http.get(target_url, params=payload_data, timeout=5)
                elapsed = time.monotonic() - start
                
                # Check for Reflection
                if canary in resp.text:
                    sinks[param] = "reflection"
                # Check for Behavioral change (Time or Status)
                elif elapsed > (self._baseline_times.get(path, 0.5) + 1.0) or resp.status_code >= 500:
                    sinks[param] = "behavioral"
                else:
                    sinks[param] = "none"
                    
            except Exception:
                continue
                
        return sinks

    async def close(self) -> None:
        await self._http.aclose()

    # ─── Main Entry ───────────────────────────────────────────────────

    async def discover(self, base_url: str) -> List[Dict]:
        """Discovery phase: map endpoints and analyze baseline."""
        self._base_url = base_url
        console.print(f"[cyan]  → Discovering structure of[/cyan] [bold]{base_url}[/bold]")
        await self._analyze_base_response(base_url)
        
        # Capture baseline timing
        self._baseline_times["/"] = await self._measure_baseline(base_url)
        
        # 1. Passive Crawl
        endpoints = await self.crawl(base_url, depth=self.config.fuzzer.crawl_depth)
        
        # 2. Active Attack Surface Discovery (Guesser)
        from core.discovery.endpoint_guesser import EndpointGuesser
        guesser = EndpointGuesser(self.config)
        console.print(f"  [cyan]→ Active probing: guessing hidden endpoints and params...[/cyan]")
        guessed = await guesser.guess_all(base_url)
        
        # Merge Crawled + Guessed
        surface = AttackSurface(base_url)
        path_map = {}
        
        # Helper to merge items into path_map
        all_raw = endpoints + guessed
        for item in all_raw:
            p = item["path"]
            if p not in path_map:
                path_map[p] = {"params": set(), "method": "GET"}
            path_map[p]["params"].update(item.get("params", []))
            if item.get("method") == "POST":
                path_map[p]["method"] = "POST"
        
        for path, data in path_map.items():
            surface.add_endpoint(path, method=data["method"], params=list(data["params"]))

        # Layer 2: Classify Surface
        SurfaceClassifier.classify_all(surface)
        return surface.endpoints

    async def _measure_baseline(self, url: str, count: int = 3) -> float:
        """Measure average response time for an endpoint (Hardened)."""
        times = []
        for _ in range(count):
            try:
                start = time.monotonic()
                # Use a small timeout for baseline to not block discovery if target is slow
                await self._http.get(url, timeout=5)
                times.append(time.monotonic() - start)
            except Exception:
                continue
        
        # Fallback to a safe 0.5s if measurement fails entirely
        return sum(times) / len(times) if times else 0.5

    async def scan(
        self,
        base_url: str,
        on_finding: Optional[callable] = None,
        interactive_ask: Optional[callable] = None,
    ) -> List[Dict]:
        """Crawl and fuzz a web target. Returns list of finding dicts."""
        self._on_finding = on_finding
        self._interactive_ask = interactive_ask

        console.print(f"[cyan]  → Starting HTTP scan on[/cyan] [bold]{base_url}[/bold]")

        # Phase 1: Baseline request + header analysis
        await self._analyze_base_response(base_url)

        # Phase 2: Crawl to discover endpoints
        endpoints = await self.discover(base_url)
        console.print(f"  [dim]Discovered {len(endpoints)} endpoint(s) through crawl and active probing[/dim]")

        # Phase 3: Fuzz each endpoint
        tasks = [self._fuzz_endpoint(ep) for ep in list(endpoints)[:50]]
        await asyncio.gather(*tasks, return_exceptions=True)

        # Phase 4: Check OOB callbacks (blind vulnerability detection)
        if self._oob:
            blind_findings = await self._oob.check_callbacks(wait_seconds=8)
            for bf in blind_findings:
                self._add_finding(
                    url=bf["endpoint"],
                    title=f"Confirmed Blind {bf['vuln_type'].upper()} (OOB)",
                    category=bf["vuln_type"],
                    severity="critical",
                    description=(
                        f"Blind {bf['vuln_type']} confirmed via Out-of-Band callback.\n"
                        f"Parameter: {bf['param']}\n"
                        f"Callback received from: {bf['remote_address']} via {bf['protocol']}\n"
                        f"This is a CONFIRMED vulnerability — the server made an outbound request."
                    ),
                    parameter=bf["param"],
                    payload=bf["payload"],
                    confidence=0.98,
                )

        return self._findings

    # ─── Baseline Analysis ────────────────────────────────────────────

    async def _analyze_base_response(self, url: str) -> None:
        """Check security headers, cookies, and baseline response."""
        try:
            resp = await self._http.get(url)
        except Exception as e:
            console.print(f"  [red]Connection failed: {e}[/red]")
            return

        headers = resp.headers

        # ── Missing security headers ──────────────────────────
        for header, msg in REQUIRED_SECURITY_HEADERS.items():
            if header.lower() not in {k.lower() for k in headers}:
                self._add_finding(
                    url=url, title=msg,
                    category="misconfiguration", severity="low",
                    description=f"The response is missing the '{header}' security header.",
                    remediation=f"Add the '{header}' HTTP response header.",
                )

        # ── Info disclosure headers ───────────────────────────
        for h in DISCLOSURE_HEADERS:
            if val := headers.get(h):
                self._add_finding(
                    url=url,
                    title=f"Server Information Disclosure via {h}",
                    category="sensitive_exposure", severity="info",
                    description=f"Header '{h}: {val}' reveals server technology.",
                    remediation=f"Remove or obscure the '{h}' header.",
                )

        # ── Insecure cookies ─────────────────────────────────
        for cookie in resp.cookies.jar:
            issues = []
            if not cookie.secure:
                issues.append("missing Secure flag")
            if not cookie.has_nonstandard_attr("httponly"):
                issues.append("missing HttpOnly flag")
            if not cookie.has_nonstandard_attr("samesite"):
                issues.append("missing SameSite attribute")
            if issues:
                self._add_finding(
                    url=url,
                    title=f"Insecure Cookie: {cookie.name}",
                    category="auth_bypass", severity="medium",
                    description=f"Cookie '{cookie.name}' has: {', '.join(issues)}.",
                    remediation="Set Secure, HttpOnly, and SameSite=Strict on all cookies.",
                )

        # ── CORS check ────────────────────────────────────────
        acao = headers.get("Access-Control-Allow-Origin", "")
        if acao == "*":
            self._add_finding(
                url=url,
                title="Overly Permissive CORS Policy",
                category="broken_access", severity="medium",
                description="Access-Control-Allow-Origin: * allows any origin to read responses.",
                remediation="Restrict CORS to specific trusted origins.",
            )

        # ── Content body analysis ─────────────────────────────
        await self._check_response_errors(url, resp.text, {})

    # ─── Crawler ──────────────────────────────────────────────────────

    async def crawl(self, base_url: str, depth: int) -> List[Dict]:
        """BFS crawler that discovers URLs and form endpoints with structure."""
        from collections import deque
        parsed_base = urlparse(base_url)
        base_domain = parsed_base.netloc

        queue: deque = deque([(base_url, 0)])
        discovered_paths: Set[str] = {base_url}
        endpoints: List[Dict] = []

        # Add base URL as a GET endpoint
        endpoints.append({
            "path": base_url,
            "method": "GET",
            "params": list(parse_qs(parsed_base.query).keys())
        })

        while queue:
            url, current_depth = queue.popleft()

            if url in self._visited or current_depth > depth:
                continue
            self._visited.add(url)

            try:
                async with self._sem:
                    resp = await self._http.get(url, timeout=10)
            except Exception:
                continue

            if "text/html" not in resp.headers.get("Content-Type", ""):
                continue

            soup = BeautifulSoup(resp.text, "html.parser")

            # Extract links
            for tag in soup.find_all("a", href=True):
                href = urljoin(url, tag["href"]).split("#")[0]
                parsed = urlparse(href)
                if parsed.netloc == base_domain:
                    if href not in discovered_paths:
                        discovered_paths.add(href)
                        endpoints.append({
                            "path": href,
                            "method": "GET",
                            "params": list(parse_qs(parsed.query).keys())
                        })
                        if current_depth + 1 <= depth:
                            queue.append((href, current_depth + 1))

            # Extract forms (The structured part)
            for form in soup.find_all("form"):
                action = urljoin(url, form.get("action") or url)
                method = form.get("method", "GET").upper()
                params = []
                for input_tag in form.find_all(["input", "textarea", "select"]):
                    name = input_tag.get("name")
                    if name:
                        params.append(name)
                
                if action not in discovered_paths:
                    discovered_paths.add(action)
                    endpoints.append({
                        "path": action,
                        "method": method,
                        "params": params
                    })

            # Extract API endpoints from scripts
            for script_url in re.findall(
                r'(?:fetch|axios\.get|axios\.post|http\.get|http\.post)\(["\']([^"\']+)["\']',
                resp.text
            ):
                full = urljoin(url, script_url)
                if urlparse(full).netloc == base_domain:
                    if full not in discovered_paths:
                        discovered_paths.add(full)
                        endpoints.append({
                            "path": full,
                            "method": "UNKNOWN",
                            "params": []
                        })

        return endpoints

    # ─── Success Verification ────────────────────────────────────────
    
    def is_success(self, response: httpx.Response, expected_behavior: str = "") -> bool:
        """Centralized success detection fingerprinting."""
        text = response.text.lower()
        code = response.status_code
        expected = (expected_behavior or "").lower()

        # 1. Behavioral: Time-based (handled externally by measurement comparison)
        
        # 2. Logic: Status & Keywords
        if code == 200:
             if any(x in text for x in ["success", "access granted", "welcome", "admin dashboard"]):
                 return True

        # 3. Identifiers: Shell & OS
        if any(x in text for x in ["uid=", "root:x:0:0", "bash:", "/usr/bin/", "system32", "drwxr-xr-x"]):
            return True

        # 4. Indicators: Database & Errors
        if any(x in text for x in ["mysql error", "sqlite error", "sqlstate", "syntax error near"]):
            return True
        
        # 5. Fingerprints: Special Consoles
        if any(x in text for x in ["__debugger__", "console_pin", "console.html", "Werkzeug", "Django Debug"]):
            return True

        # 6. Specific Contexts (Auth/Login)
        if code == 200 and "admin" in text:
            if expected and any(x in expected for x in ["auth", "login", "admin"]):
                 return True

        if expected and ("lfi" in expected or "/etc/passwd" in expected):
            if "root:x:0:0" in text:
                return True
        
        # 7. Generic Match
        if expected and expected in text:
            return True

        return False

    # ─── Endpoint Fuzzing ─────────────────────────────────────────────

    async def fuzz_guided(
        self,
        url: str,
        param_name: str,
        payloads: List[str],
        vuln_type: str = "custom",
    ) -> List[Dict]:
        """Fuzz a specific parameter with a provided list of payloads."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            params = {param_name: ["1"]}
        
        # Convert parse_qs result to flat dict
        base_data = {k: v[0] for k, v in params.items()}
        if param_name not in base_data:
            base_data[param_name] = "test"
            
        results = []
        for payload in payloads:
            if self._stopped_check():
                break
                
            fuzzed_data = dict(base_data)
            fuzzed_data[param_name] = payload
            
            await self._send_probe(url, fuzzed_data, vuln_type)
            
            # Find the finding we just added (if any)
            if self._findings:
                results.append(self._findings[-1])
            self._request_count += 1
            await asyncio.sleep(0.05)
        
        return results

    async def _fuzz_endpoint(self, ep: Endpoint) -> None:
        """Fuzz a single classified endpoint using targeted strategies."""
        path = ep.path
        method = ep.method
        discovered_params = ep.params
        ep_type = ep.type

        # Step 5: Guard - Skip parameterless endpoints unless console/high-risk
        if not discovered_params and ep_type not in [EndpointType.CONSOLE, EndpointType.COMMAND]:
            return

        # Filter parameters to fuzz
        interesting_params = ["id", "query", "q", "cmd", "exec", "file", "path", "user", "username", "pass", "token", "key"]
        params_to_fuzz = [p for p in discovered_params if p.lower() in interesting_params]
        if not params_to_fuzz:
             params_to_fuzz = list(discovered_params)[:5]

        # Stage 1: Sink Discovery (Canary Pass)
        # We send a harmless canary to find which params are actually processed/rendered
        sinks = await self._probe_sinks(path, method, params_to_fuzz)
        
        base_params = {p: "test" for p in discovered_params}
        
        # Strategy Mapping
        STRATEGIES = {
            EndpointType.COMMAND: ["cmd_injection", "ssrf"],
            EndpointType.FILE: ["lfi", "ssrf"],
            EndpointType.AUTH: ["sqli"],
            EndpointType.SEARCH: ["sqli", "xss", "ssti"],
            EndpointType.REST: ["sqli", "xss"],
            EndpointType.CONSOLE: ["cmd_injection", "ssti"],
            EndpointType.GENERAL: ["xss", "lfi"]
        }
        
        target_vulns = STRATEGIES.get(ep_type, ["xss", "sqli"])
        console.print(f"  [cyan]→ Strategy: {', '.join(target_vulns).upper()} for {ep_type.value} {path}[/cyan]")

        for param_name in params_to_fuzz:
            # Stage 2: Sink-Aware Payload Selection
            sink_type = sinks.get(param_name, "none")
            
            # Map sink behaviors to attack types
            relevant_classes = []
            if sink_type == "reflection":
                relevant_classes = ["xss", "ssti", "sqli"] # sqli-error reflection
            elif sink_type == "behavioral":
                relevant_classes = ["cmd_injection", "lfi", "sqli", "ssrf"] # Logic/Time sinks
            else:
                # If no sink detected, don't label as success unless proven
                relevant_classes = ["xss", "sqli"] # Default fallback

            # Intersect strategy with discovered sinks
            final_vulns = [v for v in target_vulns if v in relevant_classes]
            if not final_vulns and ep_type in [EndpointType.CONSOLE, EndpointType.COMMAND]:
                final_vulns = target_vulns # Force attack for high-risk types
                
            if not final_vulns:
                continue

            console.print(f"  [cyan]→ Probing Sink: {sink_type.upper()} for {param_name}[/cyan]")

            for vuln_type in final_vulns:
                if self._stopped_check(): return
                
                original = "test"
                gen = []
                if vuln_type == "sqli": gen = generate_sqli(original)
                elif vuln_type == "xss": gen = generate_xss(original)
                elif vuln_type == "ssrf": gen = generate_ssrf(original)
                elif vuln_type == "ssti": gen = generate_ssti(original)
                elif vuln_type == "lfi": gen = generate_lfi(original)
                elif vuln_type == "cmd_injection": gen = generate_cmd_injection(original)
                count = 0
                for payload in gen:
                    if count >= self.config.fuzzer.max_payloads_per_type:
                        break
                    if self._stopped_check():
                        return
                    
                    # Step 1 & 3: Multi-param payload builder
                    fuzzed_data = dict(base_params)
                    fuzzed_data[param_name] = payload
                    
                    await self._send_probe(path, fuzzed_data, vuln_type, method=method)
                    count += 1
                    self._request_count += 1
                    await asyncio.sleep(0.05)

            # ── Blind/OOB payloads (if OOB detector is active) ──
            if self._oob and self._oob._oob_domain:
                blind_payloads = self._oob.generate_blind_payloads(
                    vuln_type=vuln_type, endpoint=path, param=param_name
                )
                for bp in blind_payloads[:5]:  # Max 5 blind payloads per type
                    if self._stopped_check():
                        return
                    fuzzed_data = dict(base_params)
                    fuzzed_data[param_name] = bp["payload"]
                    await self._send_probe(path, fuzzed_data, vuln_type, method=method)
                    self._request_count += 1
                    await asyncio.sleep(0.05)

    async def _send_probe(
        self,
        path: str,
        fuzzed_data: Dict,
        vuln_type: str,
        method: str = "GET"
    ) -> None:
        """Send a single fuzzed request (GET or POST) and analyze the response."""
        url = urljoin(self._base_url, path)
        
        # Measure baseline if new path
        if path not in self._baseline_times:
            self._baseline_times[path] = await self._measure_baseline(url)

        try:
            async with self._sem:
                start = time.monotonic()
                if method.upper() == "POST":
                    resp = await self._http.post(url, data=fuzzed_data)
                    fuzzed_url = url
                else:
                    resp = await self._http.get(url, params=fuzzed_data)
                    fuzzed_url = str(resp.request.url)

                elapsed = time.monotonic() - start
                
                # Context for analysis
                # We assume only ONE param is fuzzed at a time in the current loop
                # Let's find it (it's the one that causes the fuzzed_data to match a payload)
                # Actually, pass it explicitly if possible, but for now we'll guess or just analyze
                await self._analyze_response_v2(resp, fuzzed_url, fuzzed_data, vuln_type, elapsed, path)
        except Exception:
            return

    async def _analyze_response_v2(self, resp, url, fuzzed_data, vuln_type, elapsed, path):
        """Tiered validation: Layer 6 Evidence Validator (Diffing)."""
        # Get the payload used
        payload = ""
        param = ""
        for k, v in fuzzed_data.items():
             if v != "test":
                 param = k
                 payload = v
                 break

        confidence = 0.3
        baseline_time = self._baseline_times.get(path, 0.5)

        # 1. Evidence: Behavioral Time-based (Proves heavy processing/Sleep)
        if elapsed > (baseline_time + 4.5):
            confidence = 1.0
            self._add_finding(
                url=url, title=f"Verified Time-Based {vuln_type.upper()}",
                category=vuln_type, severity="high",
                description=f"Empirical Proof: Timing delay detected ({elapsed:.2f}s vs baseline {baseline_time:.2f}s).",
                parameter=param, payload=payload, confidence=confidence
            )
            return

        # 2. Evidence: Response Diffing (Structure Change)
        # We look for successful fingerprints and diffs from baseline
        if self.is_success(resp, vuln_type):
            confidence = 0.9
            severity = "high"
            title = f"Verified {vuln_type.upper()} success"
            
            if any(x in resp.text for x in ["__debugger__", "Werkzeug", "console_pin"]):
                severity = "critical"
                title = "Exposed Debug Console"
                confidence = 1.0

            self._add_finding(
                url=url, title=title, category=vuln_type, severity=severity,
                description=f"Empirical Proof: Positive fingerprint detected for {vuln_type} in response body.",
                parameter=param, payload=payload, confidence=confidence
            )
            return

        # 3. Evidence: Reflection Detection
        if payload and payload in resp.text:
            confidence = 0.7
            if vuln_type == "xss":
                confidence = 0.9
                self._add_finding(
                    url=url, title="Reflected XSS",
                    category="xss", severity="high",
                    description=f"Empirical Proof: Payload reflected unescaped in response: {payload[:80]}",
                    parameter=param, payload=payload, confidence=confidence
                )
                return

        # 4. Evidence: Error Analysis (Hypothesis only)
        for pattern, category, title in ERROR_PATTERNS:
            if pattern.search(resp.text):
                # We normalize confidence here (Layer 7) - Errors alone are only ~0.5 confidence
                self._add_finding(
                    url=url, title=title, category=category,
                    severity="high" if category == "sql_injection" else "medium",
                    description=f"Heuristic Proof: Anomalous error pattern suggests {vuln_type} vulnerability.",
                    parameter=param, payload=payload, confidence=0.5
                )
                return

    # ─── Response Analysis ────────────────────────────────────────────

    async def _check_response_errors(
        self, url: str, body: str, context: Dict
    ) -> None:
        for pattern, category, title in ERROR_PATTERNS:
            if pattern.search(body):
                param = context.get("param", "")
                payload = context.get("payload", "")
                self._add_finding(
                    url=url, title=title, category=category,
                    severity="high" if category == "sql_injection" else "medium",
                    description=(
                        f"Error pattern detected in response body.\n"
                        f"Param: {param}, Payload: {payload[:80]}"
                    ),
                    parameter=param, payload=payload,
                    remediation="Suppress detailed error messages in production.",
                )
                break  # One finding per response

    # ─── Finding Helpers ──────────────────────────────────────────────

    def _add_finding(self, url: str, title: str, category: str, severity: str,
                     description: str = "", parameter: str = "",
                     payload: str = "", poc: str = "", remediation: str = "",
                     confidence: float = 0.8) -> None:
        # Dedup by (endpoint_path + category) — prevents 6x "Exposed Debug Console"
        from urllib.parse import urlparse
        path = urlparse(url).path if url else ""
        dedup_key = f"{path}||{category}"
        if dedup_key in self._seen_finding_keys:
            return
        self._seen_finding_keys.add(dedup_key)

        finding = {
            "url": url, "title": title, "category": category,
            "severity": severity, "description": description,
            "parameter": parameter, "payload": payload,
            "poc": poc, "remediation": remediation,
            "confidence": confidence
        }
        self._findings.append(finding)
        if self._on_finding:
            self._on_finding(finding)

    def _stopped_check(self) -> bool:
        return self._request_count > self.config.fuzzer.max_requests_per_endpoint * 50
