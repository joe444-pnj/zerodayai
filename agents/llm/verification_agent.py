"""
agents/llm/verification_agent.py — Multi-Vector Verification Agent

After a vulnerability is initially found, this agent re-tests it with:
  1. Different payloads (separator swaps, alternative commands)
  2. Different encodings (URL-encode, double-encode, base64)
  3. Different HTTP methods (GET ↔ POST)

If ≥2 out of N variants succeed → CONFIRMED REAL
If 0 succeed → UNVERIFIED (not false positive, just unconfirmed)
"""

from __future__ import annotations

import json
import hashlib
from typing import Dict, List, Optional, Tuple
from urllib.parse import quote

import httpx
from rich.console import Console

from agents.base import BaseAgent
from agents.llm.ollama_client import OllamaClient
from core.models import AgentType, Finding
from core.utils.url import normalize_url, build_exploit_url, is_valid_url

console = Console()


class VerificationAgent(BaseAgent):
    """Re-tests findings with multiple payload variants to confirm or reject."""

    agent_type = AgentType.LLM

    def __init__(self, config, session=None):
        super().__init__(config, session)
        self.ollama = OllamaClient(
            host=config.ollama.host,
            model=config.ollama.model,
            timeout=config.ollama.timeout,
            temperature=config.ollama.temperature,
        )

    async def execute(self, scan_id: str, target: str, **kwargs) -> None:
        pass

    async def verify_finding(
        self,
        target_base: str,
        finding: Finding,
        poc: Dict,
        min_confirmations: int = 2,
        max_variants: int = 6,
    ) -> Dict:
        """Re-test a finding with multiple independent verification vectors.
        
        Args:
            target_base: e.g., "http://127.0.0.1:5000"
            finding: The original Finding object
            poc: The structured PoC dict
            min_confirmations: How many variants must succeed to confirm (default: 2)
            max_variants: Maximum number of variants to test
            
        Returns:
            {
                "status": "CONFIRMED" | "UNVERIFIED" | "LIKELY_FALSE_POSITIVE",
                "confirmations": 3,
                "total_tested": 6,
                "successful_variants": [...],
                "failed_variants": [...],
                "evidence_chain": [...]
            }
        """
        console.print(f"\n  [bold cyan]🔬 Verification Agent: Testing {poc.get('name', 'Unknown')} at {poc.get('endpoint', '?')}[/bold cyan]")

        endpoint = poc.get("endpoint", "")
        method = poc.get("method", "GET")
        payload = poc.get("payload", {})
        success_indicator = poc.get("success_indicator", "")

        if not endpoint or not payload:
            return self._make_result("UNVERIFIED", 0, 0, [], [], ["No endpoint or payload to verify"])

        # Generate verification vectors
        variants = self._generate_verification_vectors(payload, method, success_indicator)
        variants = variants[:max_variants]

        confirmations = 0
        successful = []
        failed = []
        evidence_chain = []

        for i, variant in enumerate(variants, 1):
            console.print(f"    [dim]Vector {i}/{len(variants)}: {variant['technique']}[/dim]", end=" ")

            v_payload = variant["payload"]
            v_method = variant.get("method", method)
            v_indicator = variant.get("success_indicator", success_indicator)

            # Apply encoding
            encoding = variant.get("encoding", "none")
            if encoding == "url_encode":
                v_payload = {k: quote(str(v)) for k, v in v_payload.items()}
            elif encoding == "double_url_encode":
                v_payload = {k: quote(quote(str(v))) for k, v in v_payload.items()}

            url, params, data = build_exploit_url(target_base, endpoint, v_method, v_payload)

            if not is_valid_url(url):
                failed.append(variant)
                console.print("[red]✗ Invalid URL[/red]")
                continue

            try:
                async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=10) as client:
                    if v_method.upper() == "POST":
                        resp = await client.post(url, data=data, params=params)
                    else:
                        resp = await client.get(url, params=params)

                    # Check success
                    body = resp.text.lower()
                    success = False
                    indicator_found = ""

                    if v_indicator and v_indicator.lower() in body:
                        success = True
                        indicator_found = v_indicator

                    # Also check generic indicators
                    if not success:
                        success, indicator_found = self._check_indicators(body)

                    if success:
                        confirmations += 1
                        successful.append({
                            **variant,
                            "indicator_found": indicator_found,
                            "status_code": resp.status_code,
                        })
                        evidence_chain.append(f"Vector {i} ({variant['technique']}): CONFIRMED — found '{indicator_found}' in response")
                        console.print("[green]✓[/green]")
                    else:
                        failed.append(variant)
                        evidence_chain.append(f"Vector {i} ({variant['technique']}): FAILED — indicator not in response (status: {resp.status_code})")
                        console.print("[red]✗[/red]")

            except Exception as e:
                failed.append({**variant, "error": str(e)})
                evidence_chain.append(f"Vector {i} ({variant['technique']}): ERROR — {e}")
                console.print(f"[red]✗ {e}[/red]")

        # Determine status
        total = len(variants)
        calculated_confidence = confirmations / total if total > 0 else 0.0
        root_cause = ""

        if confirmations >= min_confirmations:
            status = "CONFIRMED"
            console.print(f"  [bold green]✓ CONFIRMED REAL — ({calculated_confidence:.0%} confidence) {confirmations}/{total} vectors succeeded[/bold green]")
            root_cause = self._generate_root_cause(poc, successful[0])
            console.print(f"  [dim green]Root Cause: {root_cause}[/dim green]")
        elif confirmations > 0:
            status = "LIKELY_REAL"
            console.print(f"  [yellow]⚠ LIKELY REAL — ({calculated_confidence:.0%} confidence) {confirmations}/{total} vectors succeeded (below threshold of {min_confirmations})[/yellow]")
            root_cause = "Pending re-verification. Partial success."
        else:
            status = "UNVERIFIED"
            console.print(f"  [red]✗ UNVERIFIED — 0/{total} vectors succeeded[/red]")
            root_cause = "Not exploitable or heavily filtered."

        return self._make_result(status, confirmations, total, successful, failed, evidence_chain, calculated_confidence, root_cause)

    def _generate_verification_vectors(
        self,
        payload: Dict,
        method: str,
        success_indicator: str,
    ) -> List[Dict]:
        """Generate independent verification vectors for a payload."""
        vectors = []

        for param, value in payload.items():
            if not isinstance(value, str):
                continue

            # ── 1. Separator Variants (for command injection) ────────
            sep_map = {
                "semicolon": ";",
                "double_and": "&&",
                "pipe": "|",
                "double_pipe": "||",
                "newline": "\n",
                "subshell_paren": "$(",
                "backtick": "`",
                "ampersand": "&",
                "null_byte": "%00",
            }
            
            # Find original separator
            for orig_name, orig_sep in sep_map.items():
                if orig_sep in value:
                    # Swap to every other separator
                    for new_name, new_sep in sep_map.items():
                        if new_name != orig_name:
                            new_val = value.replace(orig_sep, f" {new_sep} ", 1).strip()
                            # Handle subshell/backtick differently
                            if new_sep == "$(":
                                # Need to extract the command
                                parts = value.split(orig_sep, 1)
                                if len(parts) == 2:
                                    cmd = parts[1].strip().rstrip(")")
                                    new_val = f"{parts[0].strip()} $({cmd})"
                            elif new_sep == "`":
                                parts = value.split(orig_sep, 1)
                                if len(parts) == 2:
                                    cmd = parts[1].strip().rstrip("`")
                                    new_val = f"{parts[0].strip()} `{cmd}`"
                            
                            vectors.append({
                                "payload": {param: new_val},
                                "method": method,
                                "encoding": "none",
                                "technique": f"sep_{new_name}",
                                "success_indicator": success_indicator,
                            })
                    break

            # ── 2. Alternative Commands ──────────────────────────────
            cmd_alternatives = {
                "id": ["whoami", "uname -a", "echo VerAgent_OK"],
                "whoami": ["id", "uname", "echo VerAgent_OK"],
                "cat /etc/passwd": ["head -1 /etc/passwd", "ls -la /etc/passwd", "echo VerAgent_OK"],
                "dir": ["whoami", "echo VerAgent_OK", "set"],
                "ipconfig": ["hostname", "echo VerAgent_OK", "whoami"],
            }
            
            for orig_cmd, alts in cmd_alternatives.items():
                if orig_cmd in value:
                    for alt_cmd in alts[:2]:
                        vectors.append({
                            "payload": {param: value.replace(orig_cmd, alt_cmd)},
                            "method": method,
                            "encoding": "none",
                            "technique": f"alt_cmd_{alt_cmd.split()[0]}",
                            "success_indicator": "VerAgent_OK" if "echo" in alt_cmd else "",
                        })
                    break

            # ── 3. Encoding Variants ─────────────────────────────────
            vectors.append({
                "payload": {param: value},
                "method": method,
                "encoding": "url_encode",
                "technique": "url_encoding",
                "success_indicator": success_indicator,
            })

            vectors.append({
                "payload": {param: value},
                "method": method,
                "encoding": "double_url_encode",
                "technique": "double_encoding",
                "success_indicator": success_indicator,
            })

            # ── 4. Method Swap (GET ↔ POST) ──────────────────────────
            alt_method = "POST" if method.upper() == "GET" else "GET"
            vectors.append({
                "payload": {param: value},
                "method": alt_method,
                "encoding": "none",
                "technique": f"method_swap_{alt_method}",
                "success_indicator": success_indicator,
            })

        # Deduplicate
        seen = set()
        unique = []
        for v in vectors:
            key = hashlib.md5(f"{v['payload']}_{v['method']}_{v['encoding']}".encode()).hexdigest()
            if key not in seen:
                seen.add(key)
                unique.append(v)

        return unique

    def _check_indicators(self, body: str) -> Tuple[bool, str]:
        """Check for generic success indicators."""
        indicators = [
            ("uid=", "uid="),
            ("root:x:0:0", "root:x:0:0"),
            ("www-data", "www-data"),
            ("VerAgent_OK", "VerAgent_OK"),
            ("__debugger__", "__debugger__"),
            ("werkzeug", "werkzeug"),
            ("[boot loader]", "[boot loader]"),
            ("sqlite error", "sqlite error"),
            ("mysql error", "mysql error"),
            ("sqlstate", "sqlstate"),
            ("syntax error", "syntax error"),
            ("warning: mysql", "mysql warning"),
            ("pg_sleep", "postgres sleep"),
            ("eval\(\) failure", "eval failure"),
            ("division by zero", "division by zero"),
            ("failed to open stream", "php include failure"),
            ("java.io.FileNotFoundException", "java file exception"),
            ("com.mysql.jdbc.exceptions", "mysql jdbc exception"),
            ("org.postgresql.util.PSQLException", "postgres exception"),
        ]
        
        for needle, label in indicators:
            if needle.lower() in body:
                return True, label

        return False, ""

    def _generate_root_cause(self, poc: Dict, successful_variant: Dict) -> str:
        prompt = f"""You are analyzing a CONFIRMED vulnerability. 
Vulnerability: {poc.get('name')} at {poc.get('endpoint')}
Original Payload: {poc.get('payload')}
Successful Variant: {successful_variant.get('payload')}
Evidence: We found '{successful_variant.get('indicator_found')}' in the HTTP response.

Explain exactly WHY this vulnerability exists in 1-2 sentences. 
Do not suggest remediation, just state the root cause (e.g. data flows unsanitized into a dangerous sink).
"""
        return self.ollama.generate(prompt).strip()

    def _make_result(
        self,
        status: str,
        confirmations: int,
        total: int,
        successful: List,
        failed: List,
        evidence_chain: List,
        confidence: float = 0.0,
        root_cause: str = ""
    ) -> Dict:
        return {
            "status": status,
            "confirmations": confirmations,
            "total_tested": total,
            "successful_variants": successful,
            "failed_variants": failed,
            "evidence_chain": evidence_chain,
            "confidence": confidence,
            "root_cause_explanation": root_cause
        }
