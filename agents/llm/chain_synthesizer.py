"""
agents/llm/chain_synthesizer.py — Attack Chain Synthesis Agent

After all agents complete, this agent reasons about multi-step
exploitation chains. Instead of reporting isolated findings, it
connects bugs into realistic attack scenarios.

Example: SQLi on /user + IDOR on /admin + hardcoded JWT secret
  → "Attacker extracts admin credentials via SQLi, forges JWT,
     and accesses admin panel via IDOR for full system compromise."
"""

from __future__ import annotations

import json
from typing import Dict, List, Optional

from rich.console import Console

from agents.llm.ollama_client import OllamaClient
from core.utils.json_sanitizer import sanitize_confidence

console = Console()


# Extended chain patterns for rule-based pre-filtering
KNOWN_CHAIN_PATTERNS = [
    {
        "name": "Debug Console → Remote Code Execution",
        "requires": ["misconfiguration", "command_injection"],
        "impact": "Full server compromise via exposed debug interface",
        "cvss": 10.0,
    },
    {
        "name": "SQL Injection → Data Exfiltration → Account Takeover",
        "requires": ["sql_injection"],
        "optional": ["sensitive_exposure", "auth_bypass"],
        "impact": "Database dump leading to credential theft and unauthorized access",
        "cvss": 9.8,
    },
    {
        "name": "SSRF → Cloud Metadata → Lateral Movement",
        "requires": ["ssrf"],
        "optional": ["sensitive_exposure"],
        "impact": "Cloud credential theft via metadata service, enabling lateral movement",
        "cvss": 9.6,
    },
    {
        "name": "Path Traversal → Credential Theft → Privilege Escalation",
        "requires": ["path_traversal"],
        "optional": ["hardcoded_creds", "sensitive_exposure"],
        "impact": "Reading config files to extract credentials for privilege escalation",
        "cvss": 9.1,
    },
    {
        "name": "XSS → Session Hijacking → Admin Takeover",
        "requires": ["xss"],
        "optional": ["auth_bypass", "broken_access"],
        "impact": "Stealing admin session tokens via XSS to take over privileged accounts",
        "cvss": 8.8,
    },
    {
        "name": "Auth Bypass → IDOR → Mass Data Exposure",
        "requires": ["auth_bypass", "broken_access"],
        "impact": "Bypassing authentication to enumerate and access all user data",
        "cvss": 9.4,
    },
    {
        "name": "SSTI → RCE → Full Compromise",
        "requires": ["ssti"],
        "optional": ["command_injection"],
        "impact": "Template injection escalated to arbitrary code execution on server",
        "cvss": 10.0,
    },
    {
        "name": "Weak Crypto → Token Forgery → Impersonation",
        "requires": ["weak_crypto"],
        "optional": ["insecure_jwt", "auth_bypass"],
        "impact": "Weak cryptographic implementation allows forging authentication tokens",
        "cvss": 8.5,
    },
    {
        "name": "Deserialization → RCE",
        "requires": ["deserialization"],
        "impact": "Unsafe deserialization of user input leads to arbitrary code execution",
        "cvss": 9.8,
    },
    {
        "name": "CSRF → State Mutation → Account Takeover",
        "requires": ["csrf"],
        "optional": ["auth_bypass"],
        "impact": "Cross-site request forgery allows attacker-controlled state changes",
        "cvss": 8.0,
    },
]


class ChainSynthesizer:
    """Reasons about multi-step attack chains from individual findings."""

    def __init__(self, config):
        self.config = config
        self.ollama = OllamaClient(
            host=config.ollama.host,
            model=config.ollama.model,
            timeout=config.ollama.timeout,
            temperature=config.ollama.temperature,
        )

    async def synthesize(self, findings: list) -> List[Dict]:
        """Analyze all findings and produce attack chain hypotheses.
        
        Args:
            findings: List of Finding objects from the scan
            
        Returns:
            List of chain dicts with name, steps, impact, cvss
        """
        if len(findings) < 2:
            return []

        # Extract finding summaries
        finding_summaries = self._summarize_findings(findings)
        categories = set(finding_summaries.keys())

        # ── Phase 1: Rule-based chain detection ──
        rule_chains = self._rule_based_chains(categories, findings)

        # ── Phase 2: LLM-powered chain reasoning ──
        llm_chains = self._llm_chain_reasoning(findings, finding_summaries)

        # Merge, deduplicate, and rank
        all_chains = rule_chains + llm_chains
        unique_chains = self._deduplicate_chains(all_chains)
        unique_chains.sort(key=lambda c: c.get("cvss", 0), reverse=True)

        return unique_chains

    def _summarize_findings(self, findings: list) -> Dict[str, List[Dict]]:
        """Group findings by category with summary info."""
        grouped = {}
        for f in findings:
            if getattr(f, "false_positive", 0):
                continue
            
            cat = getattr(f, "category", None)
            cat_val = cat.value if hasattr(cat, "value") else str(cat)
            
            summary = {
                "title": getattr(f, "title", ""),
                "url": getattr(f, "url", "") or getattr(f, "file_path", ""),
                "severity": str(getattr(f, "severity", "medium")),
                "parameter": getattr(f, "parameter", ""),
                "confidence": getattr(f, "confidence", 0.5),
            }
            
            if cat_val not in grouped:
                grouped[cat_val] = []
            grouped[cat_val].append(summary)
        
        return grouped

    def _rule_based_chains(self, categories: set, findings: list) -> List[Dict]:
        """Match findings against known attack chain patterns."""
        chains = []
        
        for pattern in KNOWN_CHAIN_PATTERNS:
            required = set(pattern["requires"])
            optional = set(pattern.get("optional", []))
            
            if required.issubset(categories):
                matched_optional = optional.intersection(categories)
                all_matched = required | matched_optional
                
                # Build step details
                steps = []
                for cat in all_matched:
                    relevant = [f for f in findings 
                               if (getattr(f, "category", None) and 
                                   (getattr(f.category, "value", str(f.category)) == cat))]
                    if relevant:
                        f = relevant[0]
                        steps.append({
                            "category": cat,
                            "finding": getattr(f, "title", ""),
                            "target": getattr(f, "url", "") or getattr(f, "file_path", ""),
                        })
                
                chains.append({
                    "name": pattern["name"],
                    "steps": steps,
                    "impact": pattern["impact"],
                    "cvss": pattern["cvss"],
                    "source": "rule_based",
                    "categories_matched": list(all_matched),
                })
        
        return chains

    def _llm_chain_reasoning(self, findings: list, summaries: Dict) -> List[Dict]:
        """Ask LLM to reason about attack chains."""
        if not summaries:
            return []

        # Build concise finding list for the prompt
        finding_lines = []
        for cat, items in summaries.items():
            for item in items[:3]:  # Max 3 per category to save tokens
                finding_lines.append(
                    f"- [{cat.upper()}] {item['title']} at {item['url']} "
                    f"(param: {item['parameter']}, confidence: {item['confidence']:.0%})"
                )

        if len(finding_lines) < 2:
            return []

        findings_text = "\n".join(finding_lines[:20])  # Cap at 20 findings

        prompt = f"""You are an elite penetration tester analyzing scan results.
Given these individual vulnerability findings, identify the highest-impact ATTACK CHAINS
an attacker could execute by combining multiple vulnerabilities.

FINDINGS:
{findings_text}

Think about:
1. How can these vulnerabilities be CHAINED together for maximum impact?
2. What is the realistic step-by-step exploitation path?
3. What is the ultimate impact (data breach, RCE, full compromise)?

Return ONLY this JSON (no markdown):
{{
  "chains": [
    {{
      "name": "Chain Name",
      "steps": [
        {{"step": 1, "action": "Exploit SQLi on /login to dump user table", "category": "sql_injection"}},
        {{"step": 2, "action": "Use extracted admin creds to access /admin", "category": "auth_bypass"}}
      ],
      "impact": "Full database compromise and admin panel access",
      "cvss": 9.8,
      "confidence": 0.85
    }}
  ]
}}

If no meaningful chains exist, return {{"chains": []}}"""

        result = self.ollama.generate_json(prompt)
        
        chains = []
        for chain in result.get("chains", []):
            if chain.get("name") and chain.get("steps"):
                chains.append({
                    "name": chain["name"],
                    "steps": chain["steps"],
                    "impact": chain.get("impact", ""),
                    "cvss": sanitize_confidence(chain.get("cvss", 0)) * 10,  # Normalize to 0-10
                    "confidence": sanitize_confidence(chain.get("confidence", 0.5)),
                    "source": "llm_reasoning",
                })
        
        return chains

    def _deduplicate_chains(self, chains: List[Dict]) -> List[Dict]:
        """Remove duplicate chains by name similarity."""
        seen_names = set()
        unique = []
        for chain in chains:
            name_key = chain["name"].lower().strip()
            if name_key not in seen_names:
                seen_names.add(name_key)
                unique.append(chain)
        return unique
