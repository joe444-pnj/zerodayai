"""
agents/llm/finding_verifier.py — Second-Opinion Verification Gate

Before any finding is persisted, this module asks the LLM to score it
as REAL or FALSE_POSITIVE. Findings below the confidence threshold
are auto-rejected and logged as false positive learnings.

This specifically targets the XXE false positive dominance problem
(541/798 findings) by adding category-specific verification logic.
"""

from __future__ import annotations

import json
from typing import Dict, Optional, Tuple

from rich.console import Console

from agents.llm.ollama_client import OllamaClient
from core.utils.json_sanitizer import sanitize_confidence

console = Console()


# Categories that are commonly over-reported and need extra scrutiny
HIGH_FP_CATEGORIES = {
    "xxe": 0.6,          # Require higher confidence for XXE
    "misconfiguration": 0.3,  # Low bar — these are usually real
    "sensitive_exposure": 0.3,
    "other": 0.5,
}

# Evidence keywords that strongly indicate real vulnerabilities
STRONG_EVIDENCE_KEYWORDS = [
    "uid=", "root:x:0:0", "www-data", "__debugger__", "werkzeug",
    "SQL syntax", "mysql_fetch", "ORA-", "SQLSTATE",
    "alert(1)", "onerror=", "<script>",
    "boot loader", "/etc/passwd",
    "Traceback (most recent call last)",
]


class FindingVerifier:
    """Second-opinion gate that filters out false positives before persistence."""

    def __init__(self, config):
        self.config = config
        self.ollama = OllamaClient(
            host=config.ollama.host,
            model=config.ollama.model,
            timeout=config.ollama.timeout,
            temperature=config.ollama.temperature,
        )

    async def verify(self, finding_dict: Dict) -> Tuple[bool, float, str]:
        """Verify a finding before persisting.
        
        Args:
            finding_dict: Dict with category, title, description, url, 
                         payload, poc, code_snippet, confidence fields
                         
        Returns:
            (is_real: bool, adjusted_confidence: float, reason: str)
        """
        category = str(finding_dict.get("category", "other")).lower()
        title = finding_dict.get("title", "")
        description = finding_dict.get("description", "")
        evidence = finding_dict.get("poc", "") or finding_dict.get("raw_output", "")
        original_confidence = sanitize_confidence(finding_dict.get("confidence", 0.5))

        # ── Fast-path: Strong evidence keywords → auto-approve ──
        combined_text = f"{description} {evidence}".lower()
        for keyword in STRONG_EVIDENCE_KEYWORDS:
            if keyword.lower() in combined_text:
                return True, max(original_confidence, 0.85), f"Strong evidence: '{keyword}' found"

        # ── Category-specific rules (before LLM call) ──
        if category == "xxe":
            is_real, reason = self._verify_xxe(finding_dict)
            if not is_real:
                return False, 0.1, reason

        if category == "misconfiguration" and "missing" in title.lower():
            # Missing headers are almost always real
            return True, max(original_confidence, 0.7), "Missing security header confirmed"

        # ── LLM second opinion for medium-confidence findings ──
        threshold = HIGH_FP_CATEGORIES.get(category, 0.4)
        
        if original_confidence >= 0.9:
            # High-confidence findings with evidence skip LLM verification
            return True, original_confidence, "High confidence — auto-approved"

        # Ask LLM for second opinion
        llm_score, llm_reason = self._llm_verify(finding_dict)
        
        # Combine original + LLM confidence
        combined = (original_confidence * 0.6) + (llm_score * 0.4)
        
        if combined < threshold:
            return False, combined, f"Below threshold ({threshold}): {llm_reason}"
        
        return True, combined, llm_reason

    def _verify_xxe(self, finding: Dict) -> Tuple[bool, str]:
        """Category-specific XXE verification.
        
        The #1 false positive problem: XXE fires on anything with a DOCTYPE.
        Real XXE requires evidence of XML parser processing external entities.
        """
        desc = (finding.get("description", "") or "").lower()
        payload = (finding.get("payload", "") or "").lower()
        evidence = (finding.get("raw_output", "") or "").lower()
        
        # Real XXE indicators
        real_indicators = [
            "external entity",
            "entity expansion",
            "<!entity",
            "system \"",
            "file:///",
            "expect://",
            "php://",
            "data exfiltration",
            "out-of-band",
        ]
        
        # False positive indicators
        fp_indicators = [
            "doctype html",
            "xml parsing error",
            "dtd not",
            "dtd was",
            "dtd error",
            "normal html",
        ]
        
        has_real = any(ind in desc or ind in evidence for ind in real_indicators)
        has_fp = any(ind in desc or ind in evidence for ind in fp_indicators)
        
        if has_fp and not has_real:
            return False, "XXE FP: Only DOCTYPE/DTD error detected, no entity processing evidence"
        
        if not has_real and "heuristic" in desc.lower():
            return False, "XXE FP: Heuristic-only detection without XML parser evidence"
        
        return True, "XXE verification passed"

    def _llm_verify(self, finding: Dict) -> Tuple[float, str]:
        """Ask the LLM for a second opinion on a finding."""
        category = finding.get("category", "unknown")
        title = finding.get("title", "")
        description = finding.get("description", "")
        evidence = finding.get("poc", "") or finding.get("code_snippet", "")
        url = finding.get("url", "")
        
        prompt = f"""You are a vulnerability triage expert. Evaluate if this finding is a REAL vulnerability or a FALSE POSITIVE.

Finding:
  Category: {category}
  Title: {title}
  URL: {url}
  Description: {description[:500]}
  Evidence: {evidence[:500]}

Criteria for REAL:
- Concrete evidence of exploitation (command output, SQL errors, reflected payload, file contents)
- Clear data flow from user input to dangerous sink
- Reproducible with the given payload

Criteria for FALSE POSITIVE:
- Generic error pages that aren't caused by the payload
- DOCTYPE/DTD references in normal HTML (not XXE)
- Missing headers without actual security impact
- Theoretical vulnerabilities with no proof

Respond ONLY with this JSON:
{{"score": 0.85, "verdict": "REAL", "reason": "Brief explanation"}}

score MUST be a decimal 0.0-1.0. verdict MUST be REAL or FALSE_POSITIVE."""

        result = self.ollama.generate_json(prompt)
        
        score = sanitize_confidence(result.get("score", 0.5))
        reason = result.get("reason", "LLM verification complete")
        
        return score, reason
