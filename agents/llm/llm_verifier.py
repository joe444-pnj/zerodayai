"""
agents/llm/llm_verifier.py — LLM Verification Agent

Verifies fuzzer results to reduce false positives.
"""

from __future__ import annotations
from typing import Dict, Optional

from agents.base import BaseAgent
from agents.llm.ollama_client import OllamaClient
from agents.llm.prompts import verifier_prompt
from core.models import AgentType, Scan
from core.utils.json_sanitizer import sanitize_verifier_output

class LLMVerifier(BaseAgent):
    """Verifies fuzzer outputs."""
    
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

    async def verify(self, fuzzer_result: str, evidence: str) -> Dict:
        prompt = verifier_prompt(fuzzer_result, evidence)
        result = self.ollama.generate_json(prompt)
        return sanitize_verifier_output(result)
