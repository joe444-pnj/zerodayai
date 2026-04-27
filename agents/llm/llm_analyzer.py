"""
agents/llm/llm_analyzer.py — LLM Analysis Agent

Confirms security hypotheses by performing deep-dive code analysis.
"""

from __future__ import annotations
from typing import Dict, Optional

from agents.base import BaseAgent
from agents.llm.ollama_client import OllamaClient
from agents.llm.prompts import analyzer_prompt
from core.models import AgentType, Scan
from core.utils.json_sanitizer import sanitize_analyzer_output, sanitize_external_content

class LLMAnalyzer(BaseAgent):
    """Deep-dives into specific code/hypotheses."""
    
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
        """Subclasses implement their scanning logic here."""
        pass

    async def analyze(self, code_snippet: str, hypothesis: Dict) -> Dict:
        sanitized_snippet = sanitize_external_content(code_snippet)
        prompt = analyzer_prompt(sanitized_snippet, hypothesis)
        result = self.ollama.generate_json(prompt)
        return sanitize_analyzer_output(result)
