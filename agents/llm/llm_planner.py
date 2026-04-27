"""
agents/llm/llm_planner.py — LLM Planning Agent

Analyzes static analysis results and code context to generate 
strategic security hypotheses.
"""

from __future__ import annotations
from typing import List, Dict, Optional

from agents.base import BaseAgent
from agents.llm.ollama_client import OllamaClient
from agents.llm.prompts import planner_prompt
from core.models import AgentType, Scan
from core.utils.json_sanitizer import sanitize_planner_output

class LLMPlanner(BaseAgent):
    """Generates high-level vulnerability hypotheses."""
    
    agent_type = AgentType.LLM  # Reusing LLM type for now, or could define new enum

    def __init__(self, config, session=None):
        super().__init__(config, session)
        self.ollama = OllamaClient(
            host=config.ollama.host,
            model=config.ollama.model,
            timeout=config.ollama.timeout,
            temperature=config.ollama.temperature,
        )

    async def execute(self, scan_id: str, target: str, **kwargs) -> None:
        """
        kwargs:
            static_results: str (This will be the <ENDPOINTS> json)
            valid_endpoints: List[str]
            code_chunk: str
            past_experiences: str
        """
        # Layer 4 grounding
        import json
        endpoints_list = kwargs.get("endpoints", [])
        
        assets_json = json.dumps([
            {
                "path": e.path,
                "method": e.method,
                "params": e.params,
                "type": e.type.value if hasattr(e.type, 'value') else e.type,
                "allowed_vulns": getattr(e, "allowed_vulns", [])
            }
            for e in endpoints_list
        ])

        valid_endpoints = kwargs.get("valid_endpoints", [])
        code_chunk = kwargs.get("code_chunk", "")
        past_experiences = kwargs.get("past_experiences", "")

        self.hypotheses = await self.plan(assets_json, code_chunk, past_experiences, endpoints_list, valid_endpoints)
        self.log_info(f"Generated {len(self.hypotheses)} validated hypotheses.")

    def _validate(self, result: Dict, valid_endpoints: List[str], endpoints_list: List = None) -> bool:
        """Reject if wrong endpoint, invalid vuln type for endpoint, missing fields, or confidence < 0.6."""
        vulns = result.get("vulnerabilities", [])
        if not isinstance(vulns, list):
            return False
        
        for v in vulns:
            # Check required fields
            required = ["type", "endpoint", "method", "param", "payload", "expected_behavior"]
            if not all(field in v for field in required):
                return False
            
            # Check endpoint validity (Hallucination rejection)
            if valid_endpoints and v.get("endpoint") not in valid_endpoints:
                pass # Allow the fuzzer to explore LLM hallucinations like /graphql
            
            # Rule-based validation constraints
            if endpoints_list:
                ep_obj = next((ep for ep in endpoints_list if ep.path == v.get("endpoint")), None)
                if ep_obj:
                    v_type_lower = str(v.get("type", "")).lower().replace(" ", "_").replace("-", "_")
                    allowed = getattr(ep_obj, "allowed_vulns", [])
                    if allowed:
                        # Check strict mapping
                        if not any(a in v_type_lower for a in allowed) and not any(v_type_lower in a for a in allowed):
                            self.log_warn(f"Validation failed: Vuln type '{v.get('type')}' not allowed on endpoint {ep_obj.path}")
                            return False
            
            # Check confidence
            if v.get("confidence", 0) < 0.6:
                return False
                
        return True

    async def plan(
        self, 
        asset_model_json: str, 
        code_chunk: str, 
        past_experiences: str, 
        endpoints_list: List = None,
        valid_endpoints: List[str] = None
    ) -> List[Dict]:
        """Call LLM with retries and validation."""
        valid_endpoints = valid_endpoints or []
        
        for i in range(3):
            self.log_info(f"Generating plan (Attempt {i+1}/3)...")
            prompt = planner_prompt(asset_model_json, code_chunk, past_experiences)
            raw_result = self.ollama.generate_json(prompt)
            result = sanitize_planner_output(raw_result, valid_endpoints=valid_endpoints)
            
            if self._validate(result, valid_endpoints, endpoints_list):
                # Return the prioritized attack list
                return result.get("vulnerabilities", [])
            
            self.log_warn(f"LLM output failed validation (hallucination or missing fields). Retrying...")
            
        self.log_error("LLM failed to produce valid output after 3 attempts.")
        return []
