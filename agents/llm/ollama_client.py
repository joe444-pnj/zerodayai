"""
agents/llm/ollama_client.py — Ollama Local LLM Client

Wraps the Ollama REST API for synchronous and asynchronous
streaming chat completions. Model-agnostic.
"""

from __future__ import annotations

import json
import re
import time
from typing import Generator, Iterator, List, Optional

import httpx
from rich.console import Console

console = Console()

# Default models to try in order of preference
RECOMMENDED_MODELS = [
    "qwen2.5-coder",
    "deepseek-coder-v2",
    "codellama",
    "llama3",
    "mistral",
    "gemma2",
]


class OllamaClient:
    """HTTP client for the Ollama local inference server."""

    def __init__(
        self,
        host: str = "http://localhost:11434",
        model: str = "qwen2.5-coder:7b",
        timeout: int = 600,
        temperature: float = 0.05,
    ):
        # Normalize host: strip trailing slash and /api
        host = host.rstrip("/")
        if host.endswith("/api"):
            host = host[:-4]
        self.host = host
        self.model = model
        self.timeout = timeout
        self.temperature = temperature
        self._http = httpx.Client(timeout=timeout)

    # ─── Health Checks ───────────────────────────────────────────────

    def is_available(self) -> bool:
        """Return True if Ollama server is reachable."""
        try:
            r = self._http.get(f"{self.host}/api/tags", timeout=5)
            return r.status_code == 200
        except Exception:
            return False

    def list_models(self) -> List[str]:
        """Return list of locally available model names."""
        try:
            r = self._http.get(f"{self.host}/api/tags", timeout=10)
            r.raise_for_status()
            data = r.json()
            return [m["name"] for m in data.get("models", [])]
        except (httpx.ConnectError, httpx.ConnectTimeout):
            return []
        except Exception:
            return []

    def best_available_model(self) -> Optional[str]:
        """Pick the best available model from the recommended list."""
        available = self.list_models()
        # Normalize model names (strip tag suffix for comparison)
        available_bases = {m.split(":")[0] for m in available}
        for preferred in RECOMMENDED_MODELS:
            if preferred in available_bases or preferred in available:
                return preferred
        return available[0] if available else None

    def ensure_model(self, model_name: Optional[str] = None) -> bool:
        """Check model is available; if not, suggest pull command."""
        target = model_name or self.model
        available = self.list_models()
        if target in available:
            self.model = target
            return True
            
        available_map = {m.split(":")[0].lower(): m for m in available}
        target_lower = target.split(":")[0].lower()
        
        if target_lower in available_map:
            self.model = available_map[target_lower]
            return True

        console.print(
            f"\n[yellow]⚠ Model [bold]{target}[/bold] not found locally.[/yellow]"
        )
        console.print(
            f"[cyan]Pull it with:[/cyan] [bold]ollama pull {target}[/bold]\n"
        )

        # Try fallback
        fallback = self.best_available_model()
        if fallback:
            console.print(f"[green]Using available model: [bold]{fallback}[/bold][/green]")
            self.model = fallback
            return True
        return False

    # ─── Generation ──────────────────────────────────────────────────

    def generate(
        self,
        prompt: str,
        system: str = "",
        stream: bool = True,
    ) -> Generator[str, None, None]:
        """Single-turn generation with optional system prompt."""
        messages: List[dict] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        yield from self.chat(messages, stream=stream)

    def generate_full(self, prompt: str, system: str = "") -> str:
        """Non-streaming generation — returns full response string."""
        return "".join(self.generate(prompt, system, stream=False))

    def chat(
        self,
        messages: List[dict],
        stream: bool = True,
    ) -> Generator[str, None, None]:
        """
        Multi-turn chat completion.
        Yields text chunks if stream=True, yields single full text if stream=False.
        """
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": stream,
            "options": {
                "temperature": self.temperature,
                "num_predict": 8192,
            },
        }

        try:
            if stream:
                yield from self._stream_chat(payload)
            else:
                yield self._blocking_chat(payload)
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                # Fallback to /api/generate if /api/chat is not available
                # Also likely happens if model name is wrong case
                console.print(f"[dim]  [OLLAMA] 404 on /api/chat, trying /api/generate fallback (Model: {self.model})[/dim]")
                yield from self._generate_fallback(messages, stream)
            else:
                raise

    def _generate_fallback(self, messages: List[dict], stream: bool) -> Generator[str, None, None]:
        """Convert chat messages to a single prompt for /api/generate."""
        prompt = ""
        for msg in messages:
            role = msg.get("role", "user").upper()
            content = msg.get("content", "")
            prompt += f"\n### {role}:\n{content}\n"
        prompt += "\n### ASSISTANT:\n"

        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": stream,
            "options": {
                "temperature": self.temperature,
                "num_predict": 8192,
            },
        }

        if stream:
            with self._http.stream("POST", f"{self.host}/api/generate", json=payload, timeout=self.timeout) as r:
                r.raise_for_status()
                for line in r.iter_lines():
                    if not line.strip(): continue
                    try:
                        chunk = json.loads(line)
                        content = chunk.get("response", "")
                        if content: yield content
                        if chunk.get("done"): break
                    except json.JSONDecodeError: continue
        else:
            r = self._http.post(f"{self.host}/api/generate", json=payload, timeout=self.timeout)
            r.raise_for_status()
            yield r.json().get("response", "")

    def _stream_chat(self, payload: dict) -> Generator[str, None, None]:
        with self._http.stream(
            "POST",
            f"{self.host}/api/chat",
            json=payload,
            timeout=self.timeout,
        ) as response:
            response.raise_for_status()
            for line in response.iter_lines():
                if not line.strip():
                    continue
                try:
                    chunk = json.loads(line)
                    content = chunk.get("message", {}).get("content", "")
                    if content:
                        yield content
                    if chunk.get("done"):
                        break
                except json.JSONDecodeError:
                    continue

    def _blocking_chat(self, payload: dict) -> str:
        payload["stream"] = False
        try:
            r = self._http.post(
                f"{self.host}/api/chat",
                json=payload,
                timeout=self.timeout,
            )
            r.raise_for_status()
            data = r.json()
            return data.get("message", {}).get("content", "")
        except (httpx.ConnectError, httpx.ConnectTimeout):
            console.print(f"  [red][OLLAMA] Connection failed: Server at {self.host} is unreachable.[/red]")
            return ""
        except Exception as e:
            console.print(f"  [red][OLLAMA] Error: {e}[/red]")
            return ""

    # ─── Structured Output (JSON) ────────────────────────────────────

    def validate_json(self, output: str) -> Optional[dict]:
        """Verify if a string is valid JSON."""
        try:
            # Strip markdown
            cleaned = re.sub(r"```(?:json)?\s*", "", output).strip().rstrip("`").strip()
            return json.loads(cleaned)
        except Exception:
            return None

    def generate_json(self, prompt: str, system: str = "") -> dict:
        """
        Ask the model for a JSON response. Retries up to 3 times.
        Injects formatting instruction into the prompt.
        All outputs are post-processed through the JSON sanitizer.
        """
        from agents.llm.prompts import SYSTEM_VULN_ANALYST
        if not system:
            system = SYSTEM_VULN_ANALYST

        # Pre-check availability to avoid long timeouts
        if not self.is_available():
            return {}

        json_instruction = (
            "\n\nCRITICAL: Respond ONLY with valid JSON. No markdown, no explanation. "
            "No ```json blocks. Raw JSON only. "
            "All 'confidence' values MUST be decimal numbers (e.g., 0.85), NEVER words like 'high' or 'certain'."
        )
        full_prompt = prompt + json_instruction

        for attempt in range(3):
            try:
                raw = self.generate_full(full_prompt, system)
                if not raw:
                    return {}
                parsed = self.validate_json(raw)
                if parsed is not None:
                    # Post-process: sanitize ALL confidence values recursively
                    parsed = self._sanitize_all_confidence(parsed)
                    return parsed
                
                console.print(f"  [dim][OLLAMA] JSON parse failed (attempt {attempt+1}/3), retrying...[/dim]")
                time.sleep(1)
            except (httpx.ConnectError, httpx.ConnectTimeout):
                break # Don't retry if connection failed

        # If all attempts fail, return empty structure
        console.print("  [red][OLLAMA] Failed to get valid JSON response[/red]")
        return {}

    def _sanitize_all_confidence(self, data: dict) -> dict:
        """Recursively sanitize all 'confidence' fields in a JSON structure."""
        from core.utils.json_sanitizer import sanitize_confidence
        
        if isinstance(data, dict):
            for key, value in data.items():
                if key == "confidence":
                    data[key] = sanitize_confidence(value)
                elif key == "is_vulnerable" or key == "is_valid":
                    if isinstance(value, str):
                        data[key] = value.lower() in ("true", "yes", "1", "confirmed")
                elif isinstance(value, (dict, list)):
                    data[key] = self._sanitize_all_confidence(value)
        elif isinstance(data, list):
            data = [self._sanitize_all_confidence(item) if isinstance(item, (dict, list)) else item for item in data]
        
        return data

    def pull_model(self, model_name: str) -> bool:
        """Pull a model from Ollama registry (blocking)."""
        console.print(f"[cyan]Pulling model [bold]{model_name}[/bold]...[/cyan]")
        try:
            with self._http.stream(
                "POST",
                f"{self.host}/api/pull",
                json={"name": model_name, "stream": True},
                timeout=600,  # 10 min for large models
            ) as r:
                r.raise_for_status()
                for line in r.iter_lines():
                    if not line.strip():
                        continue
                    try:
                        data = json.loads(line)
                        status = data.get("status", "")
                        if status:
                            console.print(f"  [dim]{status}[/dim]", end="\r")
                    except json.JSONDecodeError:
                        continue
            console.print(f"\n[green]✓ Model {model_name} pulled successfully.[/green]")
            return True
        except Exception as e:
            console.print(f"\n[red]✗ Failed to pull model: {e}[/red]")
            return False

    def close(self) -> None:
        self._http.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
