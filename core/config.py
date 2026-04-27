"""
core/config.py — ZeroDay AI Configuration Manager

Loads config.yaml and .env, exposes a singleton Config object.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

import yaml
from dotenv import load_dotenv

# ─── Load .env if present ───────────────────────────────────────────
load_dotenv()

_ROOT = Path(__file__).parent.parent
_CONFIG_PATH = _ROOT / "config.yaml"


def _load_yaml() -> dict:
    if not _CONFIG_PATH.exists():
        raise FileNotFoundError(f"config.yaml not found at {_CONFIG_PATH}")
    with open(_CONFIG_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


# ─── Sub-configs ────────────────────────────────────────────────────

@dataclass
class OllamaConfig:
    host: str = "http://localhost:11434"
    model: str = "qwen2.5-coder:7b"
    fallback_model: str = "codellama"
    timeout: int = 600
    temperature: float = 0.05
    max_tokens: int = 8192
    context_window: int = 32768


@dataclass
class ScanConfig:
    max_file_size_mb: int = 10
    max_files_per_scan: int = 500
    ignore_patterns: List[str] = field(default_factory=list)
    supported_languages: List[str] = field(default_factory=list)


@dataclass
class StaticConfig:
    run_bandit: bool = True
    run_semgrep: bool = True
    run_secrets_scan: bool = True
    run_dep_audit: bool = True
    chunk_size: int = 150


@dataclass
class OOBConfig:
    enabled: bool = False
    callback_host: str = ""
    interactsh_url: str = "https://interact.sh"


@dataclass
class RateLimitConfig:
    enabled: bool = True
    requests_per_second: int = 20
    backoff_on_429: bool = True


@dataclass
class FuzzerConfig:
    max_requests_per_endpoint: int = 500
    max_payloads_per_type: int = 50
    request_timeout: int = 30
    concurrency: int = 5
    user_agent: str = "Mozilla/5.0 (ZeroDay-AI/1.0)"
    follow_redirects: bool = True
    verify_ssl: bool = False
    crawl_depth: int = 3
    run_fuzzer: bool = True
    politeness_delay: float = 0.05
    interesting_params: List[str] = field(default_factory=list)
    oob: OOBConfig = field(default_factory=OOBConfig)
    rate_limit: RateLimitConfig = field(default_factory=RateLimitConfig)


@dataclass
class NetworkConfig:
    port_scan_timeout: float = 2.0
    banner_grab_timeout: float = 5.0
    common_ports: List[int] = field(default_factory=list)
    service_detection: bool = True
    banner_grabbing: bool = True


@dataclass
class ReportingConfig:
    output_dir: str = "reports"
    formats: List[str] = field(default_factory=lambda: ["json", "markdown"])
    include_poc: bool = True
    severity_threshold: str = "info"


@dataclass
class DatabaseConfig:
    path: str = "zeroday.db"


@dataclass
class KnowledgeConfig:
    cve_cache_path: str = "knowledge/cve_cache.json"
    nvd_api_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    update_cve_on_start: bool = False
    cve_lookback_days: int = 365


@dataclass
class ApiServerConfig:
    host: str = "0.0.0.0"
    port: int = 8000
    reload: bool = False
    cors_origins: List[str] = field(default_factory=list)


# ─── Master Config ───────────────────────────────────────────────────

class Config:
    """Singleton configuration object."""

    _instance: Optional["Config"] = None

    def __init__(self, data: dict):
        o = data.get("ollama", {})
        self.ollama = OllamaConfig(
            host=os.getenv("OLLAMA_HOST", o.get("host", "http://localhost:11434")),
            model=os.getenv("OLLAMA_MODEL", o.get("model", "qwen2.5-coder:7b")),
            fallback_model=o.get("fallback_model", "codellama"),
            timeout=o.get("timeout", 600),
            temperature=o.get("temperature", 0.05),
            max_tokens=o.get("max_tokens", 8192),
            context_window=o.get("context_window", 32768),
        )

        s = data.get("scan", {})
        self.scan = ScanConfig(
            max_file_size_mb=s.get("max_file_size_mb", 10),
            max_files_per_scan=s.get("max_files_per_scan", 500),
            ignore_patterns=s.get("ignore_patterns", []),
            supported_languages=s.get("supported_languages", []),
        )

        st = data.get("static_analysis", {})
        self.static = StaticConfig(
            run_bandit=st.get("run_bandit", True),
            run_semgrep=st.get("run_semgrep", True),
            run_secrets_scan=st.get("run_secrets_scan", True),
            run_dep_audit=st.get("run_dep_audit", True),
            chunk_size=st.get("chunk_size", 150),
        )

        fz = data.get("fuzzer", {})
        self.fuzzer = FuzzerConfig(
            max_requests_per_endpoint=fz.get("max_requests_per_endpoint", 500),
            max_payloads_per_type=fz.get("max_payloads_per_type", 500),
            request_timeout=fz.get("request_timeout", 30),
            concurrency=fz.get("concurrency", 5),
            user_agent=fz.get("user_agent", "Mozilla/5.0 (ZeroDay-AI/1.0)"),
            follow_redirects=fz.get("follow_redirects", True),
            verify_ssl=fz.get("verify_ssl", False),
            crawl_depth=fz.get("crawl_depth", 3),
            run_fuzzer=fz.get("run_fuzzer", True),
            politeness_delay=fz.get("politeness_delay", 0.05),
            interesting_params=fz.get("interesting_params", []),
            oob=OOBConfig(
                enabled=fz.get("oob", {}).get("enabled", False),
                callback_host=fz.get("oob", {}).get("callback_host", ""),
                interactsh_url=fz.get("oob", {}).get("interactsh_url", "https://interact.sh"),
            ),
            rate_limit=RateLimitConfig(
                enabled=fz.get("rate_limit", {}).get("enabled", True),
                requests_per_second=fz.get("rate_limit", {}).get("requests_per_second", 20),
                backoff_on_429=fz.get("rate_limit", {}).get("backoff_on_429", True),
            ),
        )

        n = data.get("network", {})
        self.network = NetworkConfig(
            port_scan_timeout=n.get("port_scan_timeout", 2.0),
            banner_grab_timeout=n.get("banner_grab_timeout", 5.0),
            common_ports=n.get("common_ports", [80, 443, 22, 21]),
            service_detection=n.get("service_detection", True),
            banner_grabbing=n.get("banner_grabbing", True),
        )

        r = data.get("reporting", {})
        self.reporting = ReportingConfig(
            output_dir=r.get("output_dir", "reports"),
            formats=r.get("formats", ["json", "markdown"]),
            include_poc=r.get("include_poc", True),
            severity_threshold=r.get("severity_threshold", "info"),
        )

        db = data.get("database", {})
        self.database = DatabaseConfig(path=db.get("path", "zeroday.db"))

        kb = data.get("knowledge", {})
        self.knowledge = KnowledgeConfig(
            cve_cache_path=kb.get("cve_cache_path", "knowledge/cve_cache.json"),
            nvd_api_url=kb.get("nvd_api_url", "https://services.nvd.nist.gov/rest/json/cves/2.0"),
            update_cve_on_start=kb.get("update_cve_on_start", False),
            cve_lookback_days=kb.get("cve_lookback_days", 365),
        )

        api = data.get("api_server", {})
        self.api_server = ApiServerConfig(
            host=api.get("host", "0.0.0.0"),
            port=api.get("port", 8000),
            reload=api.get("reload", False),
            cors_origins=api.get("cors_origins", ["http://localhost:3000"]),
        )

        self.debug = os.getenv("DEBUG", "false").lower() == "true"
        self.log_level = os.getenv("LOG_LEVEL", "INFO")
        self.root_path = _ROOT
        self.nvd_api_key = os.getenv("NVD_API_KEY", "")

    @classmethod
    def load(cls) -> "Config":
        if cls._instance is None:
            cls._instance = cls(_load_yaml())
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Force reload (useful for testing)."""
        cls._instance = None


# ─── Convenience accessor ────────────────────────────────────────────

def get_config() -> Config:
    return Config.load()
