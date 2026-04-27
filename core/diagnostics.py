"""
core/diagnostics.py -- Environment and readiness checks

Provides a structured health report so the tool can explain whether it is
ready to scan well instead of failing later in confusing ways.
"""

from __future__ import annotations

import importlib.util
import shutil
import sys
from pathlib import Path
from typing import Dict, List

from core.config import Config


def _check_module(module_name: str, required: bool = True) -> Dict:
    present = importlib.util.find_spec(module_name) is not None
    status = "ok" if present else ("fail" if required else "warn")
    return {
        "name": module_name,
        "status": status,
        "present": present,
    }


def _check_binary(binary_name: str, required: bool = False) -> Dict:
    path = shutil.which(binary_name)
    status = "ok" if path else ("fail" if required else "warn")
    return {
        "name": binary_name,
        "status": status,
        "present": bool(path),
        "path": path or "",
    }


def build_health_report(config: Config) -> Dict:
    core_modules = [
        _check_module("click"),
        _check_module("rich"),
        _check_module("httpx"),
        _check_module("sqlalchemy"),
        _check_module("yaml"),
        _check_module("dotenv"),
        _check_module("fastapi", required=False),
        _check_module("jinja2", required=False),
    ]
    optional_modules = [
        _check_module("playwright.async_api", required=False),
        _check_module("semgrep", required=False),
        _check_module("bandit", required=False),
    ]
    binaries = [
        _check_binary("ollama"),
        _check_binary("nuclei"),
        _check_binary("ffuf"),
        _check_binary("nmap"),
    ]

    from agents.llm.ollama_client import OllamaClient

    ollama = OllamaClient(
        host=config.ollama.host,
        model=config.ollama.model,
        timeout=min(config.ollama.timeout, 10),
        temperature=config.ollama.temperature,
    )
    ollama_available = ollama.is_available()
    models = ollama.list_models() if ollama_available else []
    selected_present = config.ollama.model in models or config.ollama.model.split(":")[0] in {
        m.split(":")[0] for m in models
    }

    db_path = Path(config.root_path) / config.database.path
    db_status = "ok" if db_path.exists() else "warn"

    sections: Dict[str, List[Dict]] = {
        "core_modules": core_modules,
        "optional_modules": optional_modules,
        "external_tools": binaries,
    }

    counts = {"ok": 0, "warn": 0, "fail": 0}
    for section_items in sections.values():
        for item in section_items:
            counts[item["status"]] += 1

    ollama_status = "ok" if ollama_available and selected_present else ("warn" if ollama_available else "fail")
    counts[ollama_status] += 1
    counts[db_status] += 1

    summary_status = "ok"
    if counts["fail"]:
        summary_status = "fail"
    elif counts["warn"]:
        summary_status = "warn"

    return {
        "summary_status": summary_status,
        "counts": counts,
        "python": {
            "version": sys.version.split()[0],
            "executable": sys.executable,
        },
        "config": {
            "model": config.ollama.model,
            "ollama_host": config.ollama.host,
            "report_dir": config.reporting.output_dir,
            "database_path": str(db_path),
        },
        "database": {
            "status": db_status,
            "path": str(db_path),
            "exists": db_path.exists(),
        },
        "ollama": {
            "status": ollama_status,
            "reachable": ollama_available,
            "configured_model": config.ollama.model,
            "configured_model_present": selected_present,
            "available_models": models[:10],
        },
        **sections,
    }
