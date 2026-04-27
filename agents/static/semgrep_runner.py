"""
agents/static/semgrep_runner.py — Semgrep Multi-Language Scanner Wrapper
"""
from __future__ import annotations
import json
import subprocess
import sys
from pathlib import Path
from typing import List, Dict

# Use auto config first, then OWASP-specific rulesets
RULESETS = [
    "p/owasp-top-ten",
    "p/default",
    "p/secrets",
]


def run_semgrep(target: Path) -> List[Dict]:
    """Run semgrep with security rulesets. Returns list of result dicts."""
    cmd = [
        sys.executable, "-m", "semgrep",
        "--config", "p/default",
        "--config", "p/secrets",
        "--json",
        "--quiet",
        "--no-git-ignore",
        str(target),
    ]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300
        )
        data = json.loads(result.stdout or "{}")
        return data.get("results", [])
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
        return []
