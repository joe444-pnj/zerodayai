"""
agents/static/bandit_runner.py — Bandit Python Security Linter Wrapper
"""
from __future__ import annotations
import json
import subprocess
import sys
from pathlib import Path
from typing import List, Dict


def run_bandit(target: Path) -> List[Dict]:
    """Run bandit on a Python file/directory. Returns list of issue dicts."""
    cmd = [
        sys.executable, "-m", "bandit",
        "-r",           # recursive
        "-f", "json",
        "-q",           # quiet
        "-lll",         # report all severity levels
        "-iii",         # report all confidence levels
        "--exit-zero",  # don't fail with non-zero on findings
        str(target),
    ]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=120
        )
        data = json.loads(result.stdout or "{}")
        return data.get("results", [])
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
        return []
