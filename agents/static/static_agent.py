"""
agents/static/static_agent.py — Static Analysis Agent

Orchestrates multiple static analysis tools:
- Bandit (Python security linting)
- Semgrep (multi-language pattern matching)
- Custom secrets scanner
- Dependency CVE auditor
- AST-based taint tracker
"""

from __future__ import annotations

import asyncio
import fnmatch
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from agents.base import BaseAgent
from agents.static.bandit_runner import run_bandit
from agents.static.dep_auditor import DependencyAuditor
from agents.static.secrets_scanner import SecretsScanner
from agents.static.semgrep_runner import run_semgrep
from core.models import AgentType, Finding, FindingCategory, Scan, Severity

console = Console()

# Language detection by extension
LANG_MAP = {
    ".py":    "python",
    ".js":    "javascript",
    ".ts":    "typescript",
    ".jsx":   "javascript",
    ".tsx":   "typescript",
    ".php":   "php",
    ".java":  "java",
    ".c":     "c",
    ".cc":    "cpp",
    ".cpp":   "cpp",
    ".h":     "c",
    ".hpp":   "cpp",
    ".go":    "go",
    ".rb":    "ruby",
    ".rs":    "rust",
    ".sol":   "solidity",
    ".sh":    "bash",
    ".bash":  "bash",
    ".zsh":   "bash",
}

# Dependency manifest files
DEP_FILES = {
    "requirements.txt", "requirements-dev.txt",
    "Pipfile", "Pipfile.lock",
    "package.json", "package-lock.json", "yarn.lock",
    "Gemfile", "Gemfile.lock",
    "pom.xml", "build.gradle",
    "go.mod", "go.sum",
    "Cargo.toml", "Cargo.lock",
}


class StaticAgent(BaseAgent):
    """Multi-tool static analysis agent."""

    agent_type = AgentType.STATIC

    def __init__(self, config, session=None):
        super().__init__(config, session)
        self.secrets_scanner = SecretsScanner()
        self.dep_auditor = DependencyAuditor(nvd_api_key=config.nvd_api_key)

    # ─── Main Execute ─────────────────────────────────────────────────

    async def execute(self, scan_id: str, target: str, **kwargs) -> None:
        """
        target: path to a file, directory, or URL (directory/file scanning only).
        kwargs:
            file_list: Optional[List[str]] — pre-filtered file list
        """
        target_path = Path(target)

        if not target_path.exists():
            self.log_warn(f"Target path does not exist: {target}")
            return

        # Gather files
        if target_path.is_file():
            files = [target_path]
        else:
            files = self._collect_files(target_path)

        self.log_info(
            f"Found {len(files)} files to analyze in {target_path.name}"
        )

        # ── Secrets scan (all files) ──────────────────────────────
        if self.config.static.run_secrets_scan:
            await self._run_secrets_scan(scan_id, files)

        # ── Dependency audit ──────────────────────────────────────
        if self.config.static.run_dep_audit:
            dep_files = [f for f in files if f.name in DEP_FILES]
            if dep_files:
                await self._run_dep_audit(scan_id, dep_files, target_path)

        # ── Bandit (Python only) ──────────────────────────────────
        if self.config.static.run_bandit:
            py_files = [f for f in files if f.suffix == ".py"]
            if py_files:
                await self._run_bandit(scan_id, target_path, py_files)

        # ── Semgrep (multi-language) ──────────────────────────────
        if self.config.static.run_semgrep:
            await self._run_semgrep(scan_id, target_path, files)

        # ── Custom AST / pattern scan ─────────────────────────────
        await self._run_pattern_scan(scan_id, files)

    # ─── File Collection ──────────────────────────────────────────────

    def _collect_files(self, root: Path) -> List[Path]:
        """Recursively collect scannable files, respecting ignore patterns."""
        ignore = self.config.scan.ignore_patterns
        max_size = self.config.scan.max_file_size_mb * 1024 * 1024
        max_files = self.config.scan.max_files_per_scan
        files: List[Path] = []

        for path in root.rglob("*"):
            if len(files) >= max_files:
                self.log_warn(f"Reached max file limit ({max_files}), stopping collection.")
                break
            if not path.is_file():
                continue
            rel = path.relative_to(root).as_posix()
            if any(fnmatch.fnmatch(rel, pat) for pat in ignore):
                continue
            if path.stat().st_size > max_size:
                continue
            if path.suffix.lower() in LANG_MAP or path.name in DEP_FILES:
                files.append(path)

        return files

    # ─── Secrets Scan ─────────────────────────────────────────────────

    async def _run_secrets_scan(self, scan_id: str, files: List[Path]) -> None:
        self.log_info(f"Scanning {len(files)} files for hardcoded secrets...")
        for file_path in files:
            if self._stopped:
                return
            try:
                content = file_path.read_text(errors="replace")
                secrets = self.secrets_scanner.scan(content, str(file_path))
                for s in secrets:
                    finding = Finding(
                        scan_id=scan_id,
                        agent=AgentType.STATIC,
                        category=FindingCategory.HARDCODED_CREDS,
                        severity=Severity.HIGH,
                        title=s["title"],
                        description=s["description"],
                        file_path=str(file_path),
                        line_number=s.get("line"),
                        code_snippet=s.get("snippet"),
                        remediation=(
                            "Remove the hardcoded credential. Use environment variables "
                            "or a secrets manager instead."
                        ),
                        confidence=s.get("confidence", 0.85),
                    )
                    await self.emit_finding(finding)
            except Exception as e:
                self.log_warn(f"Secrets scan failed for {file_path.name}: {e}")

        await asyncio.sleep(0)  # Yield to event loop

    # ─── Dependency Audit ─────────────────────────────────────────────

    async def _run_dep_audit(
        self, scan_id: str, dep_files: List[Path], root: Path
    ) -> None:
        self.log_info(f"Auditing {len(dep_files)} dependency manifest(s)...")
        for dep_file in dep_files:
            if self._stopped:
                return
            try:
                results = await asyncio.to_thread(
                    self.dep_auditor.audit, dep_file
                )
                for r in results:
                    finding = Finding(
                        scan_id=scan_id,
                        agent=AgentType.STATIC,
                        category=FindingCategory.VULNERABLE_DEP,
                        severity=_cvss_to_severity(r.get("cvss_score", 0.0)),
                        title=f"Vulnerable dependency: {r['package']} {r['version']}",
                        description=(
                            f"{r['package']} version {r['version']} is affected by "
                            f"{r.get('cve_id', 'a known vulnerability')}.\n\n"
                            f"{r.get('description', '')}"
                        ),
                        file_path=str(dep_file),
                        cve_ids=r.get("cve_id"),
                        cvss_score=r.get("cvss_score"),
                        remediation=f"Upgrade {r['package']} to version {r.get('fixed_version', 'latest')}",
                        confidence=0.95,
                    )
                    await self.emit_finding(finding)
            except Exception as e:
                self.log_warn(f"Dep audit failed for {dep_file.name}: {e}")

        await asyncio.sleep(0)

    # ─── Bandit ───────────────────────────────────────────────────────

    async def _run_bandit(
        self, scan_id: str, root: Path, py_files: List[Path]
    ) -> None:
        self.log_info(f"Running Bandit on {len(py_files)} Python file(s)...")
        try:
            results = await asyncio.to_thread(run_bandit, root)
            for r in results:
                sev = _bandit_severity(r.get("issue_severity", "LOW"))
                finding = Finding(
                    scan_id=scan_id,
                    agent=AgentType.STATIC,
                    category=FindingCategory.OTHER,
                    severity=sev,
                    title=r.get("test_name", "Bandit Finding"),
                    description=r.get("issue_text", ""),
                    file_path=r.get("filename"),
                    line_number=r.get("line_number"),
                    code_snippet=r.get("code"),
                    cve_ids=r.get("cwe", {}).get("id"),
                    confidence=_bandit_confidence(r.get("issue_confidence", "LOW")),
                    raw_output=json.dumps(r),
                    remediation="Review the Bandit documentation for this issue: "
                                + r.get("more_info", ""),
                )
                await self.emit_finding(finding)
        except FileNotFoundError:
            self.log_warn("Bandit not installed. Install with: pip install bandit")
        except Exception as e:
            self.log_warn(f"Bandit failed: {e}")

    # ─── Semgrep ──────────────────────────────────────────────────────

    async def _run_semgrep(
        self, scan_id: str, root: Path, files: List[Path]
    ) -> None:
        self.log_info("Running Semgrep (multi-language rules)...")
        try:
            results = await asyncio.to_thread(run_semgrep, root)
            for r in results:
                sev_str = r.get("extra", {}).get("severity", "WARNING").lower()
                sev = {"error": Severity.HIGH, "warning": Severity.MEDIUM}.get(
                    sev_str, Severity.LOW
                )
                meta = r.get("extra", {}).get("metadata", {})
                finding = Finding(
                    scan_id=scan_id,
                    agent=AgentType.STATIC,
                    category=FindingCategory.OTHER,
                    severity=sev,
                    title=r.get("check_id", "Semgrep Finding").split(".")[-1].replace("-", " ").title(),
                    description=r.get("extra", {}).get("message", ""),
                    file_path=r.get("path"),
                    line_number=r.get("start", {}).get("line"),
                    code_snippet=r.get("extra", {}).get("lines"),
                    cve_ids=",".join(meta.get("cve", [])),
                    cvss_score=None,
                    references=json.dumps(meta.get("references", [])),
                    confidence=0.8,
                    raw_output=json.dumps(r),
                )
                await self.emit_finding(finding)
        except FileNotFoundError:
            self.log_warn("Semgrep not installed. Install with: pip install semgrep")
        except Exception as e:
            self.log_warn(f"Semgrep failed: {e}")

    # ─── Custom Pattern Scan ──────────────────────────────────────────

    async def _run_pattern_scan(self, scan_id: str, files: List[Path]) -> None:
        """Language-agnostic regex pattern scan for common vulnerability patterns."""
        self.log_info("Running custom vulnerability pattern scan...")

        PATTERNS = [
            # SQL Injection
            (
                re.compile(
                    r'(?:execute|cursor\.execute|query)\s*\(\s*["\'].*?\+|'
                    r'\.format\s*\(.*?(?:user|input|param|query|id)\b',
                    re.IGNORECASE
                ),
                FindingCategory.SQL_INJECTION, Severity.HIGH,
                "Potential SQL Injection",
                "String formatting or concatenation used in SQL query. Use parameterized queries.",
            ),
            # Command Injection
            (
                re.compile(
                    r'(?:os\.system|subprocess\.call|subprocess\.run|popen|exec)\s*\('
                    r'.*?(?:request|input|param|user|args)',
                    re.IGNORECASE
                ),
                FindingCategory.COMMAND_INJECTION, Severity.CRITICAL,
                "Potential Command Injection",
                "User-controlled input passed to shell execution. Use subprocess with list args and no shell=True.",
            ),
            # Path Traversal
            (
                re.compile(
                    r'open\s*\(\s*(?:request|input|param|user|args|path)',
                    re.IGNORECASE
                ),
                FindingCategory.PATH_TRAVERSAL, Severity.HIGH,
                "Potential Path Traversal",
                "User input used in file open operation without sanitization.",
            ),
            # eval() usage
            (
                re.compile(r'\beval\s*\(', re.IGNORECASE),
                FindingCategory.COMMAND_INJECTION, Severity.HIGH,
                "Dangerous eval() Usage",
                "eval() executes arbitrary code. Remove or replace with safe alternatives.",
            ),
            # Hardcoded IPs / internal URLs
            (
                re.compile(r'(?:http://|https://)(?:192\.168|10\.|172\.(?:1[6-9]|2\d|3[01]))'),
                FindingCategory.SENSITIVE_EXPOSURE, Severity.INFO,
                "Hardcoded Internal Network Address",
                "Internal IP/URL hardcoded. May reveal network topology.",
            ),
            # XXE potential
            (
                re.compile(
                    r'(?:xml\.etree|lxml|minidom|ElementTree).*?parse\s*\(',
                    re.IGNORECASE
                ),
                FindingCategory.XXE, Severity.MEDIUM,
                "Potential XXE (XML External Entity)",
                "XML parser used — ensure external entities are disabled to prevent XXE.",
            ),
            # Insecure deserialization
            (
                re.compile(r'\bpickle\.loads?\b|\byaml\.load\s*\((?!.*?Loader=yaml\.Safe)', re.IGNORECASE),
                FindingCategory.DESERIALIZATION, Severity.HIGH,
                "Insecure Deserialization",
                "pickle.load or yaml.load with untrusted data can execute arbitrary code.",
            ),
            # Weak random
            (
                re.compile(r'\brandom\.(?:random|randint|choice|randrange)\b(?!.*#\s*nosec)', re.IGNORECASE),
                FindingCategory.WEAK_CRYPTO, Severity.MEDIUM,
                "Weak Random Number Generator",
                "random module is not cryptographically secure. Use secrets module instead.",
            ),
        ]

        for file_path in files:
            if self._stopped:
                return
            try:
                content = file_path.read_text(errors="replace")
                lines = content.splitlines()

                for pattern, category, severity, title, remediation in PATTERNS:
                    for m in pattern.finditer(content):
                        # Find line number
                        line_num = content[: m.start()].count("\n") + 1
                        snippet = lines[max(0, line_num - 2) : line_num + 2]

                        finding = Finding(
                            scan_id=scan_id,
                            agent=AgentType.STATIC,
                            category=category,
                            severity=severity,
                            title=title,
                            description=f"Pattern match in {file_path.name}: {remediation}",
                            file_path=str(file_path),
                            line_number=line_num,
                            code_snippet="\n".join(snippet),
                            remediation=remediation,
                            confidence=0.7,
                        )
                        await self.emit_finding(finding)
            except Exception:
                pass

            await asyncio.sleep(0)


# ─── Helpers ──────────────────────────────────────────────────────────

def _cvss_to_severity(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    elif score >= 7.0:
        return Severity.HIGH
    elif score >= 4.0:
        return Severity.MEDIUM
    elif score > 0:
        return Severity.LOW
    return Severity.INFO


def _bandit_severity(s: str) -> Severity:
    return {
        "HIGH":   Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW":    Severity.LOW,
    }.get(s.upper(), Severity.INFO)


def _bandit_confidence(c: str) -> float:
    return {"HIGH": 0.9, "MEDIUM": 0.7, "LOW": 0.5}.get(c.upper(), 0.6)
