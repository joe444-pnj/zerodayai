"""
agents/static/dep_auditor.py — Dependency Vulnerability Auditor

Checks dependency manifest files against the NVD (National Vulnerability Database)
and OSV (Open Source Vulnerabilities) for known CVEs.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional

import requests


class DependencyAuditor:
    """Audits dependency files for known vulnerabilities."""

    OSV_API = "https://api.osv.dev/v1/query"
    NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, nvd_api_key: str = ""):
        self.nvd_api_key = nvd_api_key

    def audit(self, dep_file: Path) -> List[Dict]:
        """Route to appropriate auditor based on file type."""
        name = dep_file.name.lower()
        if name in ("requirements.txt", "requirements-dev.txt", "pipfile.lock"):
            return self._audit_python(dep_file)
        elif name in ("package.json", "package-lock.json", "yarn.lock"):
            return self._audit_npm(dep_file)
        elif name in ("gemfile", "gemfile.lock"):
            return self._audit_ruby(dep_file)
        elif name in ("go.mod",):
            return self._audit_go(dep_file)
        return []

    # ── Python ────────────────────────────────────────────────────────

    def _audit_python(self, dep_file: Path) -> List[Dict]:
        """Use pip-audit or OSV API."""
        # Try pip-audit first
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pip_audit", "--format=json", "-r", str(dep_file)],
                capture_output=True, text=True, timeout=60
            )
            data = json.loads(result.stdout or "[]")
            findings = []
            for item in data:
                for vuln in item.get("vulns", []):
                    findings.append({
                        "package": item.get("name", "unknown"),
                        "version": item.get("version", "unknown"),
                        "cve_id": vuln.get("id", ""),
                        "description": vuln.get("description", ""),
                        "fixed_version": (vuln.get("fix_versions") or ["latest"])[0],
                        "cvss_score": 0.0,
                    })
            return findings
        except Exception:
            pass

        # Fallback: OSV API
        packages = self._parse_requirements(dep_file)
        return self._query_osv_bulk(packages, "PyPI")

    def _parse_requirements(self, req_file: Path) -> List[Dict]:
        """Parse requirements.txt into [{name, version}]."""
        packages = []
        for line in req_file.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith(("#", "-", "http")):
                continue
            m = re.match(r'^([A-Za-z0-9_\-\.]+)\s*(?:[=><!]=?)\s*([\d\.]+)', line)
            if m:
                packages.append({"name": m.group(1), "version": m.group(2)})
        return packages

    # ── NPM ───────────────────────────────────────────────────────────

    def _audit_npm(self, dep_file: Path) -> List[Dict]:
        """Run npm audit in the project directory."""
        try:
            result = subprocess.run(
                ["npm", "audit", "--json"],
                capture_output=True, text=True,
                cwd=dep_file.parent, timeout=60
            )
            data = json.loads(result.stdout or "{}")
            findings = []
            for vuln_id, v in data.get("vulnerabilities", {}).items():
                via = v.get("via", [])
                cve_ids = [x.get("url", "").split("/")[-1] for x in via if isinstance(x, dict)]
                findings.append({
                    "package": v.get("name", vuln_id),
                    "version": v.get("range", "unknown"),
                    "cve_id": cve_ids[0] if cve_ids else "",
                    "description": str(via[0].get("title", "")) if via else "",
                    "fixed_version": v.get("fixAvailable", {}).get("version", "latest")
                    if isinstance(v.get("fixAvailable"), dict) else "latest",
                    "cvss_score": via[0].get("cvss", {}).get("score", 0.0)
                    if via and isinstance(via[0], dict) else 0.0,
                })
            return findings
        except Exception:
            return []

    # ── Ruby ──────────────────────────────────────────────────────────

    def _audit_ruby(self, dep_file: Path) -> List[Dict]:
        """Run bundler-audit if available."""
        try:
            result = subprocess.run(
                ["bundle-audit", "check", "--format", "json"],
                capture_output=True, text=True,
                cwd=dep_file.parent, timeout=60
            )
            data = json.loads(result.stdout or "[]")
            return [
                {
                    "package": v.get("gem", {}).get("name", ""),
                    "version": v.get("gem", {}).get("version", ""),
                    "cve_id": v.get("advisory", {}).get("cve", ""),
                    "description": v.get("advisory", {}).get("title", ""),
                    "fixed_version": v.get("advisory", {}).get("patched_versions", ["latest"])[0],
                    "cvss_score": 0.0,
                }
                for v in data
            ]
        except Exception:
            return []

    # ── Go ────────────────────────────────────────────────────────────

    def _audit_go(self, dep_file: Path) -> List[Dict]:
        """Run govulncheck if available."""
        try:
            result = subprocess.run(
                ["govulncheck", "-json", "./..."],
                capture_output=True, text=True,
                cwd=dep_file.parent, timeout=120
            )
            findings = []
            for line in result.stdout.splitlines():
                try:
                    item = json.loads(line)
                    if vuln := item.get("vulnerability"):
                        findings.append({
                            "package": vuln.get("affected", [{}])[0].get("package", {}).get("name", ""),
                            "version": "",
                            "cve_id": vuln.get("id", ""),
                            "description": vuln.get("summary", ""),
                            "fixed_version": "latest",
                            "cvss_score": 0.0,
                        })
                except json.JSONDecodeError:
                    continue
            return findings
        except Exception:
            return []

    # ── OSV API ───────────────────────────────────────────────────────

    def _query_osv_bulk(self, packages: List[Dict], ecosystem: str) -> List[Dict]:
        """Batch query OSV.dev for vulnerabilities."""
        findings = []
        for pkg in packages:
            try:
                resp = requests.post(
                    self.OSV_API,
                    json={"version": pkg["version"], "package": {"name": pkg["name"], "ecosystem": ecosystem}},
                    timeout=10,
                )
                if resp.ok:
                    for vuln in resp.json().get("vulns", []):
                        findings.append({
                            "package": pkg["name"],
                            "version": pkg["version"],
                            "cve_id": vuln.get("id", ""),
                            "description": vuln.get("summary", vuln.get("details", "")),
                            "fixed_version": "latest",
                            "cvss_score": self._extract_cvss(vuln),
                        })
            except Exception:
                continue
        return findings

    @staticmethod
    def _extract_cvss(vuln: Dict) -> float:
        for severity in vuln.get("severity", []):
            if "CVSS" in severity.get("type", ""):
                score_str = severity.get("score", "")
                m = re.search(r"(\d+\.\d+)$", score_str)
                if m:
                    return float(m.group(1))
        return 0.0
