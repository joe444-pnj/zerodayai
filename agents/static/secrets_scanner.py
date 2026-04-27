"""
agents/static/secrets_scanner.py — Hardcoded Secrets Detector

Scans source code for accidentally committed credentials, API keys,
private keys, tokens, and passwords using regex patterns.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional


# ─── Regex Patterns ──────────────────────────────────────────────────

SECRETS_PATTERNS = [
    # Generic high-entropy secrets
    {
        "name": "Generic API Key",
        "pattern": re.compile(
            r'(?:api[_-]?key|apikey|api[_-]?secret|api[_-]?token)\s*[=:\'"\s]+\s*["\']?([A-Za-z0-9_\-]{20,})["\']?',
            re.IGNORECASE
        ),
        "confidence": 0.8,
    },
    # AWS Keys
    {
        "name": "AWS Access Key ID",
        "pattern": re.compile(r'(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])'),
        "confidence": 0.99,
    },
    {
        "name": "AWS Secret Access Key",
        "pattern": re.compile(
            r'(?:aws[_-]?secret|secret[_-]?access[_-]?key)\s*[=:\'"\s]+\s*["\']?([A-Za-z0-9/+]{40})["\']?',
            re.IGNORECASE
        ),
        "confidence": 0.95,
    },
    # GCP / Google
    {
        "name": "Google API Key",
        "pattern": re.compile(r'AIza[0-9A-Za-z_\-]{35}'),
        "confidence": 0.99,
    },
    {
        "name": "Google OAuth Token",
        "pattern": re.compile(r'ya29\.[0-9A-Za-z_\-]+'),
        "confidence": 0.99,
    },
    # GitHub
    {
        "name": "GitHub Personal Access Token",
        "pattern": re.compile(r'ghp_[0-9A-Za-z]{36}'),
        "confidence": 0.99,
    },
    {
        "name": "GitHub OAuth Token",
        "pattern": re.compile(r'gho_[0-9A-Za-z]{36}'),
        "confidence": 0.99,
    },
    {
        "name": "GitHub App Token",
        "pattern": re.compile(r'(ghu|ghs|ghr)_[0-9A-Za-z]{36}'),
        "confidence": 0.99,
    },
    # Slack
    {
        "name": "Slack API Token",
        "pattern": re.compile(r'xox[baprs]-[0-9A-Za-z]{10,48}'),
        "confidence": 0.99,
    },
    {
        "name": "Slack Webhook URL",
        "pattern": re.compile(r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+'),
        "confidence": 0.99,
    },
    # Stripe
    {
        "name": "Stripe Secret Key",
        "pattern": re.compile(r'sk_live_[0-9A-Za-z]{24,}'),
        "confidence": 0.99,
    },
    {
        "name": "Stripe Publishable Key",
        "pattern": re.compile(r'pk_live_[0-9A-Za-z]{24,}'),
        "confidence": 0.9,
    },
    # Twilio
    {
        "name": "Twilio API Key",
        "pattern": re.compile(r'SK[0-9a-fA-F]{32}'),
        "confidence": 0.85,
    },
    # SendGrid
    {
        "name": "SendGrid API Key",
        "pattern": re.compile(r'SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}'),
        "confidence": 0.99,
    },
    # RSA / SSH Private Keys
    {
        "name": "RSA Private Key",
        "pattern": re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'),
        "confidence": 0.99,
    },
    # JWT Secrets (hardcoded in code)
    {
        "name": "Hardcoded JWT Secret",
        "pattern": re.compile(
            r'(?:jwt[_-]?secret|secret[_-]?key|signing[_-]?key)\s*[=:\'"\s]+\s*["\']([^"\']{8,})["\']',
            re.IGNORECASE
        ),
        "confidence": 0.85,
    },
    # Database connection strings
    {
        "name": "Database Connection String",
        "pattern": re.compile(
            r'(?:mysql|postgresql|postgres|mongodb|mssql|redis|amqp)://[^:\s]+:[^@\s]+@[^\s]+',
            re.IGNORECASE
        ),
        "confidence": 0.95,
    },
    # Hardcoded passwords
    {
        "name": "Hardcoded Password",
        "pattern": re.compile(
            r'(?:password|passwd|pass|secret|pwd)\s*[=:]\s*["\'](?!.*(?:your|example|changeme|placeholder|xxx|test|none|empty|null|\*+|<|\{\{))[^\'"]{6,}["\']',
            re.IGNORECASE
        ),
        "confidence": 0.75,
    },
    # Bearer tokens in code
    {
        "name": "Hardcoded Bearer Token",
        "pattern": re.compile(
            r'["\']Bearer\s+([A-Za-z0-9_\-\.]{20,})["\']',
            re.IGNORECASE
        ),
        "confidence": 0.85,
    },
    # Mailgun
    {
        "name": "Mailgun API Key",
        "pattern": re.compile(r'key-[0-9a-zA-Z]{32}'),
        "confidence": 0.85,
    },
    # HuggingFace
    {
        "name": "HuggingFace API Token",
        "pattern": re.compile(r'hf_[A-Za-z0-9]{34,}'),
        "confidence": 0.99,
    },
    # OpenAI
    {
        "name": "OpenAI API Key",
        "pattern": re.compile(r'sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}'),
        "confidence": 0.99,
    },
    # Facebook / Meta
    {
        "name": "Facebook Access Token",
        "pattern": re.compile(r'EAACEdEose0cBA[0-9A-Za-z]+'),
        "confidence": 0.99,
    },
    # Telegram Bot Token
    {
        "name": "Telegram Bot Token",
        "pattern": re.compile(r'[0-9]{8,10}:[A-Za-z0-9_\-]{35}'),
        "confidence": 0.85,
    },
    # Heroku API Key
    {
        "name": "Heroku API Key",
        "pattern": re.compile(r'[hH][eE][rR][oO][kK][uU].*[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'),
        "confidence": 0.99,
    },
    # MailChimp API Key
    {
        "name": "MailChimp API Key",
        "pattern": re.compile(r'[0-9a-fA-F]{32}-us[0-9]{1,2}'),
        "confidence": 0.99,
    },
    # Discord Bot Token
    {
        "name": "Discord Bot Token",
        "pattern": re.compile(r'[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}'),
        "confidence": 0.99,
    },
    # Google Cloud Platform Service Account
    {
        "name": "GCP Service Account",
        "pattern": re.compile(r'\"type\": \"service_account\"'),
        "confidence": 0.9,
    },
    # Firebase API Key
    {
        "name": "Firebase API Key",
        "pattern": re.compile(r'AIza[0-9A-Za-z\\-_]{35}'),
        "confidence": 0.9,
    },
]

# Allowlist — skip lines that look like comments, examples, or env reads
ALLOWLIST_PATTERNS = [
    re.compile(r'^\s*#'),                          # Python/bash comments
    re.compile(r'^\s*//'),                         # JS/Java comments
    re.compile(r'os\.(?:environ|getenv)\s*\['),    # Env var reads
    re.compile(r'process\.env\.'),                 # Node env reads
    re.compile(r'\$\{.*?\}'),                      # Shell/template vars
    re.compile(r'(?:your|example|replace|placeholder|secret_here|change_me|xxxx)', re.IGNORECASE),
]


class SecretsScanner:
    """Scans source text for hardcoded secrets using regex patterns."""

    def scan(self, content: str, file_path: str = "") -> List[Dict]:
        """Return list of found secrets as dicts."""
        findings = []
        lines = content.splitlines()

        for pattern_info in SECRETS_PATTERNS:
            for match in pattern_info["pattern"].finditer(content):
                line_num = content[: match.start()].count("\n") + 1
                line_text = lines[line_num - 1] if line_num <= len(lines) else ""

                # Allowlist check
                if any(ap.search(line_text) for ap in ALLOWLIST_PATTERNS):
                    continue

                # Extract surrounding context
                start = max(0, line_num - 2)
                end = min(len(lines), line_num + 2)
                snippet = "\n".join(lines[start:end])

                # Redact the actual secret value in the snippet for output safety
                redacted_value = self._redact(match.group(0))

                findings.append({
                    "title": f"Hardcoded Secret: {pattern_info['name']}",
                    "description": (
                        f"Found a potential hardcoded {pattern_info['name']} in "
                        f"{file_path} at line {line_num}.\n"
                        f"Matched: {redacted_value}"
                    ),
                    "line": line_num,
                    "snippet": snippet,
                    "confidence": pattern_info["confidence"],
                    "secret_type": pattern_info["name"],
                })

        return self._deduplicate(findings)

    @staticmethod
    def _redact(value: str) -> str:
        """Show first 4 and last 4 chars, redact the middle."""
        if len(value) <= 10:
            return "***REDACTED***"
        return f"{value[:4]}{'*' * (len(value) - 8)}{value[-4:]}"

    @staticmethod
    def _deduplicate(findings: List[Dict]) -> List[Dict]:
        """Remove exact line+type duplicates."""
        seen = set()
        result = []
        for f in findings:
            key = (f["line"], f["secret_type"])
            if key not in seen:
                seen.add(key)
                result.append(f)
        return result
