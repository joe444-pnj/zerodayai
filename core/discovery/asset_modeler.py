"""
core/discovery/asset_modeler.py — Structured Attack Surface Modeling

Converts a raw list of endpoints into a classified Attack Surface for
strategic vulnerability research.
"""

import re
from enum import Enum
from typing import Dict, List, Set, Optional
from dataclasses import dataclass, field

class EndpointType(Enum):
    # Functional Categories
    AUTH = "auth"            # Login, signup, password reset
    COMMAND = "command"     # Pings, execution, dynamic processing
    FILE = "file"           # Uploads, downloads, LFI paths
    SEARCH = "search"       # Query params, search boxes
    CONSOLE = "console"     # Debug consoles, dev interfaces
    REST = "rest"           # JSON APIs, resources
    GENERAL = "general"     # Static pages, generic forms

@dataclass
class Endpoint:
    path: str
    method: str = "GET"
    params: List[str] = field(default_factory=list)
    type: EndpointType = EndpointType.GENERAL
    risk_score: float = 0.0
    allowed_vulns: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        self.method = self.method.upper()

class AttackSurface:
    """A collection of classified assets on the target."""
    
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.endpoints: List[Endpoint] = []
        self.domain = self._extract_domain(base_url)

    def _extract_domain(self, url: str) -> str:
        match = re.search(r"https?://([^/:]+)", url)
        return match.group(1) if match else url

    def add_endpoint(self, path: str, method: str = "GET", params: List[str] = None) -> None:
        ep = Endpoint(path=path, method=method, params=params or [])
        self.endpoints.append(ep)

    def get_by_type(self, ep_type: EndpointType) -> List[Endpoint]:
        return [e for e in self.endpoints if e.type == ep_type]

class SurfaceClassifier:
    """Analyzes endpoints and tagging them for the Strategy Engine."""

    # Path keywords for classification
    RULES = {
        EndpointType.AUTH: [
            r"login", r"auth", r"signup", r"register", r"logout", r"token", r"session", r"pass"
        ],
        EndpointType.COMMAND: [
            r"ping", r"exec", r"shell", r"cmd", r"system", r"run", r"process", r"action"
        ],
        EndpointType.FILE: [
            r"download", r"upload", r"view", r"get", r"file", r"path", r"dir", r"folder", r"image", r"doc"
        ],
        EndpointType.SEARCH: [
            r"search", r"query", r"find", r"list", r"filter", r"search\.php", r"\?s="
        ],
        EndpointType.CONSOLE: [
            r"console", r"debug", r"debugger", r"terminal", r"inspect", r"dev", r"admin"
        ]
    }

    # Parameter keywords for reinforcement
    PARAM_RULES = {
        EndpointType.COMMAND: ["cmd", "command", "exec", "eval", "system", "run"],
        EndpointType.FILE: ["file", "path", "doc", "uri", "src", "dest", "folder"],
        EndpointType.SEARCH: ["q", "query", "s", "search", "term", "key"],
        EndpointType.REST: ["id", "uuid", "api_key"]
    }

    # Allowed vulnerability types per endpoint category (Rule-based constraints)
    ALLOWED_VULNS = {
        EndpointType.AUTH: ["sql_injection", "auth_bypass", "insecure_jwt", "xss", "logic_flaw", "session_fixation"],
        EndpointType.COMMAND: ["command_injection", "ssrf", "xss"],
        EndpointType.FILE: ["path_traversal", "xss", "ssrf", "command_injection", "xxe"],
        EndpointType.SEARCH: ["sql_injection", "xss", "ssti", "ldap_injection"],
        EndpointType.CONSOLE: ["command_injection", "misconfiguration", "auth_bypass"],
        EndpointType.REST: ["sql_injection", "auth_bypass", "broken_access", "ssrf", "xss", "ssti", "deserialization", "broken_access"],
        EndpointType.GENERAL: ["xss", "sql_injection", "open_redirect", "csrf"],
    }

    @classmethod
    def classify_all(cls, surface: AttackSurface) -> None:
        for ep in surface.endpoints:
            ep.type = cls.classify_endpoint(ep)
            ep.allowed_vulns = cls.ALLOWED_VULNS.get(ep.type, [])

    @classmethod
    def classify_endpoint(cls, ep: Endpoint) -> EndpointType:
        path = ep.path.lower()
        params = [p.lower() for p in ep.params]

        # 1. Console check (Highest priority)
        for pattern in cls.RULES[EndpointType.CONSOLE]:
            if re.search(pattern, path):
                return EndpointType.CONSOLE

        # 2. Command check
        for pattern in cls.RULES[EndpointType.COMMAND]:
            if re.search(pattern, path):
                return EndpointType.COMMAND
        for p in params:
            if p in cls.PARAM_RULES[EndpointType.COMMAND]:
                return EndpointType.COMMAND

        # 3. File check
        for pattern in cls.RULES[EndpointType.FILE]:
            if re.search(pattern, path):
                return EndpointType.FILE
        for p in params:
            if p in cls.PARAM_RULES[EndpointType.FILE]:
                return EndpointType.FILE

        # 4. Search check
        for pattern in cls.RULES[EndpointType.SEARCH]:
            if re.search(pattern, path):
                return EndpointType.SEARCH
        for p in params:
            if p in cls.PARAM_RULES[EndpointType.SEARCH]:
                return EndpointType.SEARCH

        # 5. Auth check
        for pattern in cls.RULES[EndpointType.AUTH]:
            if re.search(pattern, path):
                return EndpointType.AUTH

        # 6. REST API check
        if "/api/" in path or "/v1/" in path or "/json" in path:
            return EndpointType.REST

        return EndpointType.GENERAL
