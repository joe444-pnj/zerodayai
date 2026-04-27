"""
core/discovery/endpoint_guesser.py — Active Attack Surface Discovery

Performs endpoint bruteforcing, method probing, and parameter guessing
to enrich the target attack surface before analysis.
"""
from __future__ import annotations

import httpx
import asyncio
from typing import List, Dict, Optional
from urllib.parse import urljoin

COMMON_ENDPOINTS = [
    "login", "admin", "ping", "api", "auth", "user", "search", "debug",
    "v1", "v2", "config", "settings", "backup", "db", "upload", "status",
    "shell", "console", "manager", "inv", "monitor", "graphql", "gql", "api/graphql",
    "phpinfo.php", ".env", ".git/config", "wp-admin", "wp-login.php", "xmlrpc.php",
    "actuator", "actuator/env", "actuator/health", "jolokia", "swagger-ui.html",
    "api-docs", "v1/api-docs", "v2/api-docs", "v3/api-docs", "swagger-resources",
    "console", "composer.json", "package.json", "Dockerfile", "config.php",
    "web-console", "invoker/JMXInvokerServlet", "axis2/services/AdminService"
]

COMMON_PARAMS = [
    "username", "password", "user", "pass", "id", "key", "ip", "query",
    "cmd", "exec", "file", "url", "path", "token", "admin", "email",
    "redirect", "next", "callback", "mutation", "operationName",
    "command", "host", "dir", "arg", "input", "source", "dest", "to", "from",
    "domain", "uri", "proxy", "site", "view", "template", "page", "include"
]

class EndpointGuesser:
    """Proactively discovers hidden attack surfaces."""

    def __init__(self, config):
        self.config = config

    async def guess_all(self, base_url: str) -> List[Dict]:
        """Runs the full discovery pipeline: endpoints -> methods -> params."""
        found_endpoints = await self.discover_endpoints(base_url)
        
        enriched = []
        for ep in found_endpoints:
            url = urljoin(base_url, ep["path"])
            
            # 2. Method Detection
            if await self.detect_post_endpoint(url):
                ep["method"] = "POST"
            
            # 3. Parameter Discovery
            ep["params"] = await self.discover_params(url, ep["method"])
            enriched.append(ep)
            
        return enriched

    async def discover_endpoints(self, base_url: str) -> List[Dict]:
        """Bruteforce common web paths."""
        found = []
        async with httpx.AsyncClient(verify=False, timeout=5) as client:
            tasks = []
            for word in COMMON_ENDPOINTS:
                url = f"{base_url.rstrip('/')}/{word}"
                tasks.append(self._probe_path(client, word, url))
            
            results = await asyncio.gather(*tasks)
            for res in results:
                if res:
                    found.append(res)
        return found

    async def _probe_path(self, client: httpx.AsyncClient, word: str, url: str) -> Optional[Dict]:
        try:
            res = await client.get(url)
            if res.status_code in [200, 401, 403, 400, 405]:
                return {
                    "path": f"/{word}",
                    "method": "GET",
                    "params": []
                }
        except:
            pass
        return None

    async def detect_post_endpoint(self, url: str) -> bool:
        """Checks if an endpoint supports POST even if not found in HTML."""
        try:
            async with httpx.AsyncClient(verify=False, timeout=5) as client:
                res = await client.post(url, data={"test": "test"})
                # If response status is not 405 (Method Not Allowed), POST likely exists
                if res.status_code != 405:
                    return True
        except:
            pass
        return False

    async def discover_params(self, url: str, method: str) -> List[str]:
        """Guess common parameters for a specific endpoint."""
        params = []
        async with httpx.AsyncClient(verify=False, timeout=5) as client:
            tasks = []
            for p in COMMON_PARAMS:
                tasks.append(self._probe_param(client, url, method, p))
            
            results = await asyncio.gather(*tasks)
            params = [p for p in results if p]
        return params

    async def _probe_param(self, client: httpx.AsyncClient, url: str, method: str, param: str) -> Optional[str]:
        try:
            # First, get a baseline response
            if method == "GET":
                baseline = await client.get(url)
            else:
                baseline = await client.post(url, data={})

            # Then probe with the parameter
            canary = f"zd_probe_{param}"
            if method == "GET":
                res = await client.get(url, params={param: canary})
            else:
                res = await client.post(url, data={param: canary})
            
            # Check for changes
            if res.status_code != baseline.status_code:
                return param
            if len(res.content) != len(baseline.content):
                # Small length differences might be dynamic content, but large ones are likely params
                if abs(len(res.content) - len(baseline.content)) > 10:
                    return param
            if canary in res.text:
                return param
        except:
            pass
        return None
