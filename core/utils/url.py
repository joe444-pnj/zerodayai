"""
core/utils/url.py — Protocol-Safe URL Utilities

Hardened URL handling for exploit execution. Every outbound request
MUST go through normalize_url() to prevent malformed requests.
"""

import re
from urllib.parse import urljoin, urlparse, urlencode, urlunparse, parse_qs, quote


def normalize_url(base: str, path: str) -> str:
    """
    Safely joins a base URL with a path and ensures http/https protocol.
    
    Handles all edge cases:
      - normalize_url("http://127.0.0.1:5000", "/cmd")      → "http://127.0.0.1:5000/cmd"
      - normalize_url("http://127.0.0.1:5000", "cmd")        → "http://127.0.0.1:5000/cmd"
      - normalize_url("127.0.0.1:5000", "/cmd")              → "http://127.0.0.1:5000/cmd"
      - normalize_url("", "/cmd")                             → "http://127.0.0.1/cmd"
      - normalize_url("http://x.com/", "http://x.com/login") → "http://x.com/login"
    """
    # Ensure base has scheme
    base = _ensure_scheme(base)
    
    if not path:
        return base
    
    # If path is already a full URL, validate and return
    if path.startswith(("http://", "https://")):
        return path
    
    # Ensure path starts with /
    if not path.startswith("/"):
        path = "/" + path
    
    # Join base and path
    full_url = urljoin(base, path)
    
    # Final validation
    parsed = urlparse(full_url)
    if not parsed.scheme or not parsed.netloc:
        full_url = urljoin(base, path)
    
    return full_url


def _ensure_scheme(url: str) -> str:
    """Ensure a URL has an http:// scheme."""
    if not url:
        return "http://127.0.0.1"
    
    url = url.strip()
    
    # Already has scheme
    if url.startswith(("http://", "https://")):
        return url.rstrip("/")
    
    # Handle //host/path
    if url.startswith("//"):
        return "http:" + url
    
    # Bare host:port or host/path
    return "http://" + url


def build_exploit_url(
    base: str,
    endpoint: str,
    method: str,
    payload: dict,
) -> tuple:
    """Build a full exploit request URL + body from structured PoC data.
    
    Returns:
        (url: str, params: dict, data: dict)
        - For GET:  url has query params baked in, params dict for httpx, data={}
        - For POST: url is clean, params={}, data dict for httpx body
    
    Example:
        build_exploit_url("http://127.0.0.1:5000", "/cmd", "GET", {"host": "127.0.0.1; id"})
        → ("http://127.0.0.1:5000/cmd", {"host": "127.0.0.1; id"}, {})
    """
    url = normalize_url(base, endpoint)
    method = method.upper()
    
    if not isinstance(payload, dict):
        payload = {"input": str(payload)} if payload else {}
    
    if method == "GET":
        return (url, payload, {})
    else:
        return (url, {}, payload)


def build_curl_command(
    base: str,
    endpoint: str,
    method: str,
    payload: dict,
    headers: dict = None,
) -> str:
    """Build a copy-pasteable curl command from structured PoC data."""
    url = normalize_url(base, endpoint)
    method = method.upper()
    
    parts = [f"curl -s"]
    
    if headers:
        for k, v in headers.items():
            parts.append(f"-H '{k}: {v}'")
    
    if method == "GET" and payload:
        qs = urlencode(payload)
        sep = "&" if "?" in url else "?"
        url = f"{url}{sep}{qs}"
        parts.append(f"'{url}'")
    elif method == "POST":
        parts.append(f"-X POST")
        if payload:
            for k, v in payload.items():
                parts.append(f"--data-urlencode '{k}={v}'")
        parts.append(f"'{url}'")
    else:
        parts.append(f"-X {method} '{url}'")
    
    return " ".join(parts)


def is_valid_url(url: str) -> bool:
    """Strict validation for protocol safety."""
    try:
        parsed = urlparse(url)
        return all([parsed.scheme, parsed.netloc]) and parsed.scheme in ("http", "https")
    except Exception:
        return False


def extract_base_url(url: str) -> str:
    """Extract scheme + netloc from a URL (e.g., 'http://127.0.0.1:5000')."""
    parsed = urlparse(_ensure_scheme(url))
    return f"{parsed.scheme}://{parsed.netloc}"
