"""
tools/poc_downloader.py — CVE PoC Fetcher & Safety Scanner

Downloads public exploit PoCs from CVE references and scans them for dangerous operations before use.
"""
import os
import re
import requests
from pathlib import Path
from typing import List, Dict

# Directory to store downloaded PoCs
POC_DIR = Path("poc_scripts")
POC_DIR.mkdir(exist_ok=True)

# Dangerous patterns to block
DANGEROUS_PATTERNS = [
    r"rm\s+-rf", r"os\.system\(.*rm ", r"subprocess.*rm ", r"pip install", r"apt-get install", r"curl .+\| sh", r"wget .+\| sh",
    r"chmod 777 /", r"useradd ", r"adduser ", r"sudo ", r"dd if=", r"mkfs", r"mount ", r"shutdown", r"reboot", r"nc -e", r"bash -i", r"powershell -Command"
]

SAFE_EXTENSIONS = [".py", ".sh", ".txt", ".md", ".pl", ".rb", ".js"]


def extract_poc_links(cve_references: List[str]) -> List[str]:
    """Return only links likely to be public PoCs (GitHub, ExploitDB, Gist, etc)."""
    poc_links = []
    for url in cve_references:
        if any(domain in url for domain in ["github.com", "exploit-db.com", "gist.github.com", "packetstormsecurity.com", "gitlab.com"]):
            poc_links.append(url)
    return poc_links


def download_poc(url: str) -> Path:
    """Download a PoC script from a URL to the sandbox directory."""
    filename = url.split("/")[-1]
    if not any(filename.endswith(ext) for ext in SAFE_EXTENSIONS):
        filename += ".txt"
    dest = POC_DIR / filename
    try:
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        dest.write_bytes(resp.content)
        return dest
    except Exception as e:
        print(f"[PoC Downloader] Failed to download {url}: {e}")
        return False


def scan_poc_for_dangerous_ops(path: Path) -> Dict:
    """Scan a PoC script for dangerous operations. Returns dict with 'safe' and 'reasons'."""
    try:
        text = path.read_text(errors="replace")
    except Exception as e:
        return {"safe": False, "reasons": [f"Could not read file: {e}"]}
    reasons = []
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            reasons.append(f"Pattern found: {pattern}")
    return {"safe": not reasons, "reasons": reasons}


def get_safe_pocs_for_cve(cve_references: List[str]) -> List[Path]:
    """For a list of CVE references, download and return only safe PoC scripts."""
    safe_pocs = []
    for url in extract_poc_links(cve_references):
        path = download_poc(url)
        if path:
            scan = scan_poc_for_dangerous_ops(path)
            if scan["safe"]:
                safe_pocs.append(path)
            else:
                print(f"[PoC Scanner] {path.name} blocked: {scan['reasons']}")
    return safe_pocs
