"""
knowledge/cve_loader.py — NVD CVE Data Fetcher & Cache Builder

Downloads recent CVE data from the NVD API and caches it locally
as a JSON file for the RAG knowledge base.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlencode

import requests
from rich.console import Console
from rich.progress import BarColumn, Progress, TextColumn, TimeRemainingColumn

console = Console()

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_CACHE = Path("knowledge/cve_cache.json")
PAGE_SIZE = 2000
REQUEST_TIMEOUT = 30


def fetch_cves(
    api_key: str = "",
    days_back: int = 365,
    cache_path: Path = DEFAULT_CACHE,
    force_refresh: bool = False,
) -> List[Dict]:
    cache_path.parent.mkdir(parents=True, exist_ok=True)

    # Use cache if fresh enough
    if cache_path.exists() and not force_refresh:
        age_hours = (time.time() - cache_path.stat().st_mtime) / 3600
        if age_hours < 24:
            console.print(f"[green]✓ Using cached CVE data ({cache_path})[/green]")
            return json.loads(cache_path.read_text())
        console.print(f"[yellow]Cache is {age_hours:.0f}h old, refreshing...[/yellow]")

    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=days_back)
    pub_start = start_date.strftime("%Y-%m-%dT00:00:00.000")
    pub_end   = end_date.strftime("%Y-%m-%dT23:59:59.999")

    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    all_cves: List[Dict] = []
    start_index = 0
    total_results = None

    console.print(f"[cyan]Fetching CVEs from NVD (last {days_back} days)...[/cyan]")

    with Progress(
        TextColumn("[cyan]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeRemainingColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Downloading CVEs", total=1)

        while True:
            params = {
                "pubStartDate": pub_start,
                "pubEndDate": pub_end,
                "startIndex": start_index,
                "resultsPerPage": PAGE_SIZE,
            }
            
            retry_count = 0
            max_retries = 3
            data = None
            
            while retry_count < max_retries and data is None:
                try:
                    resp = requests.get(
                        NVD_API_URL,
                        params=params,
                        headers=headers,
                        timeout=REQUEST_TIMEOUT,
                        allow_redirects=True
                    )
                    
                    if resp.status_code == 403:
                        console.print("[yellow]NVD rate limit hit. Waiting 30s...[/yellow]")
                        time.sleep(30)
                        retry_count += 1
                        continue
                    elif resp.status_code == 404:
                        console.print(f"[yellow]NVD API 404 - endpoint may have changed. Attempting fallback...[/yellow]")
                        console.print(f"[dim]Request URL: {resp.url}[/dim]")
                        retry_count += 1
                        time.sleep(2)
                        continue
                    elif resp.status_code >= 500:
                        console.print(f"[yellow]NVD server error ({resp.status_code}). Retrying in 15s...[/yellow]")
                        time.sleep(15)
                        retry_count += 1
                        continue
                    
                    resp.raise_for_status()
                    data = resp.json()
                    
                except requests.exceptions.Timeout:
                    console.print(f"[yellow]Request timeout. Retrying ({retry_count+1}/{max_retries})...[/yellow]")
                    retry_count += 1
                    time.sleep(5)
                except requests.exceptions.ConnectionError as e:
                    console.print(f"[yellow]Connection error: {e}. Retrying ({retry_count+1}/{max_retries})...[/yellow]")
                    retry_count += 1
                    time.sleep(5)
                except Exception as e:
                    console.print(f"[red]NVD API error: {e}[/red]")
                    retry_count += 1
                    time.sleep(2)
            
            if data is None:
                console.print(f"[red]Failed to fetch CVEs after {max_retries} retries[/red]")
                break

            if total_results is None:
                total_results = data.get("totalResults", 0)
                progress.update(task, total=total_results)

            vuln_list = data.get("vulnerabilities", [])
            if not vuln_list:
                break

            for item in vuln_list:
                cve = item.get("cve", {})
                cve_id = cve.get("id", "")
                descriptions = cve.get("descriptions", [])
                desc = next(
                    (d["value"] for d in descriptions if d.get("lang") == "en"),
                    ""
                )
                metrics = cve.get("metrics", {})
                cvss_score = _extract_cvss(metrics)
                cwe_list = [
                    p.get("value", "")
                    for p in cve.get("weaknesses", [{}])[0].get("description", [])
                    if p.get("lang") == "en"
                ] if cve.get("weaknesses") else []

                all_cves.append({
                    "id": cve_id,
                    "description": desc,
                    "cvss_score": cvss_score,
                    "cwe_id": cwe_list[0] if cwe_list else "",
                    "published": cve.get("published", ""),
                    "references": [
                        r.get("url", "") for r in cve.get("references", [])[:5]
                    ],
                })

            start_index += PAGE_SIZE
            progress.update(task, completed=min(start_index, total_results or start_index))

            if start_index >= (total_results or 0):
                break

            # Respect NVD rate limits (5 req/30s without key, 50/30s with key)
            time.sleep(6 if not api_key else 0.6)

    console.print(f"[green]✓ Downloaded {len(all_cves):,} CVEs[/green]")

    if all_cves:
        cache_path.write_text(json.dumps(all_cves, indent=2))
        console.print(f"[green]✓ Saved to {cache_path}[/green]")

    return all_cves


def _extract_cvss(metrics: Dict) -> float:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if entries := metrics.get(key):
            for entry in entries:
                if score := (
                    entry.get("cvssData", {}).get("baseScore")
                    or entry.get("baseScore")
                ):
                    return float(score)
    return 0.0


if __name__ == "__main__":
    from core.config import get_config
    cfg = get_config()
    fetch_cves(
        api_key=cfg.nvd_api_key,
        days_back=cfg.knowledge.cve_lookback_days,
        cache_path=Path(cfg.knowledge.cve_cache_path),
        force_refresh=True,
    )
