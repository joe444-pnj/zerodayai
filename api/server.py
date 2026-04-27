"""
api/server.py — FastAPI Backend + Built-in Web Dashboard

Serves the ZeroDay AI REST API and a beautiful self-contained
dashboard via Jinja2 templates (no npm / build step required).

Start with:  python -m uvicorn api.server:app --reload --port 8000
Then open:   http://localhost:8000
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Optional

if sys.platform == "win32":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        sys.stderr.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import select, func
from sqlalchemy.orm import selectinload

from api.scan_runtime import scan_manager
from core.config import get_config
from core.database import close_db, get_session, init_db
from core.finding_quality import score_finding
from core.models import Finding, Scan, Severity

cfg = get_config()

app = FastAPI(
    title="ZeroDay AI",
    description="Autonomous Vulnerability Research Agent API",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=cfg.api_server.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup():
    await init_db()


@app.on_event("shutdown")
async def shutdown():
    await scan_manager.shutdown()
    await close_db()


class ScanCreateRequest(BaseModel):
    target: str = Field(..., min_length=1)
    label: str = ""
    model: str = ""
    output_dir: str = ""
    run_static: bool = True
    run_llm: bool = True
    run_fuzzer: bool = True
    run_network: bool = True
    zero_day_mode: bool = False


# ─── Dashboard HTML ───────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    """Serve the built-in web dashboard."""
    return HTMLResponse(content=_DASHBOARD_HTML)


# ─── REST API ─────────────────────────────────────────────────────────

@app.get("/api/scans")
async def list_scans(limit: int = 20, offset: int = 0):
    async with get_session() as session:
        result = await session.execute(
            select(Scan).options(selectinload(Scan.findings)).order_by(Scan.created_at.desc()).limit(limit).offset(offset)
        )
        scans = result.scalars().all()
        return [_scan_to_dict(s) for s in scans]


@app.post("/api/scans", status_code=202)
async def create_scan(payload: ScanCreateRequest):
    runtime = await scan_manager.start_scan(
        target=payload.target,
        label=payload.label,
        model=payload.model,
        output_dir=payload.output_dir,
        run_static=payload.run_static,
        run_llm=payload.run_llm,
        run_fuzzer=payload.run_fuzzer,
        run_network=payload.run_network,
        zero_day_mode=payload.zero_day_mode,
    )
    return runtime.snapshot()


@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str):
    async with get_session() as session:
        result = await session.execute(
            select(Scan).options(selectinload(Scan.findings)).where(Scan.id.startswith(scan_id))
        )
        scan = result.scalars().first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        return _scan_to_dict(scan)


@app.get("/api/scans/{scan_id}/runtime")
async def get_scan_runtime(scan_id: str):
    runtime = scan_manager.get(scan_id)
    if runtime:
        return runtime.snapshot()

    async with get_session() as session:
        result = await session.execute(select(Scan).options(selectinload(Scan.findings)).where(Scan.id.startswith(scan_id)))
        scan = result.scalars().first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        report_dir = Path(cfg.reporting.output_dir) / scan.id[:8]
        return {
            **_scan_to_dict(scan),
            "phase": "completed" if scan.status else "unknown",
            "active": False,
            "reports": {
                "json": str(report_dir / "report.json"),
                "markdown": str(report_dir / "report.md"),
            },
            "last_event_id": 0,
        }


@app.get("/api/scans/{scan_id}/events")
async def stream_scan_events(scan_id: str, after: int = 0):
    if not scan_manager.get(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")
    stream = scan_manager.stream(scan_id, after=after)

    return StreamingResponse(
        stream,
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.post("/api/scans/{scan_id}/cancel")
async def cancel_scan(scan_id: str):
    cancelled = await scan_manager.cancel_scan(scan_id)
    if not cancelled:
        raise HTTPException(status_code=409, detail="Scan is not running")
    return {"success": True, "scan_id": scan_id}


@app.get("/api/scans/{scan_id}/findings")
async def get_findings(
    scan_id: str,
    severity: Optional[str] = None,
    category: Optional[str] = None,
    limit: int = 100,
):
    async with get_session() as session:
        query = select(Finding).where(Finding.scan_id.startswith(scan_id))
        if severity:
            query = query.where(Finding.severity == severity)
        if category:
            query = query.where(Finding.category == category)
        query = query.order_by(Finding.created_at.desc()).limit(limit)
        result = await session.execute(query)
        findings = result.scalars().all()
        return [_finding_to_dict(f) for f in findings]


@app.get("/api/scans/{scan_id}/reports/{report_format}")
async def download_report(scan_id: str, report_format: str):
    if report_format not in {"json", "markdown"}:
        raise HTTPException(status_code=400, detail="report_format must be 'json' or 'markdown'")

    runtime = scan_manager.get(scan_id)
    if runtime and runtime.reports.get(report_format):
        report_path = Path(runtime.reports[report_format])
        if report_path.exists():
            media_type = "application/json" if report_format == "json" else "text/markdown"
            return FileResponse(report_path, media_type=media_type, filename=report_path.name)

    async with get_session() as session:
        result = await session.execute(select(Scan).options(selectinload(Scan.findings)).where(Scan.id.startswith(scan_id)))
        scan = result.scalars().first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

    suffix = "report.json" if report_format == "json" else "report.md"
    media_type = "application/json" if report_format == "json" else "text/markdown"
    report_path = Path(cfg.reporting.output_dir) / scan.id[:8] / suffix
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report not found")

    return FileResponse(report_path, media_type=media_type, filename=report_path.name)


@app.get("/api/stats")
async def get_stats():
    async with get_session() as session:
        total_scans = (await session.execute(select(func.count(Scan.id)))).scalar()
        total_findings = (await session.execute(select(func.count(Finding.id)))).scalar()
        crits = (await session.execute(
            select(func.count(Finding.id)).where(Finding.severity == Severity.CRITICAL)
        )).scalar()
        highs = (await session.execute(
            select(func.count(Finding.id)).where(Finding.severity == Severity.HIGH)
        )).scalar()
        from core.models import AgentLearning
        total_learnings = (await session.execute(select(func.count(AgentLearning.id)))).scalar()
        return {
            "total_scans": total_scans,
            "total_findings": total_findings,
            "total_learnings": total_learnings,
            "critical": crits,
            "high": highs,
        }


@app.patch("/api/findings/{finding_id}/false-positive")
async def mark_false_positive(finding_id: str, is_fp: bool = True):
    async with get_session() as session:
        result = await session.execute(
            select(Finding).where(Finding.id == finding_id)
        )
        finding = result.scalars().first()
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")
        finding.false_positive = 1 if is_fp else 0
        return {"success": True}


# ─── Serializers ──────────────────────────────────────────────────────

def _scan_to_dict(s: Scan) -> dict:
    return {
        "id": s.id, "target": s.target, "label": s.label,
        "status": s.status.value if s.status else "unknown",
        "finding_count": s.finding_count,
        "critical_count": s.critical_count,
        "high_count": s.high_count,
        "created_at": str(s.created_at)[:16] if s.created_at else None,
        "finished_at": str(s.finished_at)[:16] if s.finished_at else None,
    }


def _finding_to_dict(f: Finding) -> dict:
    trust = score_finding(f)
    return {
        "id": f.id, "title": f.title,
        "severity": f.severity.value if f.severity else "info",
        "category": f.category.value if f.category else "other",
        "agent": f.agent.value if f.agent else "unknown",
        "file_path": f.file_path, "line_number": f.line_number,
        "url": f.url, "parameter": f.parameter,
        "description": f.description, "code_snippet": f.code_snippet,
        "poc": f.poc, "remediation": f.remediation,
        "cve_ids": f.cve_ids, "cvss_score": f.cvss_score,
        "confidence": f.confidence, "false_positive": bool(f.false_positive),
        "trust_score": trust["score"],
        "trust_tier": trust["tier"],
        "trust_signals": trust["signals"],
        "created_at": str(f.created_at)[:16] if f.created_at else None,
    }


# ─── Embedded Dashboard HTML ──────────────────────────────────────────

_DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ZeroDay AI — Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js" defer></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
:root {
  --bg:       #080b12;
  --bg2:      #0d1117;
  --bg3:      #131a24;
  --border:   #1e2d3d;
  --accent:   #00e5ff;
  --accent2:  #7c3aed;
  --green:    #00ff88;
  --red:      #ff3b5c;
  --orange:   #ff7c2a;
  --yellow:   #ffd700;
  --text:     #e0e6f0;
  --muted:    #5a7090;
  --font:     'Inter', sans-serif;
  --mono:     'JetBrains Mono', monospace;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { background: var(--bg); color: var(--text); font-family: var(--font); min-height: 100vh; }

/* Scrollbar */
::-webkit-scrollbar { width: 6px; }
::-webkit-scrollbar-track { background: var(--bg2); }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }

/* Layout */
.app { display: flex; min-height: 100vh; }
.sidebar { width: 240px; background: var(--bg2); border-right: 1px solid var(--border); padding: 0; display: flex; flex-direction: column; flex-shrink: 0; }
.main { flex: 1; overflow: auto; }

/* Sidebar */
.logo { padding: 24px 20px 20px; border-bottom: 1px solid var(--border); }
.logo-title { font-size: 18px; font-weight: 700; color: var(--accent); letter-spacing: 1px; font-family: var(--mono); }
.logo-sub { font-size: 11px; color: var(--muted); margin-top: 2px; }
.nav { padding: 16px 12px; flex: 1; }
.nav-item { display: flex; align-items: center; gap: 10px; padding: 10px 12px; border-radius: 8px; cursor: pointer; font-size: 14px; color: var(--muted); transition: all 0.15s; margin-bottom: 4px; border: 1px solid transparent; }
.nav-item:hover { color: var(--text); background: rgba(0,229,255,0.05); border-color: rgba(0,229,255,0.1); }
.nav-item.active { color: var(--accent); background: rgba(0,229,255,0.1); border-color: rgba(0,229,255,0.2); }
.nav-icon { font-size: 16px; }
.status-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--green); box-shadow: 0 0 8px var(--green); margin-left: auto; }

/* Top bar */
.topbar { background: var(--bg2); border-bottom: 1px solid var(--border); padding: 16px 28px; display: flex; align-items: center; justify-content: space-between; }
.topbar-title { font-size: 20px; font-weight: 600; }
.topbar-actions { display: flex; gap: 12px; align-items: center; }
.btn { padding: 8px 16px; border-radius: 8px; border: 1px solid var(--border); background: var(--bg3); color: var(--text); cursor: pointer; font-size: 13px; font-family: var(--font); transition: all 0.15s; }
.btn:hover { border-color: var(--accent); color: var(--accent); }
.btn-primary { background: var(--accent); color: #000; border-color: var(--accent); font-weight: 600; }
.btn-primary:hover { background: #00c4e0; color: #000; }

/* Page content */
.page { padding: 28px; }

/* Stat cards */
.stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 28px; }
.stat-card { background: var(--bg2); border: 1px solid var(--border); border-radius: 12px; padding: 20px; position: relative; overflow: hidden; }
.stat-card::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 2px; }
.stat-card.critical::before { background: var(--red); }
.stat-card.high::before { background: var(--orange); }
.stat-card.scans::before { background: var(--accent); }
.stat-card.total::before { background: var(--accent2); }
.stat-label { font-size: 12px; color: var(--muted); font-weight: 500; text-transform: uppercase; letter-spacing: 0.5px; }
.stat-value { font-size: 36px; font-weight: 700; margin-top: 8px; font-family: var(--mono); }
.stat-card.critical .stat-value { color: var(--red); }
.stat-card.high .stat-value { color: var(--orange); }
.stat-card.scans .stat-value { color: var(--accent); }
.stat-card.total .stat-value { color: var(--accent2); }
.stat-glow { position: absolute; bottom: -20px; right: -20px; font-size: 60px; opacity: 0.05; }

/* Table */
.card { background: var(--bg2); border: 1px solid var(--border); border-radius: 12px; overflow: hidden; margin-bottom: 24px; }
.card-header { padding: 18px 24px; border-bottom: 1px solid var(--border); display: flex; align-items: center; justify-content: space-between; }
.card-title { font-size: 15px; font-weight: 600; }
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; }
th { padding: 12px 16px; text-align: left; font-size: 11px; font-weight: 600; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 1px solid var(--border); white-space: nowrap; }
td { padding: 14px 16px; font-size: 13px; border-bottom: 1px solid rgba(30,45,61,0.5); }
tr:last-child td { border-bottom: none; }
tr:hover td { background: rgba(0,229,255,0.02); }
.clickable { cursor: pointer; }

/* Severity badges */
.badge { display: inline-flex; align-items: center; gap: 5px; padding: 3px 10px; border-radius: 20px; font-size: 11px; font-weight: 600; font-family: var(--mono); letter-spacing: 0.5px; }
.badge-critical { background: rgba(255,59,92,0.15); color: var(--red); border: 1px solid rgba(255,59,92,0.3); }
.badge-high     { background: rgba(255,124,42,0.15); color: var(--orange); border: 1px solid rgba(255,124,42,0.3); }
.badge-medium   { background: rgba(255,215,0,0.15); color: var(--yellow); border: 1px solid rgba(255,215,0,0.3); }
.badge-low      { background: rgba(0,255,136,0.15); color: var(--green); border: 1px solid rgba(0,255,136,0.3); }
.badge-info     { background: rgba(0,229,255,0.15); color: var(--accent); border: 1px solid rgba(0,229,255,0.3); }

/* Modal */
.modal-backdrop { position: fixed; inset: 0; background: rgba(0,0,0,0.8); display: flex; align-items: center; justify-content: center; z-index: 100; padding: 24px; }
.modal { background: var(--bg2); border: 1px solid var(--border); border-radius: 16px; max-width: 780px; width: 100%; max-height: 85vh; overflow-y: auto; }
.modal-header { padding: 20px 24px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; }
.modal-body { padding: 24px; }
.field { margin-bottom: 20px; }
.field-label { font-size: 11px; font-weight: 600; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 6px; }
.field-value { font-size: 14px; line-height: 1.6; }
pre.code { background: var(--bg); border: 1px solid var(--border); border-radius: 8px; padding: 16px; font-family: var(--mono); font-size: 12px; overflow-x: auto; line-height: 1.6; color: var(--green); }
.close-btn { background: none; border: none; color: var(--muted); font-size: 20px; cursor: pointer; padding: 4px; }
.close-btn:hover { color: var(--text); }

/* Charts */
.chart-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 24px; }
.chart-card { background: var(--bg2); border: 1px solid var(--border); border-radius: 12px; padding: 24px; }
.chart-title { font-size: 14px; font-weight: 600; margin-bottom: 16px; }

/* Filters */
.filters { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
.filter-select { background: var(--bg3); border: 1px solid var(--border); color: var(--text); padding: 7px 12px; border-radius: 8px; font-size: 13px; font-family: var(--font); cursor: pointer; }
.filter-select:focus { outline: none; border-color: var(--accent); }

/* Empty state */
.empty { text-align: center; padding: 60px 20px; color: var(--muted); }
.empty-icon { font-size: 48px; margin-bottom: 16px; }

/* Loading */
.loading { display: flex; align-items: center; justify-content: center; padding: 40px; color: var(--muted); gap: 10px; }
@keyframes spin { to { transform: rotate(360deg); } }
.spinner { width: 20px; height: 20px; border: 2px solid var(--border); border-top-color: var(--accent); border-radius: 50%; animation: spin 0.8s linear infinite; }

/* Scan ID chip */
.scan-id { font-family: var(--mono); font-size: 12px; background: var(--bg3); padding: 3px 8px; border-radius: 4px; color: var(--muted); }

/* Confidence bar */
.conf-wrap { display: flex; align-items: center; gap: 8px; }
.conf-bar-bg { width: 60px; height: 4px; background: var(--border); border-radius: 2px; }
.conf-bar { height: 4px; border-radius: 2px; background: var(--accent); }
</style>
</head>
<body>
<div class="app" x-data="app()" x-init="init()">

  <!-- Sidebar -->
  <div class="sidebar">
    <div class="logo">
      <div class="logo-title">ZERODAY AI</div>
      <div class="logo-sub">Vulnerability Research Agent</div>
    </div>
    <nav class="nav">
      <div class="nav-item" :class="{active: page==='dashboard'}" @click="page='dashboard'; loadStats(); loadScans()">
        <span class="nav-icon">📊</span> Dashboard
        <div class="status-dot" x-show="page==='dashboard'"></div>
      </div>
      <div class="nav-item" :class="{active: page==='scans'}" @click="page='scans'; loadScans()">
        <span class="nav-icon">🔍</span> Scans
      </div>
      <div class="nav-item" :class="{active: page==='findings'}" @click="page='findings'; loadAllFindings()">
        <span class="nav-icon">🎯</span> All Findings
      </div>
    </nav>
  </div>

  <!-- Main -->
  <div class="main">
    <!-- Topbar -->
    <div class="topbar">
      <div class="topbar-title" x-text="pageTitle()"></div>
      <div class="topbar-actions">
        <span style="font-size:12px; color:var(--muted)" x-text="'API: ' + apiBase"></span>
        <button class="btn btn-primary" @click="launchScan()">+ New Scan</button>
        <button class="btn" @click="refresh()">↺ Refresh</button>
      </div>
    </div>

    <!-- Dashboard Page -->
    <div x-show="page==='dashboard'" class="page">
      <!-- Stats -->
      <div class="stats-grid">
        <div class="stat-card scans">
          <div class="stat-label">Total Scans</div>
          <div class="stat-value" x-text="stats.total_scans ?? '—'"></div>
          <div class="stat-glow">🔍</div>
        </div>
        <div class="stat-card total">
          <div class="stat-label">Intelligence Level</div>
          <div class="stat-value" x-text="(stats.total_learnings ?? 0).toLocaleString()"></div>
          <div class="stat-glow">🧠</div>
        </div>
        <div class="stat-card total">
          <div class="stat-label">Total Findings</div>
          <div class="stat-value" x-text="stats.total_findings ?? '—'"></div>
          <div class="stat-glow">🎯</div>
        </div>
        <div class="stat-card critical">
          <div class="stat-label">Critical</div>
          <div class="stat-value" x-text="stats.critical ?? '—'"></div>
          <div class="stat-glow">🔴</div>
        </div>
        <div class="stat-card high">
          <div class="stat-label">High</div>
          <div class="stat-value" x-text="stats.high ?? '—'"></div>
          <div class="stat-glow">🟠</div>
        </div>
      </div>

      <!-- Recent Scans -->
      <div class="card">
        <div class="card-header">
          <div class="card-title">Recent Scans</div>
        </div>
        <div class="table-wrap">
          <template x-if="scans.length === 0">
            <div class="empty"><div class="empty-icon">📭</div><p>No scans yet</p></div>
          </template>
          <div style="overflow-y:auto; max-height:300px; padding: 0 24px;">
            <template x-for="s in scans.slice(0,8)" :key="s.id || Math.random()">
              <div style="display:flex;align-items:center;justify-content:space-between;padding:12px 0;border-bottom:1px solid var(--border);" @click="selectScan(s)" class="clickable">
                <div>
                  <div style="font-size:14px;font-weight:600" x-text="s.target"></div>
                  <div style="font-size:12px;color:var(--muted);margin-top:4px" x-text="(s.created_at || 'Unknown') + ' • ' + (s.id || '').slice(0,8)"></div>
                </div>
                <div style="display:flex;gap:12px;align-items:center">
                  <span x-show="(s.critical_count || 0) > 0" style="color:var(--red);font-size:12px;font-weight:700" x-text="s.critical_count + ' CRIT'"></span>
                  <span style="font-size:12px;color:var(--muted)" x-text="(s.finding_count || 0) + ' total'"></span>
                </div>
              </div>
            </template>
          </div>
        </div>
      </div>

      <!-- Recent findings -->
      <div class="card">
        <div class="card-header">
          <div class="card-title">Latest Findings</div>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr><th>Severity</th><th>Title</th><th>Category</th><th>Agent</th><th>Location</th><th>Confidence</th></tr>
            </thead>
            <tbody>
              <template x-for="f in latestFindings" :key="f.id">
                <tr class="clickable" @click="selectedFinding = f">
                  <td><span class="badge" :class="'badge-' + f.severity" x-text="f.severity.toUpperCase()"></span></td>
                  <td style="max-width:300px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis" x-text="f.title"></td>
                  <td style="color:var(--muted);font-size:12px" x-text="f.category"></td>
                  <td style="color:var(--muted);font-size:12px" x-text="f.agent"></td>
                  <td style="font-family:var(--mono);font-size:11px;color:var(--muted)" x-text="(f.file_path || f.url || '—').slice(-35)"></td>
                  <td>
                    <div class="conf-wrap">
                      <div class="conf-bar-bg"><div class="conf-bar" :style="'width:' + ((f.confidence||0)*100) + '%'"></div></div>
                      <span style="font-size:11px;color:var(--muted)" x-text="Math.round((f.confidence||0)*100) + '%'"></span>
                    </div>
                  </td>
                </tr>
              </template>
            </tbody>
          </table>
          <div x-show="latestFindings.length === 0" class="empty">
            <div class="empty-icon">🎯</div>
            <p>No findings yet — run a scan!</p>
          </div>
        </div>
      </div>
    </div>

    <!-- Scans Page -->
    <div x-show="page==='scans'" class="page">
      <div class="card">
        <div class="card-header"><div class="card-title">All Scans</div></div>
        <div class="table-wrap">
          <table>
            <thead><tr><th>ID</th><th>Target</th><th>Status</th><th>Findings</th><th>Critical</th><th>Date</th><th></th></tr></thead>
            <tbody>
              <template x-for="s in scans" :key="s.id || Math.random()">
                <tr>
                  <td><span class="scan-id" x-text="(s.id || '').slice(0,8)"></span></td>
                  <td x-text="s.target || 'Unknown'"></td>
                  <td><span :style="s.status==='completed' ? 'color:var(--green)' : 'color:var(--yellow)'" x-text="s.status || 'unknown'"></span></td>
                  <td x-text="s.finding_count || 0"></td>
                  <td><span x-show="(s.critical_count || 0) > 0" style="color:var(--red);font-weight:700" x-text="s.critical_count"></span><span x-show="(s.critical_count || 0) === 0" style="color:var(--muted)">—</span></td>
                  <td style="color:var(--muted);font-size:12px" x-text="s.created_at || 'Unknown'"></td>
                  <td><button class="btn" @click="viewScanFindings(s)">Findings →</button></td>
                </tr>
              </template>
            </tbody>
          </table>
          <div x-show="scans.length === 0" class="empty"><div class="empty-icon">📭</div><p>No scans found</p></div>
        </div>
      </div>
    </div>

    <!-- All Findings Page -->
    <div x-show="page==='findings'" class="page">
      <div class="card">
        <div class="card-header">
          <div class="card-title">Findings <span style="color:var(--muted);font-weight:400" x-text="'(' + allFindings.length + ')'"></span></div>
          <div class="filters">
            <select class="filter-select" x-model="filterSev" @change="applyFilters()">
              <option value="">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
            </select>
            <select class="filter-select" x-model="filterAgent" @change="applyFilters()">
              <option value="">All Agents</option>
              <option value="static">Static</option>
              <option value="llm">LLM</option>
              <option value="fuzzer">Fuzzer</option>
              <option value="network">Network</option>
            </select>
          </div>
        </div>
        <div class="table-wrap">
          <table>
            <thead><tr><th>Severity</th><th>Title</th><th>Category</th><th>Agent</th><th>Location</th></tr></thead>
            <tbody>
              <template x-for="f in filteredFindings" :key="f.id">
                <tr class="clickable" @click="selectedFinding = f">
                  <td><span class="badge" :class="'badge-' + f.severity" x-text="f.severity.toUpperCase()"></span></td>
                  <td x-text="f.title"></td>
                  <td style="color:var(--muted);font-size:12px" x-text="f.category"></td>
                  <td style="color:var(--muted);font-size:12px" x-text="f.agent"></td>
                  <td style="font-family:var(--mono);font-size:11px;color:var(--muted)" x-text="(f.file_path || f.url || '—').slice(-40)"></td>
                </tr>
              </template>
            </tbody>
          </table>
          <div x-show="filteredFindings.length === 0" class="empty"><div class="empty-icon">🎯</div><p>No findings match filters</p></div>
        </div>
      </div>
    </div>
  </div>

  <!-- Finding Detail Modal -->
  <div class="modal-backdrop" x-show="selectedFinding" @click.self="selectedFinding=null" style="display:none">
    <div class="modal" @click.stop>
      <div class="modal-header">
        <div>
          <span class="badge" :class="'badge-' + (selectedFinding?.severity || 'info')" x-text="selectedFinding?.severity?.toUpperCase()"></span>
          <span style="font-size:16px;font-weight:600;margin-left:10px" x-text="selectedFinding?.title"></span>
        </div>
        <button class="close-btn" @click="selectedFinding=null">✕</button>
      </div>
      <div class="modal-body" x-show="selectedFinding">
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:20px">
          <div class="field">
            <div class="field-label">Category</div>
            <div class="field-value" x-text="selectedFinding?.category"></div>
          </div>
          <div class="field">
            <div class="field-label">Agent</div>
            <div class="field-value" x-text="selectedFinding?.agent"></div>
          </div>
          <div class="field" x-show="selectedFinding?.cvss_score">
            <div class="field-label">CVSS Score</div>
            <div class="field-value" style="font-family:var(--mono);color:var(--orange)" x-text="selectedFinding?.cvss_score"></div>
          </div>
          <div class="field" x-show="selectedFinding?.cve_ids">
            <div class="field-label">CVE IDs</div>
            <div class="field-value" style="font-family:var(--mono);color:var(--accent)" x-text="selectedFinding?.cve_ids"></div>
          </div>
          <div class="field" x-show="selectedFinding?.file_path">
            <div class="field-label">File</div>
            <div class="field-value" style="font-family:var(--mono);font-size:12px" x-text="selectedFinding?.file_path + (selectedFinding?.line_number ? ':' + selectedFinding?.line_number : '')"></div>
          </div>
          <div class="field" x-show="selectedFinding?.url">
            <div class="field-label">URL</div>
            <div class="field-value" style="font-family:var(--mono);font-size:12px" x-text="selectedFinding?.url"></div>
          </div>
        </div>
        <div class="field">
          <div class="field-label">Description</div>
          <div class="field-value" x-text="selectedFinding?.description"></div>
        </div>
        <div class="field" x-show="selectedFinding?.code_snippet">
          <div class="field-label">Code Snippet</div>
          <pre class="code" x-text="selectedFinding?.code_snippet"></pre>
        </div>
        <div class="field" x-show="selectedFinding?.poc">
          <div class="field-label" style="color:var(--red)">Proof of Concept</div>
          <pre class="code" style="color:var(--red)" x-text="selectedFinding?.poc"></pre>
        </div>
        <div class="field" x-show="selectedFinding?.remediation">
          <div class="field-label" style="color:var(--green)">Remediation</div>
          <div class="field-value" style="color:var(--green)" x-text="selectedFinding?.remediation"></div>
        </div>
        <div style="margin-top:20px;display:flex;gap:12px">
          <button class="btn" @click="markFP(selectedFinding)">Mark False Positive</button>
          <button class="btn" @click="selectedFinding=null">Close</button>
        </div>
      </div>
    </div>
  </div>

</div>

<script>
function app() {
  return {
    page: 'dashboard',
    apiBase: window.location.origin,
    stats: {},
    scans: [],
    latestFindings: [],
    allFindings: [],
    filteredFindings: [],
    selectedFinding: null,
    filterSev: '',
    filterAgent: '',
    sevChart: null,

    async init() {
      await this.loadStats();
      await this.loadScans();
      await this.loadLatestFindings();
    },

    pageTitle() {
      return { dashboard: 'Dashboard', scans: 'Scans', findings: 'All Findings' }[this.page] || 'ZeroDay AI';
    },

    async loadStats() {
      try {
        const r = await fetch(this.apiBase + '/api/stats');
        this.stats = await r.json();
      } catch(e) { console.warn('API unavailable:', e); }
    },

    async loadScans() {
      try {
        const r = await fetch(this.apiBase + '/api/scans?limit=20');
        this.scans = await r.json();
        if (this.page === 'dashboard') {
          await this.loadLatestFindings();
        }
      } catch(e) {}
    },

    async loadLatestFindings() {
      if (!this.scans.length) return;
      try {
        const id = this.scans[0].id;
        const r = await fetch(this.apiBase + '/api/scans/' + id + '/findings?limit=50');
        this.latestFindings = await r.json();
      } catch(e) {}
    },

    async loadAllFindings() {
      this.allFindings = [];
      for (const s of this.scans.slice(0, 5)) {
        try {
          const r = await fetch(this.apiBase + '/api/scans/' + s.id + '/findings?limit=100');
          const f = await r.json();
          this.allFindings.push(...f);
        } catch(e) {}
      }
      this.filteredFindings = [...this.allFindings];
    },

    applyFilters() {
      this.filteredFindings = this.allFindings.filter(f => {
        if (this.filterSev && f.severity !== this.filterSev) return false;
        if (this.filterAgent && f.agent !== this.filterAgent) return false;
        return true;
      });
    },

    async viewScanFindings(scan) {
      try {
        const r = await fetch(this.apiBase + '/api/scans/' + scan.id + '/findings?limit=200');
        this.allFindings = await r.json();
        this.filteredFindings = [...this.allFindings];
        this.page = 'findings';
      } catch(e) {}
    },

    async markFP(finding) {
      try {
        await fetch(this.apiBase + '/api/findings/' + finding.id + '/false-positive?is_fp=true', { method: 'PATCH' });
        finding.false_positive = true;
        alert('Marked as false positive.');
      } catch(e) {}
    },

    async launchScan() {
      const target = prompt('Scan target (path, URL, or IP)');
      if (!target) return;
      try {
        const r = await fetch(this.apiBase + '/api/scans', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ target })
        });
        const scan = await r.json();
        alert('Scan started: ' + scan.scan_id.slice(0, 8));
        this.page = 'scans';
        await this.loadScans();
        this.watchScan(scan.scan_id);
      } catch (e) {
        alert('Failed to start scan.');
      }
    },

    watchScan(scanId) {
      const events = new EventSource(this.apiBase + '/api/scans/' + scanId + '/events');
      events.addEventListener('scan_completed', async () => {
        events.close();
        await this.refresh();
      });
      events.addEventListener('scan_failed', async () => {
        events.close();
        await this.refresh();
      });
    },

    selectScan(scan) {
      this.viewScanFindings(scan);
    },

    async refresh() {
      await this.loadStats();
      await this.loadScans();
      if (this.page === 'dashboard') await this.loadLatestFindings();
      if (this.page === 'findings') await this.loadAllFindings();
    },

    drawChart() {
      // Chart removed
    }
  }
}
</script>
</body>
</html>"""
