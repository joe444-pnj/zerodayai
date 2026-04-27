"""
core/finding_quality.py -- Finding trust scoring and evidence summarization

Turns raw findings into a more honest signal:
- trust score (0-100)
- trust tier
- short evidence signals
"""

from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List


def _get_value(finding: Any, name: str, default=None):
    if isinstance(finding, dict):
        return finding.get(name, default)
    return getattr(finding, name, default)


def _parse_raw_output(raw_output: Any) -> Dict[str, Any]:
    if not raw_output:
        return {}
    if isinstance(raw_output, dict):
        return raw_output
    if not isinstance(raw_output, str):
        return {}

    try:
        return json.loads(raw_output)
    except Exception:
        return {}


def score_finding(finding: Any) -> Dict[str, Any]:
    """Return a trust score, tier, and concise evidence signals for a finding."""
    score = 0
    signals: List[str] = []

    confidence = float(_get_value(finding, "confidence", 0.0) or 0.0)
    poc = _get_value(finding, "poc", "") or ""
    raw_output = _parse_raw_output(_get_value(finding, "raw_output", ""))
    file_path = _get_value(finding, "file_path")
    line_number = _get_value(finding, "line_number")
    url = _get_value(finding, "url")
    parameter = _get_value(finding, "parameter")
    payload = _get_value(finding, "payload")
    false_positive = bool(_get_value(finding, "false_positive", 0))
    agent = str(_get_value(finding, "agent", "") or "")

    if confidence >= 0.95:
        score += 18
        signals.append("very high model confidence")
    elif confidence >= 0.85:
        score += 14
        signals.append("high model confidence")
    elif confidence >= 0.70:
        score += 10
        signals.append("moderate model confidence")
    elif confidence > 0:
        score += 5
        signals.append("low model confidence")

    if poc:
        score += 16
        signals.append("proof-of-concept attached")

    if file_path:
        score += 10
        signals.append("file location captured")
        if line_number:
            score += 4
            signals.append("line number available")

    if url:
        score += 8
        signals.append("request target captured")
    if parameter:
        score += 4
        signals.append("parameter identified")
    if payload:
        score += 6
        signals.append("payload recorded")

    verification = raw_output.get("verification", {}) if isinstance(raw_output, dict) else {}
    ver_status = str(verification.get("status", "")).upper()
    if ver_status == "CONFIRMED":
        score += 28
        signals.append("multi-vector verification confirmed")
    elif ver_status == "LIKELY_REAL":
        score += 18
        signals.append("partial verification success")
    elif ver_status == "UNVERIFIED":
        score -= 8
        signals.append("verification did not confirm exploit")

    evidence = raw_output.get("evidence", {}) if isinstance(raw_output, dict) else {}
    if isinstance(evidence, dict):
        if evidence.get("status_code") or evidence.get("request_url"):
            score += 10
            signals.append("runtime HTTP evidence captured")
        if evidence.get("indicator_found"):
            score += 12
            signals.append("success indicator observed")

    if "request" in raw_output and "response" in raw_output:
        score += 12
        signals.append("request/response transcript stored")

    if agent in ("static", "AgentType.STATIC"):
        score += 6
        signals.append("detected from deterministic static analysis")
    elif agent in ("fuzzer", "AgentType.FUZZER", "network", "AgentType.NETWORK"):
        score += 8
        signals.append("observed during runtime probing")

    if false_positive:
        score = max(0, score - 40)
        signals.append("marked false positive")

    score = max(0, min(100, score))
    if score >= 85:
        tier = "verified"
    elif score >= 65:
        tier = "strong"
    elif score >= 45:
        tier = "moderate"
    else:
        tier = "weak"

    return {
        "score": score,
        "tier": tier,
        "signals": signals[:6],
    }


def summarize_trust(findings: Iterable[Any]) -> Dict[str, int]:
    summary = {"verified": 0, "strong": 0, "moderate": 0, "weak": 0}
    for finding in findings:
        tier = score_finding(finding)["tier"]
        summary[tier] = summary.get(tier, 0) + 1
    return summary
