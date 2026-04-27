"""
export_training_data.py — Export Agent Learnings to Fine-Tuning Dataset

Reads the 70K+ agent_learnings from zeroday.db and exports them as
a proper JSONL training dataset. Also deduplicates and enriches entries.

Usage:
    python export_training_data.py
    
Then create a custom model:
    ollama create zeroday-ai -f Modelfile
"""

import json
import sqlite3
import hashlib
from pathlib import Path
from collections import Counter

DB_PATH = "zeroday.db"
OUTPUT_PATH = "training_data.jsonl"


def export():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # ── Fetch all non-false-positive learnings ──
    cursor.execute("""
        SELECT pattern_context, outcome_notes, is_false_positive
        FROM agent_learnings
        WHERE outcome_notes IS NOT NULL 
          AND LENGTH(outcome_notes) > 10
    """)
    rows = cursor.fetchall()

    # ── Also enrich with actual confirmed findings ──
    cursor.execute("""
        SELECT 
            category, severity, title, description, 
            url, parameter, payload, poc, code_snippet,
            confidence
        FROM findings
        WHERE false_positive = 0
          AND confidence >= 0.7
    """)
    findings = cursor.fetchall()
    conn.close()

    # ── Deduplication ──
    seen_hashes = set()
    records = []
    category_counts = Counter()

    # Process learnings
    for row in rows:
        pattern = row["pattern_context"] or ""
        outcome = row["outcome_notes"] or ""
        is_fp = row["is_false_positive"]

        # Deduplicate by content hash
        content_hash = hashlib.md5(f"{pattern}||{outcome}".encode()).hexdigest()
        if content_hash in seen_hashes:
            continue
        seen_hashes.add(content_hash)

        # Build instruction based on content type
        if is_fp:
            instruction = "Analyze this pattern and explain why it is a false positive"
            output = f"FALSE POSITIVE: {outcome}"
        elif "PoC" in outcome:
            instruction = "Analyze this code/endpoint for vulnerabilities and generate a proof-of-concept"
            output = outcome
        else:
            instruction = "Analyze this code/context for security vulnerabilities"
            output = outcome

        # Categorize
        vuln_type = _extract_vuln_type(outcome)
        category_counts[vuln_type] += 1

        records.append({
            "instruction": instruction,
            "input": pattern,
            "output": output,
            "category": vuln_type,
        })

    # Process confirmed findings (richer data)
    for f in findings:
        content_hash = hashlib.md5(
            f"{f['title']}||{f['url'] or f['code_snippet'] or ''}".encode()
        ).hexdigest()
        if content_hash in seen_hashes:
            continue
        seen_hashes.add(content_hash)

        # Build rich training example from finding
        input_ctx = []
        if f["url"]:
            input_ctx.append(f"Endpoint: {f['url']}")
        if f["parameter"]:
            input_ctx.append(f"Parameter: {f['parameter']}")
        if f["code_snippet"]:
            input_ctx.append(f"Code:\n{f['code_snippet']}")
        if f["payload"]:
            input_ctx.append(f"Payload: {f['payload']}")

        output_parts = [
            f"Vulnerability: {f['title']}",
            f"Category: {f['category']}",
            f"Severity: {f['severity']}",
            f"Confidence: {f['confidence']}",
            f"Description: {f['description']}",
        ]
        if f["poc"]:
            output_parts.append(f"PoC: {f['poc']}")

        records.append({
            "instruction": f"Find {f['category']} vulnerabilities and generate a proof-of-concept",
            "input": "\n".join(input_ctx),
            "output": "\n".join(output_parts),
            "category": f["category"] or "other",
        })
        category_counts[f["category"] or "other"] += 1

    # ── Write JSONL ──
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

    # ── Print statistics ──
    print(f"\n{'='*60}")
    print(f"  ZeroDay AI — Training Data Export")
    print(f"{'='*60}")
    print(f"  Source DB:         {DB_PATH}")
    print(f"  Raw learnings:     {len(rows):,}")
    print(f"  Confirmed findings:{len(findings):,}")
    print(f"  After dedup:       {len(records):,}")
    print(f"  Output file:       {OUTPUT_PATH}")
    print(f"  File size:         {Path(OUTPUT_PATH).stat().st_size / 1024 / 1024:.1f} MB")
    print(f"\n  Category Breakdown:")
    for cat, count in category_counts.most_common(15):
        print(f"    {cat:30s} {count:>6,}")
    print(f"\n  Next steps:")
    print(f"    1. ollama create zeroday-ai -f Modelfile")
    print(f"    2. Update config.yaml: model: zeroday-ai")
    print(f"{'='*60}\n")


def _extract_vuln_type(text: str) -> str:
    """Extract vulnerability type from outcome text."""
    text_lower = text.lower()
    type_map = {
        "buffer overflow": "buffer_overflow",
        "xss": "xss",
        "cross-site scripting": "xss",
        "sql injection": "sql_injection",
        "sqli": "sql_injection",
        "command injection": "command_injection",
        "cmd injection": "command_injection",
        "rce": "command_injection",
        "path traversal": "path_traversal",
        "directory traversal": "path_traversal",
        "lfi": "path_traversal",
        "ssrf": "ssrf",
        "ssti": "ssti",
        "xxe": "xxe",
        "deserialization": "deserialization",
        "auth bypass": "auth_bypass",
        "idor": "broken_access",
        "weak crypto": "weak_crypto",
        "hardcoded": "hardcoded_creds",
        "information disclosure": "sensitive_exposure",
        "race condition": "race_condition",
        "format string": "format_string",
        "null dereference": "null_dereference",
        "use after free": "use_after_free",
        "integer overflow": "integer_overflow",
        "uninitialized": "other",
        "input validation": "other",
        "misconfiguration": "misconfiguration",
    }
    for keyword, category in type_map.items():
        if keyword in text_lower:
            return category
    return "other"


if __name__ == "__main__":
    export()
