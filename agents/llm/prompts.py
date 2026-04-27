"""
agents/llm/prompts.py — Vulnerability Analysis Prompt Templates

All prompts are crafted for security-focused code analysis with local LLMs.
They are designed to produce structured JSON output that can be parsed
directly into Finding objects.
"""

from __future__ import annotations

# ─── System Prompt ───────────────────────────────────────────────────

SYSTEM_VULN_ANALYST = """You are a strict security analysis engine and elite researcher.
Your sole purpose is to find real, testable vulnerabilities in code and web applications.

Rules:
1. Analyze ONLY the provided endpoints or code chunks.
2. DO NOT invent endpoints or assume hidden routes. If it is not listed, ignore it completely.
3. DO NOT GUESS. DO NOT INVENT reality. Only reason on verified inputs.
4. Return ONLY real, testable vulnerabilities with exact payloads.
5. If no real vulnerability exists, you MUST return: {"vulnerabilities": []}
6. Assign accurate severity and provide technical reasoning.
7. Trust ONLY the facts provided in the prompt.
8. Be creative but grounded. Think about how an attacker would chain these findings or bypass filters.
9. Look for logical flaws and state-machine violations that automated scanners often miss.
"""


# ─── Code Analysis Prompts ───────────────────────────────────────────

def code_analysis_prompt(code: str, language: str, file_path: str = "", past_learnings: str = "") -> str:
    loc = f" ({file_path})" if file_path else ""
    learnings_block = f"\n<past_experiences>\n{past_learnings}\n</past_experiences>\n" if past_learnings else ""
    return f"""Analyze the following {language} code{loc} for security vulnerabilities.{learnings_block}

Look for ALL of these vulnerability classes:
- Injection (SQL, Command, LDAP, XPath, SSTI, NoSQL)
- XSS (reflected, stored, DOM-based, blind)
- Insecure deserialization (Python pickle, Java serialization, Node.js serialize)
- Broken authentication / session management
- Sensitive data exposure (hardcoded secrets, insecure storage, PII)
- Broken access control / IDOR / BOLA / BOPA
- Security misconfiguration (Default creds, debug modes, excessive permissions)
- Vulnerable components / unsafe imports / Supply chain risks
- SSRF / open redirect / Host header injection
- Race conditions / TOCTOU / HTTP Request Smuggling
- Integer overflows / arithmetic errors / Business logic flaws
- Memory safety (if C/C++/Rust)
- Path traversal / LFI / RFI
- Weak cryptography / Insecure random / Padding oracles
- JWT/OAuth flaws / SAML vulnerabilities
- API Security (Mass assignment, Improper Assets Management)

Code to analyze:
```{language}
{code}
```

Return a JSON object with this exact structure:
{{
  "vulnerabilities": [
    {{
      "title": "Short descriptive title",
      "category": "sql_injection|xss|command_injection|ssrf|path_traversal|auth_bypass|...",
      "severity": "critical|high|medium|low|info",
      "line_number": 42,
      "description": "Detailed explanation of the vulnerability and why it is exploitable",
      "code_snippet": "The specific vulnerable code line(s)",
      "poc": "Step-by-step proof of concept or exploit payload",
      "remediation": "How to fix this vulnerability",
      "cve_references": ["CVE-2021-44228"],
      "cvss_score": 9.8,
      "confidence": 0.95
    }}
  ],
  "summary": "Brief overall security assessment",
  "risk_rating": "critical|high|medium|low",
  "interesting_observations": ["Any noteworthy patterns that may become vulnerabilities with more context"]
}}

If no vulnerabilities are found, return {{"vulnerabilities": [], "summary": "No vulnerabilities detected", "risk_rating": "info", "interesting_observations": []}}
"""


def auth_audit_prompt(code: str, language: str) -> str:
    return f"""Perform a focused authentication and authorization security audit on this {language} code.

Specifically check for:
1. Authentication bypass possibilities
2. Missing authentication checks
3. Weak session management (predictable tokens, no expiry, no revocation)
4. JWT vulnerabilities (alg:none, weak secret, no expiry, missing claims validation)
5. OAuth 2.0 misconfigurations (implicit flow, open redirects, CSRF on callback)
6. Privilege escalation paths
7. IDOR (Insecure Direct Object References)
8. Broken object-level authorization (BOLA/BOLA)
9. Mass assignment vulnerabilities
10. Password handling flaws (cleartext, weak hashing)

Code:
```{language}
{code}
```

Return JSON with the same vulnerability structure as the full code analysis.
"""


def taint_analysis_prompt(sources: str, sinks: str, language: str) -> str:
    return f"""Perform taint analysis on this {language} code.

I have identified the following:

SOURCES (untrusted user input entry points):
{sources}

SINKS (dangerous operations that could be exploited):
{sinks}

For each source→sink path you identify:
1. Trace the data flow from source to sink
2. Determine if sanitization/validation is applied (and if it's sufficient)
3. Classify the vulnerability type
4. Provide a concrete attack payload

Return JSON with vulnerability findings.
"""


def crypto_audit_prompt(code: str, language: str) -> str:
    return f"""Audit this {language} code for cryptographic vulnerabilities.

Check for:
1. Use of deprecated/broken algorithms (MD5, SHA1, DES, RC4, ECB mode)
2. Hardcoded encryption keys or IVs
3. Insufficient key lengths
4. Predictable random number generation (use of rand(), Math.random() for security, etc.)
5. Insecure key storage
6. Missing TLS verification
7. Padding oracle vulnerabilities
8. Timing attacks in comparison functions

Code:
```{language}
{code}
```

Return JSON with vulnerability findings.
"""


# ─── Web Application Prompts ─────────────────────────────────────────

def web_response_analysis_prompt(
    url: str,
    method: str,
    request_headers: str,
    request_body: str,
    response_status: int,
    response_headers: str,
    response_body: str,
    past_learnings: str = "",
) -> str:
    learnings_block = f"\n<past_experiences>\n{past_learnings}\n</past_experiences>\n" if past_learnings else ""
    return f"""Analyze this HTTP interaction for security vulnerabilities and information disclosure.{learnings_block}

REQUEST:
{method} {url}
Headers: {request_headers}
Body: {request_body}

RESPONSE:
Status: {response_status}
Headers: {response_headers}
Body (first 2000 chars): {response_body[:2000]}

Check for:
1. Information disclosure in headers (Server version, X-Powered-By, stack traces)
2. Missing security headers (CSP, HSTS, X-Frame-Options, etc.)
3. Sensitive data in response (tokens, passwords, PII, internal paths)
4. Error messages that reveal system internals
5. SQL error messages
6. Path disclosure
7. Debug information
8. API keys or credentials in response
9. CORS misconfiguration
10. Cookie security flags (HttpOnly, Secure, SameSite)
11. JWT tokens — decode and check algorithms/expiry
12. Signs of SQL injection in URL parameters
13. Reflected content (XSS potential)

Return JSON with vulnerability findings. Include specific header/value evidence.
"""


def endpoint_fuzz_prompt(
    url: str,
    parameters: list,
    description: str = "",
) -> str:
    param_list = "\n".join(f"  - {p}" for p in parameters)
    return f"""I am fuzzing the following endpoint:
URL: {url}
Parameters found: 
{param_list}
Context: {description}

Based on the parameter names and URL patterns, suggest:
1. Which vulnerability types to test for each parameter
2. The most likely high-impact attack vectors
3. Specific payloads to try first (most likely to succeed)
4. Any unusual parameter names that suggest hidden functionality

Return a JSON object:
{{
  "parameter_risks": [
    {{
      "parameter": "id",
      "likely_vulnerabilities": ["sql_injection", "idor"],
      "priority_payloads": ["1 OR 1=1", "1; DROP TABLE users--"],
      "reasoning": "Numeric ID parameter commonly vulnerable to SQLi and IDOR"
    }}
  ],
  "recommended_attack_order": ["idor", "sql_injection", "xss"],
  "high_priority_params": ["id", "user"],
  "notes": "..."
}}
"""


# ─── Binary / Reverse Engineering Prompts ────────────────────────────

def binary_function_prompt(decompiled_code: str, function_name: str) -> str:
    return f"""Analyze this decompiled function for security vulnerabilities.
Function: {function_name}

Decompiled code:
```c
{decompiled_code}
```

Focus on:
1. Buffer overflows (strcpy, sprintf, gets, memcpy with user-controlled length)
2. Use-after-free patterns
3. Integer overflows (especially in size calculations)
4. Format string vulnerabilities
5. Null pointer dereferences
6. Race conditions (global state, non-atomic operations)
7. Off-by-one errors
8. Unchecked return values

Return JSON with vulnerability findings including estimated CVSS score and exploitation complexity.
"""


# ─── Network Service Prompts ──────────────────────────────────────────

def service_analysis_prompt(
    host: str,
    port: int,
    service: str,
    banner: str,
    version: str = "",
) -> str:
    return f"""Analyze this network service for known vulnerabilities and security issues.

Target: {host}:{port}
Service: {service}
Banner: {banner}
Version: {version or 'Unknown'}

Provide:
1. Known CVEs for this service/version
2. Default credentials to try
3. Common misconfigurations for this service
4. Attack surface assessment
5. Recommended exploitation approach for pentesting

Return JSON with vulnerability findings and attack recommendations.
"""


# ─── Zero-Day Hypothesis Prompts ──────────────────────────────────────

def zero_day_hypothesis_prompt(code: str, language: str, context: str = "", past_learnings: str = "") -> str:
    learnings_block = f"\n<past_experiences>\n{past_learnings}\n</past_experiences>\n" if past_learnings else ""
    return f"""Think like a zero-day researcher. Analyze this {language} code for non-obvious, 
subtle vulnerabilities that automated scanners would miss.{learnings_block}

Context: {context}

Code:
```{language}
{code}
```

Ask yourself:
1. What assumptions does this code make that an attacker could violate?
2. What happens in edge cases or with unexpected input types?
3. Are there any state machine violations possible?
4. Could any operation overflow, underflow, or wraparound?
5. Is there any trust boundary that's crossed without validation?
6. Are there any time-of-check to time-of-use (TOCTOU) windows?
7. Could an attacker influence any "constants" through environment or config?
8. Are there any parser differential attacks possible?
9. What happens with extremely large or small inputs?
10. Are there any side-channel information leaks?

Return JSON with hypothesis-driven vulnerability findings, including your reasoning chain.
Each finding should include a field "reasoning_chain" explaining your thought process.
"""


# ─── PoC Generation ───────────────────────────────────────────────────

def poc_generation_prompt(
    title: str,
    description: str,
    category: str,
    code_snippet: str,
    target_url: str = "",
    language: str = "",
) -> str:
    target_info = f"Target URL: {target_url}" if target_url else f"Language: {language}"
    return f"""Generate a detailed proof-of-concept (PoC) for this vulnerability.

Vulnerability: {title}
Category: {category}
{target_info}

Description:
{description}

Vulnerable code/context:
{code_snippet}

Provide:
1. Step-by-step exploitation instructions
2. Actual exploit code or payload (Python requests, curl command, or code)
3. Expected output that confirms successful exploitation
4. Any prerequisites or conditions needed
5. Cleanup steps if applicable
6. CVSS score and vector string

Return as JSON:
{{
  "steps": ["Step 1: ...", "Step 2: ..."],
  "exploit_code": "#!/usr/bin/env python3\\n...",
  "expected_output": "...",
  "prerequisites": ["..."],
  "cvss_score": 8.5,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "notes": "..."
}}
"""


# ─── CVE Correlation ────────────────────────────────────────────────

def cve_correlation_prompt(
    finding_title: str,
    finding_description: str,
    relevant_cves: list,
) -> str:
    cve_list = "\n".join(
        f"  - {c['id']}: {c.get('description', '')[:200]}" for c in relevant_cves
    )
    return f"""I found this vulnerability and retrieved potentially related CVEs.
Match and rank the CVEs by relevance.

Finding: {finding_title}
Description: {finding_description}

Potentially related CVEs:
{cve_list}

Return JSON:
{{
  "matched_cves": [
    {{
      "cve_id": "CVE-2021-44228",
      "relevance_score": 0.95,
      "reason": "Why this CVE matches this finding",
      "cvss_score": 10.0
    }}
  ],
  "best_match": "CVE-2021-44228",
  "notes": "..."
}}
"""


# ─── Multi-Agent Reasoning Stack Prompts ─────────────────────────────

def planner_prompt(asset_model_json: str, code_chunk: str, past_experiences: str = "") -> str:
    exp_block = f"\n<past_experiences>\n{past_experiences}\n</past_experiences>\n" if past_experiences else ""
    return f"""You are the LLMPlanner, the brain of an Attack Graph Engine.
Your role is to analyze a classified attack surface and plan high-precision exploits.

<ATTACK_SURFACE>
{asset_model_json}
</ATTACK_SURFACE>

CODE/STRUCTURE CONTEXT:
```
{code_chunk}
```
{exp_block}

Task:
Analyze the classified endpoints in the <ATTACK_SURFACE> block.
Each endpoint has a 'type' (AUTH, COMMAND, FILE, SEARCH, CONSOLE, etc.) and an 'allowed_vulns' list.
Plan your attacks restricting yourself to these vulnerability families.

STRICT GROUNDING RULES:
1. The endpoint MUST exist in the provided <ATTACK_SURFACE> list. If not listed → DO NOT include it.
2. The vulnerability 'type' you choose MUST strongly map to one of the values listed in the endpoint's 'allowed_vulns' list. DO NOT suggest Command Injection on an AUTH endpoint if 'command_injection' is not in its allowed list.
3. Prioritize CONSOLE and COMMAND types first.
4. The "confidence" field MUST be a decimal number between 0.0 and 1.0. NEVER use words like "high" or "certain".
5. The "payload" field MUST be the EXACT string to inject, not a description.
6. If no real vulnerabilities logically fit within the parameters and allowed types, return: {{"risk_priorities": [], "vulnerabilities": []}}

Output ONLY this JSON structure (no markdown, no explanation):
{{
  "risk_priorities": ["/path1", "/path2"],
  "vulnerabilities": [
    {{
      "type": "Command Injection",
      "endpoint": "/cmd",
      "method": "GET",
      "param": "host",
      "payload": "127.0.0.1; id",
      "expected_behavior": "Response contains uid= indicating command execution",
      "success_indicator": "uid=",
      "confidence": 0.9,
      "reasoning": "The host parameter is passed to os.popen() without sanitization"
    }}
  ]
}}
"""


def analyzer_prompt(code_snippet: str, hypothesis: dict) -> str:
    return f"""You are the LLMAnalyzer. Confirm if a specific security hypothesis is valid by analyzing the code.

Hypothesis:
{hypothesis}

Code Snippet:
```
{code_snippet}
```

Task:
1. Trace data flows from sources (user input) to sinks (dangerous operations).
2. Check if sanitization/validation exists between source and sink.
3. If vulnerable, document the exact data flow chain.

RULES:
- "confidence" MUST be a decimal number between 0.0 and 1.0. NEVER use words.
- "is_vulnerable" MUST be true or false (boolean, not string).
- If not vulnerable, set is_vulnerable=false and confidence=0.0.

Return ONLY this JSON (no markdown, no explanation):
{{
  "is_vulnerable": true,
  "reasoning": "The host parameter from request.args flows directly into subprocess.call() at line 42 without any sanitization",
  "data_flow": "request.args['host'] -> subprocess.call(f'ping {{host}}')",
  "sink": "subprocess.call",
  "confidence": 0.85
}}
"""


def exploiter_prompt(confirmed_vuln: dict, endpoint_info: str, past_intelligence: str = "") -> str:
    intel_block = f"\n<past_intelligence>\n{past_intelligence}\n</past_intelligence>\n" if past_intelligence else ""
    return f"""You are the LLMExploiter. Generate an actionable, executable Proof-of-Concept for a confirmed vulnerability.

Confirmed Vulnerability:
{confirmed_vuln}

Endpoint/Context Info:
{endpoint_info}
{intel_block}

STRICT OUTPUT RULES:
1. "confidence" MUST be a decimal number (e.g., 0.95). NEVER a word.
2. "payload" MUST be a JSON object mapping parameter names to injected values.
3. "method" MUST be GET, POST, PUT, or DELETE.
4. "success_indicator" is the EXACT string to search for in the response to confirm exploitation.
5. "retry_variants" contains alternative payloads to try if the first fails.
6. The "curl" command MUST be copy-pasteable and start with "curl".
7. If you cannot generate a real PoC, return {{"name": "Unknown", "endpoint": "", "confidence": 0.0}}

Return ONLY this JSON (no markdown, no explanation):
{{
  "name": "Command Injection",
  "endpoint": "/cmd",
  "method": "GET",
  "payload": {{"host": "127.0.0.1; id"}},
  "success_indicator": "uid=",
  "confidence": 0.95,
  "curl": "curl 'http://TARGET/cmd?host=127.0.0.1;id'",
  "python_exploit": "import requests\\nr = requests.get('http://TARGET/cmd', params={{'host': '127.0.0.1; id'}})\\nprint(r.text)",
  "retry_variants": [
    {{"payload": {{"host": "127.0.0.1 && id"}}, "encoding": "none", "technique": "and_separator"}},
    {{"payload": {{"host": "127.0.0.1 | id"}}, "encoding": "none", "technique": "pipe_separator"}},
    {{"payload": {{"host": "127.0.0.1$(id)"}}, "encoding": "none", "technique": "subshell"}}
  ]
}}
"""


def verifier_prompt(fuzzer_result: str, evidence: str) -> str:
    return f"""You are the LLMVerifier. Analyze fuzzer results to distinguish true positives from false positives.

Fuzzer Result:
{fuzzer_result}

Evidence (HTTP Response snippet/Status/Headers):
{evidence}

STRICT OUTPUT RULES:
1. "is_valid" MUST be true or false (boolean).
2. "confidence" MUST be a decimal number between 0.0 and 1.0. NEVER use words.
3. Look for CONCRETE evidence: command output, SQL errors, reflected payloads, file contents.
4. Generic 200 OK responses WITHOUT specific indicators are NOT evidence — set is_valid=false.
5. A response that contains the success_indicator string IS evidence — set is_valid=true.

Return ONLY this JSON (no markdown, no explanation):
{{
  "is_valid": true,
  "evidence": "Response body contains 'uid=1000(www-data)' confirming command injection succeeded",
  "confidence": 0.95,
  "false_positive_reason": ""
}}
"""


def chain_synthesis_prompt(findings_summary: str) -> str:
    return f"""You are an elite penetration tester performing attack chain analysis.

Given the following individual vulnerability findings from a security scan,
identify realistic multi-step attack chains an attacker could execute.

Findings:
{findings_summary}

For each chain:
1. Describe the step-by-step exploitation path
2. Explain how each vulnerability enables the next step
3. Assess the combined impact (what can the attacker ultimately achieve?)
4. Assign an overall CVSS score for the chain

Return ONLY this JSON:
{{
  "chains": [
    {{
      "name": "Chain Name (e.g., 'SQLi to RCE Pipeline')",
      "steps": [
        {{"step": 1, "action": "Description of step", "category": "vuln_type"}}
      ],
      "impact": "What the attacker achieves",
      "cvss": 9.8,
      "confidence": 0.85
    }}
  ]
}}

If no meaningful chains exist, return {{"chains": []}}
"""
