# ZeroDay AI Security Report
**Scan ID:** 5ff729d1-09d7-4920-9b53-b8096f7f81bf
**Target:** https://pentest-ground.com:81/
**Started:** 2026-04-11 08:17:59.973346
**Finished:** None
**Total Findings:** 12

---

## Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High     | 1 |
| 🟡 Medium   | 3 |
| 🟢 Low      | 7 |
| 🔵 Info     | 1 |

---

## Findings


### 1. Possible Time-Based Blind SQLi — param 'id'

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Category** | sql_injection |
| **Agent** | fuzzer |


| **URL** | https://pentest-ground.com:81/1/edit?id=1%22+UNION+SELECT+NULL--&user=1&username=1 |


| **Confidence** | 75% |

**Description:**
Request took 4.6s (>4.5s) with payload: 1" UNION SELECT NULL--






**Remediation:**
Use parameterized queries; never concatenate user input into SQL.


---

### 2. Insecure Cookie: SessionID

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Category** | auth_bypass |
| **Agent** | fuzzer |


| **URL** | https://pentest-ground.com:81/ |


| **Confidence** | 75% |

**Description:**
Cookie 'SessionID' has: missing Secure flag, missing HttpOnly flag, missing SameSite attribute.






**Remediation:**
Set Secure, HttpOnly, and SameSite=Strict on all cookies.


---

### 3. Overly Permissive CORS Policy

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Category** | broken_access |
| **Agent** | fuzzer |


| **URL** | https://pentest-ground.com:81/ |


| **Confidence** | 75% |

**Description:**
Access-Control-Allow-Origin: * allows any origin to read responses.






**Remediation:**
Restrict CORS to specific trusted origins.


---

### 4. Stack Trace Disclosure

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Category** | sensitive_exposure |
| **Agent** | fuzzer |


| **URL** | https://pentest-ground.com:81/post/2?id=PHNlbGVjdCBhdXRvZm9jdXMgb25mb2N1cz1hbGVydCgxKT4%3D&user=1&username=1 |


| **Confidence** | 75% |

**Description:**
Error pattern detected in response body.
Param: id, Payload: PHNlbGVjdCBhdXRvZm9jdXMgb25mb2N1cz1hbGVydCgxKT4=






**Remediation:**
Suppress detailed error messages in production.


---

### 5. Missing HSTS header

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **Category** | misconfiguration |
| **Agent** | fuzzer |


| **URL** | https://pentest-ground.com:81/ |


| **Confidence** | 75% |

**Description:**
The response is missing the 'Strict-Transport-Security' security header.






**Remediation:**
Add the 'Strict-Transport-Security' HTTP response header.


---

### 6. Missing X-Content-Type-Options (MIME-sniffing)

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **Category** | misconfiguration |
| **Agent** | fuzzer |


| **URL** | https://pentest-ground.com:81/ |


| **Confidence** | 75% |

**Description:**
The response is missing the 'X-Content-Type-Options' security header.






**Remediation:**
Add the 'X-Content-Type-Options' HTTP response header.


---

### 7. Missing X-Frame-Options (clickjacking risk)

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **Category** | misconfiguration |
| **Agent** | fuzzer |


| **URL** | https://pentest-ground.com:81/ |


| **Confidence** | 75% |

**Description:**
The response is missing the 'X-Frame-Options' security header.






**Remediation:**
Add the 'X-Frame-Options' HTTP response header.


---

### 8. Missing Content-Security-Policy (XSS risk)

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **Category** | misconfiguration |
| **Agent** | fuzzer |


| **URL** | https://pentest-ground.com:81/ |


| **Confidence** | 75% |

**Description:**
The response is missing the 'Content-Security-Policy' security header.






**Remediation:**
Add the 'Content-Security-Policy' HTTP response header.


---

### 9. Missing X-XSS-Protection header

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **Category** | misconfiguration |
| **Agent** | fuzzer |


| **URL** | https://pentest-ground.com:81/ |


| **Confidence** | 75% |

**Description:**
The response is missing the 'X-XSS-Protection' security header.






**Remediation:**
Add the 'X-XSS-Protection' HTTP response header.


---

### 10. Missing Referrer-Policy header

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **Category** | misconfiguration |
| **Agent** | fuzzer |


| **URL** | https://pentest-ground.com:81/ |


| **Confidence** | 75% |

**Description:**
The response is missing the 'Referrer-Policy' security header.






**Remediation:**
Add the 'Referrer-Policy' HTTP response header.


---

### 11. Missing Permissions-Policy header

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **Category** | misconfiguration |
| **Agent** | fuzzer |


| **URL** | https://pentest-ground.com:81/ |


| **Confidence** | 75% |

**Description:**
The response is missing the 'Permissions-Policy' security header.






**Remediation:**
Add the 'Permissions-Policy' HTTP response header.


---

### 12. Server Information Disclosure via Server

| Field | Value |
|-------|-------|
| **Severity** | INFO |
| **Category** | sensitive_exposure |
| **Agent** | fuzzer |


| **URL** | https://pentest-ground.com:81/ |


| **Confidence** | 75% |

**Description:**
Header 'Server: nginx/1.29.8' reveals server technology.






**Remediation:**
Remove or obscure the 'Server' header.


---


*Generated by ZeroDay AI at 2026-04-11T08:37:24.895479*