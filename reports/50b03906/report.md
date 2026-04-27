# ZeroDay AI Security Report
**Scan ID:** 50b03906-5abf-464e-a0d3-278ce9a102cf
**Target:** https://pentest-ground.com:5013
**Started:** 2026-04-21 19:01:23.665203
**Finished:** 2026-04-21 19:04:41.206813
**Total Findings:** 10

---

## Summary

| Severity | Count |
|----------|-------|
| Critical | 1 |
| High     | 1 |
| Medium   | 1 |
| Low      | 1 |
| Info     | 6 |

## Trust Profile

| Trust Tier | Count |
|------------|-------|
| Verified   | 0 |
| Strong     | 0 |
| Moderate   | 0 |
| Weak       | 10 |

---

## Findings


### 1. Dangerous Service Exposed: REDIS on port 6379

| Field | Value |
|-------|-------|
| **Severity** | CRITICAL |
| **Category** | exposed_service |
| **Agent** | network |


| **URL** | pentest-ground.com:6379 |


| **Confidence** | 90% |
| **Trust** | WEAK (30/100) |

**Description:**
Redis exposed — often unauthenticated.
Banner: +PONG


**Evidence Signals:** high model confidence, request target captured, observed during runtime probing







**Remediation:**
Firewall port 6379 or ensure redis requires authentication.


---

### 2. Attack Chain: Redis Configuration Disclosure and Exploitation

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Category** | other |
| **Agent** | llm |



| **CVSS** | 0.8500000000000001 |

| **Confidence** | 90% |
| **Trust** | WEAK (14/100) |

**Description:**
Impact: Full compromise of server configuration and potentially sensitive data

Steps:
  1: Discover open Redis port (6379) via Open Port finding
  2: Exploit insecure cookie 'env' to access sensitive information about the server
  3: Use disclosed Redis configuration details to perform unauthorized data retrieval or modification


**Evidence Signals:** high model confidence








---

### 3. Insecure Cookie: env

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Category** | auth_bypass |
| **Agent** | fuzzer |


| **URL** | https://pentest-ground.com:5013 |


| **Confidence** | 80% |
| **Trust** | WEAK (26/100) |

**Description:**
Cookie 'env' has: missing Secure flag, missing HttpOnly flag, missing SameSite attribute.


**Evidence Signals:** moderate model confidence, request target captured, observed during runtime probing







**Remediation:**
Set Secure, HttpOnly, and SameSite=Strict on all cookies.


---

### 4. Missing HSTS header

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **Category** | misconfiguration |
| **Agent** | fuzzer |


| **URL** | https://pentest-ground.com:5013 |


| **Confidence** | 80% |
| **Trust** | WEAK (26/100) |

**Description:**
The response is missing the 'Strict-Transport-Security' security header.


**Evidence Signals:** moderate model confidence, request target captured, observed during runtime probing







**Remediation:**
Add the 'Strict-Transport-Security' HTTP response header.


---

### 5. Server Information Disclosure via Server

| Field | Value |
|-------|-------|
| **Severity** | INFO |
| **Category** | sensitive_exposure |
| **Agent** | fuzzer |


| **URL** | https://pentest-ground.com:5013 |


| **Confidence** | 80% |
| **Trust** | WEAK (26/100) |

**Description:**
Header 'Server: nginx/1.29.8' reveals server technology.


**Evidence Signals:** moderate model confidence, request target captured, observed during runtime probing







**Remediation:**
Remove or obscure the 'Server' header.


---

### 6. Open Port: 80/http

| Field | Value |
|-------|-------|
| **Severity** | INFO |
| **Category** | open_port |
| **Agent** | network |


| **URL** | pentest-ground.com:80 |


| **Confidence** | 99% |
| **Trust** | WEAK (34/100) |

**Description:**
Port 80 (http) is open on pentest-ground.com.
Banner: HTTP/1.1 301 Moved Permanently
Server: nginx/1.29.8
Date: Tue, 21 Apr 2026 19:02:37 GMT
Content-Type: text/html
Content-Length: 169
Connection: close
Location: https://pentest-ground.com

<html>
<head><title>301 Moved Permanently</title></head>
<body>
<center><h1>301 Moved Permanently</h1></center>
<hr><center>nginx/1.29.8</center>
</body>
</html>


**Evidence Signals:** very high model confidence, request target captured, observed during runtime probing








---

### 7. Version Disclosure: nginx 1.29.8 on port 80

| Field | Value |
|-------|-------|
| **Severity** | INFO |
| **Category** | sensitive_exposure |
| **Agent** | network |


| **URL** | pentest-ground.com:80 |


| **Confidence** | 95% |
| **Trust** | WEAK (34/100) |

**Description:**
nginx version 1.29.8 identified from banner.
Check CVE databases for known vulnerabilities in this version.


**Evidence Signals:** very high model confidence, request target captured, observed during runtime probing








---

### 8. Open Port: 443/https

| Field | Value |
|-------|-------|
| **Severity** | INFO |
| **Category** | open_port |
| **Agent** | network |


| **URL** | pentest-ground.com:443 |


| **Confidence** | 99% |
| **Trust** | WEAK (34/100) |

**Description:**
Port 443 (https) is open on pentest-ground.com.
Banner: HTTP/1.1 400 Bad Request
Server: nginx/1.29.8
Date: Tue, 21 Apr 2026 19:02:37 GMT
Content-Type: text/html
Content-Length: 255
Connection: close

<html>
<head><title>400 The plain HTTP request was sent to HTTPS port</title></head>
<body>
<center><h1>400 Bad Request</h1></center>
<center>The plain HTTP request was sent to HTTPS port</center>
<hr><center>nginx/1.29.8</center>
</body>
</html>


**Evidence Signals:** very high model confidence, request target captured, observed during runtime probing








---

### 9. Version Disclosure: nginx 1.29.8 on port 443

| Field | Value |
|-------|-------|
| **Severity** | INFO |
| **Category** | sensitive_exposure |
| **Agent** | network |


| **URL** | pentest-ground.com:443 |


| **Confidence** | 95% |
| **Trust** | WEAK (34/100) |

**Description:**
nginx version 1.29.8 identified from banner.
Check CVE databases for known vulnerabilities in this version.


**Evidence Signals:** very high model confidence, request target captured, observed during runtime probing








---

### 10. Open Port: 6379/redis

| Field | Value |
|-------|-------|
| **Severity** | INFO |
| **Category** | open_port |
| **Agent** | network |


| **URL** | pentest-ground.com:6379 |


| **Confidence** | 99% |
| **Trust** | WEAK (34/100) |

**Description:**
Port 6379 (redis) is open on pentest-ground.com.
Banner: +PONG


**Evidence Signals:** very high model confidence, request target captured, observed during runtime probing








---


*Generated by ZeroDay AI at 2026-04-21T19:04:41.340712*