# ZeroDay AI Security Report
**Scan ID:** 3ba877e7-db4f-4109-a3ea-287406bd45f1
**Target:** https://pentest-ground.com:5013
**Started:** 2026-04-21 18:44:52.485359
**Finished:** 2026-04-21 18:50:05.453656
**Total Findings:** 9

---

## Summary

| Severity | Count |
|----------|-------|
| Critical | 1 |
| High     | 0 |
| Medium   | 1 |
| Low      | 1 |
| Info     | 6 |

## Trust Profile

| Trust Tier | Count |
|------------|-------|
| Verified   | 0 |
| Strong     | 0 |
| Moderate   | 0 |
| Weak       | 9 |

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

### 2. Insecure Cookie: env

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

### 3. Missing HSTS header

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **Category** | misconfiguration |
| **Agent** | fuzzer |


| **URL** | https://pentest-ground.com:5013 |


| **Confidence** | 80% |
| **Trust** | WEAK (42/100) |

**Description:**
The response is missing the 'Strict-Transport-Security' security header.


**Evidence Signals:** moderate model confidence, proof-of-concept attached, request target captured, observed during runtime probing





**Proof of Concept:**
{
  "name": "Generation Failed",
  "endpoint": "https://pentest-ground.com:5013",
  "method": "GET",
  "payload": {},
  "success_indicator": "",
  "confidence": 0.0,
  "curl": "",
  "python_exploit": "",
  "retry_variants": []
}



**Remediation:**
Add the 'Strict-Transport-Security' HTTP response header.


---

### 4. Server Information Disclosure via Server

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

### 5. Open Port: 80/http

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
Date: Tue, 21 Apr 2026 18:48:55 GMT
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

### 6. Version Disclosure: nginx 1.29.8 on port 80

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

### 7. Open Port: 443/https

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
Date: Tue, 21 Apr 2026 18:48:55 GMT
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

### 8. Version Disclosure: nginx 1.29.8 on port 443

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

### 9. Open Port: 6379/redis

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


*Generated by ZeroDay AI at 2026-04-21T18:50:05.605066*