# ZeroDay AI Security Report
**Scan ID:** 52282b5a-5145-4ad0-87ca-3f56bbfbc9d6
**Target:** https://pentest-ground.com:81/
**Started:** 2026-04-11 19:45:15.714198
**Finished:** 2026-04-11 20:01:13.353690
**Total Findings:** 17

---

## Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 1 |
| 🟠 High     | 1 |
| 🟡 Medium   | 2 |
| 🟢 Low      | 7 |
| 🔵 Info     | 6 |

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

**Description:**
Redis exposed — often unauthenticated.
Banner: +PONG






**Remediation:**
Firewall port 6379 or ensure redis requires authentication.


---

### 2. Possible Time-Based Blind SQLi — param 'id'

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Category** | sql_injection |
| **Agent** | fuzzer |


| **URL** | https://pentest-ground.com:81/?id=%27+AND+%28SELECT+1+FROM%28SELECT+COUNT%28%2A%29%2CCONCAT%28version%28%29%2C0x3a%2CFLOOR%28RAND%280%29%2A2%29%29x+FROM+information_schema.tables+GROUP+BY+x%29a%29--%00&user=1&username=1 |


| **Confidence** | 75% |

**Description:**
Request took 4.5s (>4.5s) with payload: ' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),0x3a,FLOOR(RAND(0)*2))x FROM information_schem






**Remediation:**
Use parameterized queries; never concatenate user input into SQL.


---

### 3. Insecure Cookie: SessionID

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

### 4. Overly Permissive CORS Policy

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

### 13. Open Port: 80/http

| Field | Value |
|-------|-------|
| **Severity** | INFO |
| **Category** | open_port |
| **Agent** | network |


| **URL** | pentest-ground.com:80 |


| **Confidence** | 99% |

**Description:**
Port 80 (http) is open on pentest-ground.com.
Banner: HTTP/1.1 301 Moved Permanently
Server: nginx/1.29.8
Date: Sat, 11 Apr 2026 19:59:50 GMT
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







---

### 14. Version Disclosure: nginx 1.29.8 on port 80

| Field | Value |
|-------|-------|
| **Severity** | INFO |
| **Category** | sensitive_exposure |
| **Agent** | network |


| **URL** | pentest-ground.com:80 |


| **Confidence** | 95% |

**Description:**
nginx version 1.29.8 identified from banner.
Check CVE databases for known vulnerabilities in this version.







---

### 15. Open Port: 443/https

| Field | Value |
|-------|-------|
| **Severity** | INFO |
| **Category** | open_port |
| **Agent** | network |


| **URL** | pentest-ground.com:443 |


| **Confidence** | 99% |

**Description:**
Port 443 (https) is open on pentest-ground.com.
Banner: HTTP/1.1 400 Bad Request
Server: nginx/1.29.8
Date: Sat, 11 Apr 2026 19:59:51 GMT
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







---

### 16. Version Disclosure: nginx 1.29.8 on port 443

| Field | Value |
|-------|-------|
| **Severity** | INFO |
| **Category** | sensitive_exposure |
| **Agent** | network |


| **URL** | pentest-ground.com:443 |


| **Confidence** | 95% |

**Description:**
nginx version 1.29.8 identified from banner.
Check CVE databases for known vulnerabilities in this version.







---

### 17. Open Port: 6379/redis

| Field | Value |
|-------|-------|
| **Severity** | INFO |
| **Category** | open_port |
| **Agent** | network |


| **URL** | pentest-ground.com:6379 |


| **Confidence** | 99% |

**Description:**
Port 6379 (redis) is open on pentest-ground.com.
Banner: +PONG







---


*Generated by ZeroDay AI at 2026-04-11T20:01:13.462633*