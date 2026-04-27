# ZeroDay AI Security Report
**Scan ID:** f379a3ef-1b23-4da6-9ce7-55e47683dd15
**Target:** https://pentest-ground.com:4280/vulnerabilities/brute/
**Started:** 2026-04-10 16:55:23.776853
**Finished:** None
**Total Findings:** 26

---

## Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 1 |
| 🟠 High     | 5 |
| 🟡 Medium   | 6 |
| 🟢 Low      | 7 |
| 🔵 Info     | 7 |

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

### 2. Reflected XSS — param 'page'

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Category** | xss |
| **Agent** | fuzzer |


| **URL** | https://pentest-ground.com:4280/vulnerabilities/fi/?page=javascript%3Aalert%281%29 |


| **Confidence** | 75% |

**Description:**
Payload reflected unescaped in response: javascript:alert(1)




**Proof of Concept:**
Visit: https://pentest-ground.com:4280/vulnerabilities/fi/?page=javascript%3Aalert%281%29



**Remediation:**
HTML-encode all user-supplied output. Implement a strict CSP.


---

### 3. Reflected XSS — param 'id'

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Category** | xss |
| **Agent** | fuzzer |


| **URL** | https://pentest-ground.com:4280/phpinfo.php?id=javascript%3Aalert%281%29&user=1&username=1 |


| **Confidence** | 75% |

**Description:**
Payload reflected unescaped in response: javascript:alert(1)




**Proof of Concept:**
Visit: https://pentest-ground.com:4280/phpinfo.php?id=javascript%3Aalert%281%29&user=1&username=1



**Remediation:**
HTML-encode all user-supplied output. Implement a strict CSP.


---

### 4. Possible Time-Based Blind SQLi — param 'page'

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Category** | sql_injection |
| **Agent** | fuzzer |


| **URL** | https://pentest-ground.com:4280/vulnerabilities/fi/?page=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F |


| **Confidence** | 75% |

**Description:**
Request took 8.2s (>4.5s) with payload: http://169.254.169.254/latest/meta-data/






**Remediation:**
Use parameterized queries; never concatenate user input into SQL.


---

### 5. Possible Time-Based Blind SQLi — param 'id'

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Category** | sql_injection |
| **Agent** | fuzzer |


| **URL** | https://pentest-ground.com:4280/setup.php?id=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F&user=1&username=1 |


| **Confidence** | 75% |

**Description:**
Request took 8.2s (>4.5s) with payload: http://169.254.169.254/latest/meta-data/






**Remediation:**
Use parameterized queries; never concatenate user input into SQL.


---

### 6. Possible Time-Based Blind SQLi — param 'doc'

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Category** | sql_injection |
| **Agent** | fuzzer |


| **URL** | https://pentest-ground.com:4280/instructions.php?doc=http%3A%2F%2F017700000001%2F |


| **Confidence** | 75% |

**Description:**
Request took 8.2s (>4.5s) with payload: http://017700000001/






**Remediation:**
Use parameterized queries; never concatenate user input into SQL.


---

### 7. Insecure Cookie: security

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Category** | auth_bypass |
| **Agent** | fuzzer |


| **URL** | https://pentest-ground.com:4280/vulnerabilities/brute/ |


| **Confidence** | 75% |

**Description:**
Cookie 'security' has: missing Secure flag, missing HttpOnly flag, missing SameSite attribute.






**Remediation:**
Set Secure, HttpOnly, and SameSite=Strict on all cookies.


---

### 8. Insecure Cookie: PHPSESSID

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Category** | auth_bypass |
| **Agent** | fuzzer |


| **URL** | https://pentest-ground.com:4280/vulnerabilities/brute/ |


| **Confidence** | 75% |

**Description:**
Cookie 'PHPSESSID' has: missing Secure flag, missing HttpOnly flag, missing SameSite attribute.






**Remediation:**
Set Secure, HttpOnly, and SameSite=Strict on all cookies.


---

### 9. Server Path Disclosure

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Category** | path_traversal |
| **Agent** | fuzzer |


| **URL** | https://pentest-ground.com:4280/instructions.php?doc=%27+OR+%271%27%3D%271 |


| **Confidence** | 75% |

**Description:**
Error pattern detected in response body.
Param: doc, Payload: ' OR '1'='1






**Remediation:**
Suppress detailed error messages in production.


---

### 10. Server Path Disclosure

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Category** | path_traversal |
| **Agent** | fuzzer |


| **URL** | https://pentest-ground.com:4280/README.ar.md?id=%27+OR+%271%27%3D%271&user=1&username=1 |


| **Confidence** | 75% |

**Description:**
Error pattern detected in response body.
Param: id, Payload: ' OR '1'='1






**Remediation:**
Suppress detailed error messages in production.


---

### 11. Server Path Disclosure

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Category** | path_traversal |
| **Agent** | fuzzer |


| **URL** | https://pentest-ground.com:4280/vulnerabilities/fi/?page=%27+OR+%271%27%3D%271 |


| **Confidence** | 75% |

**Description:**
Error pattern detected in response body.
Param: page, Payload: ' OR '1'='1






**Remediation:**
Suppress detailed error messages in production.


---

### 12. Possible SSTI — Expression Evaluated (7*7=49)

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Category** | ssti |
| **Agent** | fuzzer |


| **URL** | https://pentest-ground.com:4280/phpinfo.php?id=%27+OR+%271%27%3D%271&user=1&username=1 |


| **Confidence** | 75% |

**Description:**
Error pattern detected in response body.
Param: id, Payload: ' OR '1'='1






**Remediation:**
Suppress detailed error messages in production.


---

### 13. Missing HSTS header

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **Category** | misconfiguration |
| **Agent** | fuzzer |


| **URL** | https://pentest-ground.com:4280/vulnerabilities/brute/ |


| **Confidence** | 75% |

**Description:**
The response is missing the 'Strict-Transport-Security' security header.






**Remediation:**
Add the 'Strict-Transport-Security' HTTP response header.


---

### 14. Missing X-Content-Type-Options (MIME-sniffing)

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **Category** | misconfiguration |
| **Agent** | fuzzer |


| **URL** | https://pentest-ground.com:4280/vulnerabilities/brute/ |


| **Confidence** | 75% |

**Description:**
The response is missing the 'X-Content-Type-Options' security header.






**Remediation:**
Add the 'X-Content-Type-Options' HTTP response header.


---

### 15. Missing X-Frame-Options (clickjacking risk)

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **Category** | misconfiguration |
| **Agent** | fuzzer |


| **URL** | https://pentest-ground.com:4280/vulnerabilities/brute/ |


| **Confidence** | 75% |

**Description:**
The response is missing the 'X-Frame-Options' security header.






**Remediation:**
Add the 'X-Frame-Options' HTTP response header.


---

### 16. Missing Content-Security-Policy (XSS risk)

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **Category** | misconfiguration |
| **Agent** | fuzzer |


| **URL** | https://pentest-ground.com:4280/vulnerabilities/brute/ |


| **Confidence** | 75% |

**Description:**
The response is missing the 'Content-Security-Policy' security header.






**Remediation:**
Add the 'Content-Security-Policy' HTTP response header.


---

### 17. Missing X-XSS-Protection header

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **Category** | misconfiguration |
| **Agent** | fuzzer |


| **URL** | https://pentest-ground.com:4280/vulnerabilities/brute/ |


| **Confidence** | 75% |

**Description:**
The response is missing the 'X-XSS-Protection' security header.






**Remediation:**
Add the 'X-XSS-Protection' HTTP response header.


---

### 18. Missing Referrer-Policy header

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **Category** | misconfiguration |
| **Agent** | fuzzer |


| **URL** | https://pentest-ground.com:4280/vulnerabilities/brute/ |


| **Confidence** | 75% |

**Description:**
The response is missing the 'Referrer-Policy' security header.






**Remediation:**
Add the 'Referrer-Policy' HTTP response header.


---

### 19. Missing Permissions-Policy header

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **Category** | misconfiguration |
| **Agent** | fuzzer |


| **URL** | https://pentest-ground.com:4280/vulnerabilities/brute/ |


| **Confidence** | 75% |

**Description:**
The response is missing the 'Permissions-Policy' security header.






**Remediation:**
Add the 'Permissions-Policy' HTTP response header.


---

### 20. Server Information Disclosure via Server

| Field | Value |
|-------|-------|
| **Severity** | INFO |
| **Category** | sensitive_exposure |
| **Agent** | fuzzer |


| **URL** | https://pentest-ground.com:4280/vulnerabilities/brute/ |


| **Confidence** | 75% |

**Description:**
Header 'Server: nginx/1.29.8' reveals server technology.






**Remediation:**
Remove or obscure the 'Server' header.


---

### 21. Server Information Disclosure via X-Powered-By

| Field | Value |
|-------|-------|
| **Severity** | INFO |
| **Category** | sensitive_exposure |
| **Agent** | fuzzer |


| **URL** | https://pentest-ground.com:4280/vulnerabilities/brute/ |


| **Confidence** | 75% |

**Description:**
Header 'X-Powered-By: PHP/8.5.5' reveals server technology.






**Remediation:**
Remove or obscure the 'X-Powered-By' header.


---

### 22. Open Port: 80/http

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
Date: Fri, 10 Apr 2026 17:01:57 GMT
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

### 23. Version Disclosure: nginx 1.29.8 on port 80

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

### 24. Open Port: 443/https

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
Date: Fri, 10 Apr 2026 17:01:58 GMT
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

### 25. Version Disclosure: nginx 1.29.8 on port 443

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

### 26. Open Port: 6379/redis

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


*Generated by ZeroDay AI at 2026-04-10T17:02:26.799369*