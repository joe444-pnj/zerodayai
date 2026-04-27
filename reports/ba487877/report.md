# ZeroDay AI Security Report
**Scan ID:** ba487877-b0ea-41dc-9d51-7989c995914e
**Target:** http://127.0.0.1:5000
**Started:** 2026-04-13 21:05:28.495212
**Finished:** 2026-04-13 21:14:36.951333
**Total Findings:** 20

---

## Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 6 |
| 🟠 High     | 4 |
| 🟡 Medium   | 1 |
| 🟢 Low      | 7 |
| 🔵 Info     | 2 |

---

## Findings


### 1. Exposed Debug Console

| Field | Value |
|-------|-------|
| **Severity** | CRITICAL |
| **Category** | other |
| **Agent** | fuzzer |


| **URL** | http://127.0.0.1:5000/console |


| **Confidence** | 100% |

**Description:**
Empirical Proof: Positive fingerprint detected for sqli in response body.







---

### 2. Exposed Debug Console

| Field | Value |
|-------|-------|
| **Severity** | CRITICAL |
| **Category** | xss |
| **Agent** | fuzzer |


| **URL** | http://127.0.0.1:5000/console |


| **Confidence** | 100% |

**Description:**
Empirical Proof: Positive fingerprint detected for xss in response body.







---

### 3. Exposed Debug Console

| Field | Value |
|-------|-------|
| **Severity** | CRITICAL |
| **Category** | ssrf |
| **Agent** | fuzzer |


| **URL** | http://127.0.0.1:5000/console |


| **Confidence** | 100% |

**Description:**
Empirical Proof: Positive fingerprint detected for ssrf in response body.







---

### 4. Exposed Debug Console

| Field | Value |
|-------|-------|
| **Severity** | CRITICAL |
| **Category** | ssti |
| **Agent** | fuzzer |


| **URL** | http://127.0.0.1:5000/console |


| **Confidence** | 100% |

**Description:**
Empirical Proof: Positive fingerprint detected for ssti in response body.







---

### 5. Exposed Debug Console

| Field | Value |
|-------|-------|
| **Severity** | CRITICAL |
| **Category** | other |
| **Agent** | fuzzer |


| **URL** | http://127.0.0.1:5000/console |


| **Confidence** | 100% |

**Description:**
Empirical Proof: Positive fingerprint detected for lfi in response body.







---

### 6. Exposed Debug Console

| Field | Value |
|-------|-------|
| **Severity** | CRITICAL |
| **Category** | other |
| **Agent** | fuzzer |


| **URL** | http://127.0.0.1:5000/console |


| **Confidence** | 100% |

**Description:**
Empirical Proof: Positive fingerprint detected for cmd_injection in response body.







---

### 7. Reflected XSS

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Category** | xss |
| **Agent** | fuzzer |


| **URL** | http://127.0.0.1:5000/ping?callback=test&url=test&next=test&password=test&ip=test&email=test&query=%3Cscript%3Ealert%281%29%3C%2Fscript%3E&admin=test&username=test&redirect=test&user=test&cmd=test&key=test&exec=test&id=test&file=test&pass=test&token=test&path=test |


| **Confidence** | 90% |

**Description:**
Empirical Proof: Payload reflected unescaped in response: <script>alert(1)</script>







---

### 8. Verified LFI success

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Category** | other |
| **Agent** | fuzzer |


| **URL** | http://127.0.0.1:5000/ping?callback=test&url=test&next=test&password=test&ip=test&email=test&query=C%3A%5CWindows%5CSystem32%5Cdrivers%5Cetc%5Chosts&admin=test&username=test&redirect=test&user=test&cmd=test&key=test&exec=test&id=test&file=test&pass=test&token=test&path=test |


| **Confidence** | 90% |

**Description:**
Empirical Proof: Positive fingerprint detected for lfi in response body.







---

### 9. Verified CMD_INJECTION success

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Category** | other |
| **Agent** | fuzzer |


| **URL** | http://127.0.0.1:5000/ping?callback=test&url=test&next=test&password=test&ip=test&email=test&query=%2Fusr%2Fbin%2Fid&admin=test&username=test&redirect=test&user=test&cmd=test&key=test&exec=test&id=test&file=test&pass=test&token=test&path=test |


| **Confidence** | 90% |

**Description:**
Empirical Proof: Positive fingerprint detected for cmd_injection in response body.







---

### 10. Dangerous Service Exposed: SMB on port 445

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Category** | exposed_service |
| **Agent** | network |


| **URL** | 127.0.0.1:445 |


| **Confidence** | 90% |

**Description:**
SMB exposed — check for EternalBlue and related CVEs.
Banner: 






**Remediation:**
Firewall port 445 or ensure smb requires authentication.


---

### 11. Server Path Disclosure

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Category** | path_traversal |
| **Agent** | fuzzer |


| **URL** | http://127.0.0.1:5000/ping?callback=test&url=test&next=test&password=test&ip=test&email=test&query=%27+INTO+OUTFILE+%27%2Fvar%2Fwww%2Fhtml%2Fshell.php%27--&admin=test&username=test&redirect=test&user=test&cmd=test&key=test&exec=test&id=test&file=test&pass=test&token=test&path=test |


| **Confidence** | 50% |

**Description:**
Heuristic Proof: Anomalous error pattern suggests sqli vulnerability.







---

### 12. Missing HSTS header

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **Category** | misconfiguration |
| **Agent** | fuzzer |


| **URL** | http://127.0.0.1:5000 |


| **Confidence** | 80% |

**Description:**
The response is missing the 'Strict-Transport-Security' security header.




**Proof of Concept:**
curl -X POST http://127.0.0.1:5000/login -d "username=admin&password=' OR 1=1--"



**Remediation:**
Add the 'Strict-Transport-Security' HTTP response header.


---

### 13. Missing X-Content-Type-Options (MIME-sniffing)

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **Category** | misconfiguration |
| **Agent** | fuzzer |


| **URL** | http://127.0.0.1:5000 |


| **Confidence** | 80% |

**Description:**
The response is missing the 'X-Content-Type-Options' security header.






**Remediation:**
Add the 'X-Content-Type-Options' HTTP response header.


---

### 14. Missing X-Frame-Options (clickjacking risk)

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **Category** | misconfiguration |
| **Agent** | fuzzer |


| **URL** | http://127.0.0.1:5000 |


| **Confidence** | 80% |

**Description:**
The response is missing the 'X-Frame-Options' security header.






**Remediation:**
Add the 'X-Frame-Options' HTTP response header.


---

### 15. Missing Content-Security-Policy (XSS risk)

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **Category** | misconfiguration |
| **Agent** | fuzzer |


| **URL** | http://127.0.0.1:5000 |


| **Confidence** | 80% |

**Description:**
The response is missing the 'Content-Security-Policy' security header.






**Remediation:**
Add the 'Content-Security-Policy' HTTP response header.


---

### 16. Missing X-XSS-Protection header

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **Category** | misconfiguration |
| **Agent** | fuzzer |


| **URL** | http://127.0.0.1:5000 |


| **Confidence** | 80% |

**Description:**
The response is missing the 'X-XSS-Protection' security header.






**Remediation:**
Add the 'X-XSS-Protection' HTTP response header.


---

### 17. Missing Referrer-Policy header

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **Category** | misconfiguration |
| **Agent** | fuzzer |


| **URL** | http://127.0.0.1:5000 |


| **Confidence** | 80% |

**Description:**
The response is missing the 'Referrer-Policy' security header.






**Remediation:**
Add the 'Referrer-Policy' HTTP response header.


---

### 18. Missing Permissions-Policy header

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **Category** | misconfiguration |
| **Agent** | fuzzer |


| **URL** | http://127.0.0.1:5000 |


| **Confidence** | 80% |

**Description:**
The response is missing the 'Permissions-Policy' security header.






**Remediation:**
Add the 'Permissions-Policy' HTTP response header.


---

### 19. Server Information Disclosure via Server

| Field | Value |
|-------|-------|
| **Severity** | INFO |
| **Category** | sensitive_exposure |
| **Agent** | fuzzer |


| **URL** | http://127.0.0.1:5000 |


| **Confidence** | 80% |

**Description:**
Header 'Server: Werkzeug/3.1.3 Python/3.13.3' reveals server technology.






**Remediation:**
Remove or obscure the 'Server' header.


---

### 20. Open Port: 445/smb

| Field | Value |
|-------|-------|
| **Severity** | INFO |
| **Category** | open_port |
| **Agent** | network |


| **URL** | 127.0.0.1:445 |


| **Confidence** | 99% |

**Description:**
Port 445 (smb) is open on 127.0.0.1.
Banner: 







---


*Generated by ZeroDay AI at 2026-04-13T21:14:37.053994*