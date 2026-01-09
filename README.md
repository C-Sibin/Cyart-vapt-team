# PTES Report
## Overview
The objective is to evaluate how exposed the DVWA instance is to common web application vulnerabilities, particularly issues like SQL injection, cross‑site scripting (XSS), command injection, file inclusion, and related flaws
Scope : DVWA VM IP (192.168.74.16)
Out-of-Scope: Any other except vulnerable lab

## Methodology
The Penetration Testing Execution Standard (PTES) has seven phases:
1. Pre‑engagement interactions
2. Intelligence gathering
3. Threat modeling
4. Vulnerability analysis
5. Exploitation
6. Post‑exploitation
7. Reporting

>[!NOTE]
>The above mentioned steps are provide in the Week-2 folder


# Non-Technical Sumary

## EXECUTIVE SUMMARY: DVWA SECURITY ASSESSMENT
I conducted a comprehensive security assessment of our lab web application (DVWA) running on server 192.168.74.16 to evaluate vulnerability detection and remediation processes.

## Critical Risks Identified:
In testing we had confirmed that attackers could execute unauthorized database queries to steal user credentials and customer data (SQL injection). Additionally, attackers could inject malicious scripts to hijack user sessions and impersonate legitimate users (cross-site scripting). The server also runs outdated software versions containing known exploitable vulnerabilities.

## Recommended Actions:
- Developers must implement secure coding practices: use database prepared statements.
- Validate all user input, and encode output safely
- Immediately patch web server, database, and application components to current supported versions
- Deploy automated vulnerability scanning monthly and conduct penetration testing quarterly
- Establish secure code review process before deployment
