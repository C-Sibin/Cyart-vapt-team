# Introduction
VAPT is a said to be Vulnerability assessment and peneration testing.
The Vulenrability assessment is a type of automated scan using tools , and the penetration testing is way of testing the network or the website manually and finding the exploit,
moreover the Vulnerability assessement will only identify the securtity weaknesses and provide a compherensive report , they can only detect the known vulnerabilities and it will not exploit the findings,
On the other hand penetration testing is to find the weakness and exploit the founded vulnerability and provide the impact of that vulnerability
# Three scan types 
1. Network Scanning
2. Application Scanning
3. Authenticated vs Unauthenticated Scanning

## Network scanning
Network scanning is said to be scanning for live hosts, open ports, and running services/versions on a network.
This is classic recon / footprinting and maps directly to NIST SP 800‑115’s “network discovery” and “port and service identification” activities.
​
### Common modes:
 1. TCP connect scan (-sT)
    Completes the full TCP 3‑way handshake, Sends SYN packet if it recieve the SYN/ACK packet it sends ACK packet to complete the three way handshake.
    Example: `nmap -sT 192.168.1.100 -sT`
    
2. SYN (half‑open) scan (-sS)
    Sends SYN packet and once it received SYN/ACK packet it immediately sends RST without completeing the 3-way handshake
    Faster and stealthier than -sT
    Example: `sudo nmap -sS -sV 192.168.1.100`

3. Service & version detection (-sV)
   After finding open ports, Nmap sends probes to figure out service and version (e.g., Apache httpd 2.2.8, vsftpd 2.3.4).
   Example: `nmap -sV 192.168.1.100`

## Application Scanning
Application scanning is said to be testing a web server / web application for security misconfigurations, dangerous files, default content, outdated software, and some known vulnerabilities.
**Nikto** is a web server scanner, not a full web app fuzzer:
Looks for:
 - Outdated Apache/PHP/Tomcat versions.
 - Dangerous HTTP methods (PUT/DELETE/TRACE).
 - Default files (/phpinfo.php, /phpMyAdmin/, /manual/).
 - Directory listing (/icons/, /uploads/).
Example: `nikto -h http://192.168.1.100`
There are various other tools like Nikto which are Nuclei, OWASP Zap and more

## Authenticated vs Unauthenticated Scanning
### Authenticated Scan:
Scanner logs in with valid OS or app credentials (SSH, SMB, Windows domain account, web app login).it can able to check exact package versions via local checks and inspect configuration files and registry.
It provides more accurate and less false positives, but slower and needs credential management.

### Unauthenticaed Scan:
It is a type of scan which act like an extenal attacker with no credentials and other details about the network. It only check what is exposed over the network like (open ports, banners, public endpoints).
They are fast, but limited and can’t see internal config, patch levels behind login, or hidden admin panels.

# CVSS v4.0 scoring
CVSS is the measurement system used to determine the severity of a vulnerability. It translates technical details into a numerical score (0.0 to 10.0), making it easier for organizations to prioritize remediation.
It includes three Components:
 - **Base Score**:
    Intrinsic characteristics (attack vector, complexity, privileges required).
 - **Temporal Score**:
    Factors that change over time (availability of exploits, patches).
 - **Environmental Score**:
    How severe the vulnerability is in your specific environment.

## Sevirity Scoring:
 - 9.0–10.0 = Critical
 - 7.0–8.9 = High
 - 4.0–6.9 = Medium
 - 0.1–3.9 = Low

#  False positive validation techniques
False positive is said to be a security system which incorrectly identifies or block the legitimate service or updates thinking as a mailicous file or a threat 
For Example: Antivirus software might flag a safe software update as malware, or an IDS could block routine network traffic, mistaking it for an attack.
Need a manual verification to validate the flase positive

# OWASP WSTG
The OWASP Web Security Testing Guide (WSTG) is a big framework that defines how to systematically test web apps
It include several steps to complete starting from Information gathering to Validation and context
There the Steps to be Followed: 
(https://github.com/OWASP/wstg/tree/master/document/4-Web_Application_Security_Testing)
1.  Introduction and Objective
2.  Information Gathering
3.  Configuration and Deployment Management Testing
4.  Identity Management Testing
5.  Authentication Testing
6.  Authorization Testing
7.  Session Management Testing
8.  Input Validation Testing
9.  Testing for Error Handling
10. Testing for Weak Cryptography
11. Business Logic Testing
12. Client-side Testing
13. API Testing

# NIST SP 800‑115 methodology
NIST SP 800‑115 = “Technical Guide to Information Security Testing and Assessment”. It’s the classic standard for how to run security testing and vuln scanning.
Phased approach: 
Later interpretations of SP 800‑115 describe phases similar to `Planning & Preparation → Information Gathering → Vulnerability Analysis → Exploitation → Post‑Testing / Reporting`
