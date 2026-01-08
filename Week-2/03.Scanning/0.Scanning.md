# Scanning
Scanning is also a type fo gathering informatiom but more aggressively with full port scans, service and version detection, OS fingerprinting, and NSE scripts to identify vulnerabilities and misconfigurations for exploitation.

There are various tools which are used for deep scanning it also has different type like:
- Network Scan
- Web App Scan

## Network Scan
Using tools like : `Nmap`
Example : nmap -sCV -p- -O 192.168.229.16 --open
### Nmap Result:
<img width="913" height="830" alt="image" src="https://github.com/user-attachments/assets/0f06c2a7-801f-4c49-b3db-2de4cc46c41a" />


>[!NOTE]
>The output will be provide a PNG

## Web App Scan
Using tools like : Nikto , Nuclei
Example :
 1. nikto -url http://192.168.229.16
    ### Nikto Result:
    <img width="840" height="693" alt="image" src="https://github.com/user-attachments/assets/992f889e-7b6f-4c8c-b943-366dba16f526" />
 3. nuclei -u http://192.168.229.16
    ### Nuclei Result:
    <img width="1563" height="813" alt="image" src="https://github.com/user-attachments/assets/e9ec9841-55b7-49c4-a90c-ee2858617c5b" />

>[!NOTE]
>The output will be provide a PNG


# Findings:
Identified critical misconfigurations including anonymous FTP access, outdated vsftpd with known backdoor, exposed Telnet service, vulnerable Apache and OpenSSH versions, insecure PHP configuration allowing remote code execution (CVE-2012-1823), exposed phpMyAdmin panel, directory listing, and HTTP TRACE method enabled, leading to high risk of remote compromise.
