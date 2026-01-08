# Scanning
Scanning is also a type fo gathering informatiom but more aggressively with full port scans, service and version detection, OS fingerprinting, and NSE scripts to identify vulnerabilities and misconfigurations for exploitation.

There are various tools which are used for deep scanning it also has different type like:
- Network Scan
- Web App Scan

## Network Scan
Using tools like : `Nmap`
Example : nmap -sCV -p- -O 192.168.229.16 --open
Nmap Result:
<img width="840" height="693" alt="image" src="https://github.com/user-attachments/assets/992f889e-7b6f-4c8c-b943-366dba16f526" />

>[!NOTE]
>The output will be provide a PNG

## Web App Scan
Using tools like : Nikto , Nuclei
Example :
 1. nikto -url http://192.168.229.16
 2. nuclei -u http://192.168.229.16
>[!NOTE]
>The output will be provide a PNG
