# Scanning
Scanning is also a type fo gathering informatiom but more aggressively with full port scans, service and version detection, OS fingerprinting, and NSE scripts to identify vulnerabilities and misconfigurations for exploitation.

There are various tools which are used for deep scanning it also has different type like:
- Network Scan
- Web App Scan

## Network Scan
Using tools like : `Nmap`
Example : nmap -sCV -p- -O 192.168.229.16 --open
>[!NOTE]
>The output will be provide a PNG

## Web App Scan
Using tools like : Nikto , Nuclei
Example :
 1. nikto -url http://192.168.229.16
 2. nuclei -u http://192.168.229.16
>[!NOTE]
>The output will be provide a PNG
