#!/usr/bin/env python3
"""
nmap_automation.py
Automates an Nmap SYN scan and writes results to scan_report.txt
"""

import nmap          # python-nmap library wrapper around Nmap
import datetime      # for timestamps


def run_syn_scan(target):
    """
    Run an Nmap SYN (-sS) scan against the given target.
    Returns a PortScanner object containing the scan results.
    """
    nm = nmap.PortScanner()
    # -sS = SYN scan, -Pn = skip host discovery (assume host is up), -T4 = faster timing
    nm.scan(target, arguments='-sS -Pn -T4')
    return nm


def generate_report(target, nm, filename="scan_report.txt"):
    """
    Generate a text report from an Nmap PortScanner result.
    The report includes timestamp, target IP, and a table of open ports/services.
    """
    with open(filename, "w") as f:
        # Header information
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write("==== Nmap Automated Scan Report ====\n")
        f.write(f"Scan timestamp : {timestamp}\n")
        f.write(f"Target         : {target}\n\n")

        # Iterate over all discovered hosts
        for host in nm.all_hosts():
            f.write(f"Host IP        : {host}\n")
            f.write(f"Host state     : {nm[host].state()}\n\n")

            # Table header
            f.write("Open Ports and Services:\n")
            f.write("{:<8} {:<8} {:<20} {:<30}\n".format(
                "Port", "Proto", "Service", "Version"))
            f.write("-" * 70 + "\n")

            # For each protocol (usually 'tcp' and/or 'udp')
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in sorted(ports):
                    port_data = nm[host][proto][port]
                    if port_data.get("state") == "open":
                        # Extract service name and version info if present
                        name = port_data.get("name", "")
                        product = port_data.get("product", "")
                        version = port_data.get("version", "")
                        extrainfo = port_data.get("extrainfo", "")

                        # Build a version string if we have any details
                        version_str = " ".join(
                            x for x in [product, version, extrainfo] if x
                        )

                        f.write("{:<8} {:<8} {:<20} {:<30}\n".format(
                            port, proto, name, version_str))

            f.write("\n")

        # Completion note
        f.write("Scan completed successfully.\n")
        f.write("====================================\n")


def main():
    """
    Main function:
    - Ask user for target
    - Run SYN scan
    - Generate scan_report.txt
    """
    target = input("Enter target IP or hostname: ").strip()
    if not target:
        print("No target provided. Exiting.")
        return

    print(f"[+] Running SYN scan on {target} ...")
    nm = run_syn_scan(target)
    print("[+] Scan finished, generating report ...")
    generate_report(target, nm)
    print("[+] Report saved to scan_report.txt")


if __name__ == "__main__":
    main()
