#!/usr/bin/env python3
from scapy.all import IP, TCP, send


def main():
    target_ip = input("Enter target IP (Snort-monitored host): ").strip()
    if not target_ip:
        print("[-] No target IP provided, exiting.")
        return

 
    ports = [22, 80, 443, 8080, 4444]


    src_ip = "127.0.0.1"
    src_port = 44444

    print("[+] Starting SYN packet generation ...")
    for dport in ports:
        ip_layer = IP(src=src_ip, dst=target_ip)
        tcp_layer = TCP(sport=src_port, dport=dport, flags="S", seq=100)
        packet = ip_layer / tcp_layer
        print(f"[+] Sending SYN from {src_ip}:{src_port} to {target_ip}:{dport}")
        send(packet, verbose=0)
    print("[+] Finished sending test packets.")


if __name__ == "__main__":
    main()
