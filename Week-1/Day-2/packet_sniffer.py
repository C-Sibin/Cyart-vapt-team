#!/usr/bin/env python3
import matplotlib.pyplot as plt
from scapy.all import sniff
from collections import Counter
import matplotlib.pyplot as pltfrom
from scapy.all import show_interfaces
show_interfaces()


# Dictionary to hold protocol counts
proto_counts = Counter()

def process_packet(pkt):
    """Callback for each captured packet: detect protocol and update counter."""
    if pkt.haslayer("TCP"):
        proto_counts["TCP"] += 1
    elif pkt.haslayer("UDP"):
        proto_counts["UDP"] += 1
    elif pkt.haslayer("ICMP"):
        proto_counts["ICMP"] += 1
    else:
        proto_counts["Other"] += 1

def main():
    iface = input("Enter interface to sniff on (e.g., eth0, wlan0, lo): ").strip()
    print(f"[+] Sniffing 100 packets on {iface} ...")
    sniff(iface=iface, count=100, prn=process_packet)
    print("[+] Capture complete.")
    print("Protocol counts:", proto_counts)

    # Bar chart of protocol distribution
    labels = list(proto_counts.keys())
    values = [proto_counts[k] for k in labels]

    plt.bar(labels, values)
    plt.title("Captured Protocol Distribution")
    plt.xlabel("Protocol")
    plt.ylabel("Packet Count")
    plt.savefig("protocol_distribution.png")
    plt.close()
    print("[+] Saved chart to protocol_distribution.png")


if __name__ == "__main__":
    main()
