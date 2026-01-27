#!/usr/bin/env python3
"""
HTTPS Traffic Analyzer: Parses PCAP for metadata analysis.
Captures packet sizes, inter-arrival times (IAT), IP packet counts.
Generates bar chart of packet size distribution (binned by 100 bytes).
Usage: python3 traffic_analyzer.py https_capture.pcap
"""

import pyshark
from collections import defaultdict, Counter
from typing import List, Dict
import matplotlib.pyplot as plt
import sys
import argparse

def analyze_https_traffic(pcap_file: str) -> None:
    """
    Main analysis function:
    - Filters HTTPS (tcp.port == 443)
    - Extracts: packet length, src/dst IP, timestamp
    - Computes: IAT, IP packet counts
    - Prints metadata table
    - Saves bar chart as 'packet_size_dist.png'
    """
    # Load PCAP with HTTPS filter for efficiency
    cap = pyshark.FileCapture(pcap_file, display_filter='tcp.port == 443')
    
    packet_sizes: List[int] = []
    ip_counts: Dict[str, int] = defaultdict(int)
    inter_arrival_times: List[float] = []
    timestamps: List[float] = []
    prev_time: float = None
    
    print("Parsing HTTPS packets...")
    for pkt in cap:
        if hasattr(pkt, 'ip') and hasattr(pkt, 'tcp'):
            # Packet metadata extraction
            src_ip = pkt.ip.src
            dst_ip = pkt.ip.dst
            size = int(pkt.length)  # Total packet length (frame.len)
            packet_sizes.append(size)
            ip_counts[src_ip] += 1
            ip_counts[dst_ip] += 1
            
            # Inter-arrival time calculation
            ts = float(pkt.sniff_time.timestamp())
            timestamps.append(ts)
            if prev_time is not None:
                iat = ts - prev_time
                inter_arrival_times.append(iat)
            prev_time = ts
    
    cap.close()
    
    # Print summary table (top 5 IPs)
    print("\n=== PACKET METADATA TABLE ===")
    print("IP Address\t|\tPacket Count\t|\tAvg Size (bytes)")
    print("-" * 50)
    total_packets = len(packet_sizes)
    avg_size = sum(packet_sizes) / total_packets if packet_sizes else 0
    avg_iat = sum(inter_arrival_times) / len(inter_arrival_times) if inter_arrival_times else 0
    
    for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"{ip}\t|\t{count}\t|\t{avg_size:.0f}")
    
    print(f"\nTotal HTTPS packets: {total_packets}")
    print(f"Avg packet size: {avg_size:.0f} bytes")
    print(f"Avg inter-arrival time: {avg_iat*1000:.2f} ms")  # Convert to ms
    
    # Bar chart: Packet size distribution (bin by 100 bytes for visibility)
    if packet_sizes:
        binned_sizes = Counter([s // 100 * 100 for s in packet_sizes])  # Bin: 0,100,200,...
        sizes = list(binned_sizes.keys())
        frequencies = list(binned_sizes.values())
        
        plt.figure(figsize=(12, 6))
        plt.bar(sizes, frequencies, width=90, color='skyblue', edgecolor='navy')
        plt.xlabel('Packet Size (bytes, binned)')
        plt.ylabel('Packet Frequency')
        plt.title('HTTPS Traffic: Packet Size Distribution')
        plt.grid(axis='y', alpha=0.3)
        plt.xticks(sizes[::max(1, len(sizes)//10)], rotation=45)  # Limit x-ticks
        plt.tight_layout()
        plt.savefig('packet_size_dist.png', dpi=300, bbox_inches='tight')
        plt.show()
        print("\nBar chart saved as 'packet_size_dist.png'")
    else:
        print("No HTTPS packets found in PCAP.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze HTTPS traffic metadata")
    parser.add_argument("pcap_file", help="Path to Wireshark PCAP file")
    args = parser.parse_args()
    
    if not args.pcap_file.endswith('.pcap'):
        print("Error: Input must be a .pcap file")
        sys.exit(1)
    
    analyze_https_traffic(args.pcap_file)
