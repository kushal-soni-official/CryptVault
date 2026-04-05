from scapy.all import rdpcap
from scapy.layers.inet import TCP, UDP, IP
from collections import defaultdict
import warnings

# Suppress scapy warnings about missing integrations
warnings.filterwarnings("ignore", category=UserWarning, module="scapy")

def analyze_pcap(filepath: str) -> dict:
    """Analyze a PCAP file to find suspicious patterns like rapid port scanning or large payloads."""
    try:
        packets = rdpcap(filepath)
    except Exception as e:
        return {"error": f"Failed to read PCAP: {str(e)}"}
    
    syn_counts = defaultdict(int)
    large_transfers = []
    
    for pkt in packets:
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            
            # Detect SYN packets for port scanning
            if TCP in pkt:
                if pkt[TCP].flags == 'S': # SYN flag
                    syn_counts[src_ip] += 1
            
            # Detect unusually large single packets
            if len(pkt) > 1500:
                large_transfers.append({
                    'src': src_ip,
                    'dst': dst_ip,
                    'size': len(pkt)
                })
                
    # Threshold for "port scanning" heuristic: more than 50 SYN packets from a single IP
    suspicious_ips = {ip: count for ip, count in syn_counts.items() if count > 50}
    
    return {
        "total_packets": len(packets),
        "suspicious_scanners": suspicious_ips,
        "large_transfers": large_transfers[:10] # Top 10
    }
