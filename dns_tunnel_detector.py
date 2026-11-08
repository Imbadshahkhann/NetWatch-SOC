from scapy.all import IP, DNS, DNSQR
from alert_manager import create_alert
import math


def calculate_entropy(text):
    if not text:
        return 0

    entropy = 0

    for char in set(text):
        probability = text.count(char) / len(text)
        entropy -= probability * math.log2(probability)

    return entropy


def detect_dns(packet):

    # Check required packet layers
    if IP not in packet or DNS not in packet or DNSQR not in packet:
        return

    # Process DNS queries only
    if packet[DNS].qr != 0:
        return

    domain = packet[DNS].qd.qname.decode("utf-8", errors="ignore").rstrip(".")

    if not domain:
        return

    # Find the longest subdomain label
    suspicious_label = max(domain.split("."), key=len)

    entropy = calculate_entropy(suspicious_label)

    # Detect unusually long, high-entropy labels
    if len(suspicious_label) >= 30 and entropy >= 3.5:

        create_alert(
            alert_type="Possible DNS Tunnelling",
            source_ip=packet[IP].src,
            severity="MEDIUM",
            description=(
                f"Suspicious DNS label: {domain} | "
                f"Length: {len(suspicious_label)} | "
                f"Entropy: {entropy:.2f}"
            ),
            mitre_id="T1071.004",
        )


print("NetWatch SOC - DNS Detection Loaded")
