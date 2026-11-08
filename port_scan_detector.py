from scapy.all import IP, TCP
from alert_manager import create_alert
import time

ports_by_source = {}
alerted_sources = set()

PORT_THRESHOLD = 20
TIME_WINDOW = 10


def remember_port(packet):

    if IP not in packet or TCP not in packet:
        return

    flags = int(packet[TCP].flags)

    if not (flags & 0x02) or (flags & 0x10):
        return

    src = packet[IP].src
    dst = packet[IP].dst
    port = packet[TCP].dport
    now = time.time()

    key = (src, dst)

    if key not in ports_by_source:
        ports_by_source[key] = []

    ports_by_source[key].append((port, now))

    ports_by_source[key] = [
        (p, t) for p, t in ports_by_source[key] if now - t <= TIME_WINDOW
    ]

    recent_ports = {p for p, t in ports_by_source[key]}

    if len(recent_ports) >= PORT_THRESHOLD and key not in alerted_sources:

        create_alert(
            alert_type="Port Scan",
            source_ip=src,
            severity="HIGH",
            description=f"Scanned {len(recent_ports)} unique ports on {dst}",
            mitre_id="T1046",
        )

        alerted_sources.add(key)


print("NetWatch SOC - Port Scan Detection Loaded")
