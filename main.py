from scapy.all import sniff, IP, TCP, UDP, ARP
from port_scan_detector import remember_port
from arp_spoof_detector import detect_arp
from dns_tunnel_detector import detect_dns

import json
import os
import time

INTERFACE = r"\Device\NPF_{EB749E75-A93A-41BD-862E-AA733BAD09AE}"

STATS_FILE = "traffic_stats.json"
TEMP_FILE = f"traffic_stats_{os.getpid()}.tmp"

stats = {
    "total_packets": 0,
    "tcp_packets": 0,
    "udp_packets": 0,
    "arp_packets": 0,
    "other_packets": 0,
}

last_saved = 0


def save_stats():
    with open(TEMP_FILE, "w", encoding="utf-8") as file:
        json.dump(stats, file, indent=4)

    # Retry if Windows temporarily locks the destination file
    for attempt in range(5):
        try:
            os.replace(TEMP_FILE, STATS_FILE)
            return
        except PermissionError:
            time.sleep(0.2)

    raise PermissionError("Could not update traffic statistics file")


def process_packet(packet):
    global last_saved

    stats["total_packets"] += 1

    if ARP in packet:
        stats["arp_packets"] += 1
        detect_arp(packet)

    elif IP in packet:

        if TCP in packet:
            stats["tcp_packets"] += 1

        elif UDP in packet:
            stats["udp_packets"] += 1

        else:
            stats["other_packets"] += 1

        print(f"\n[TRAFFIC] {packet[IP].src} -> {packet[IP].dst}")

        if TCP in packet:
            print(f"[TCP] {packet[TCP].sport} -> " f"{packet[TCP].dport}")

        if UDP in packet and packet[UDP].dport == 53:
            print("[DNS] DNS query detected")

        remember_port(packet)
        detect_dns(packet)

    else:
        stats["other_packets"] += 1

    # Save statistics approximately once per second
    if time.time() - last_saved >= 1:
        try:
            save_stats()
        except OSError as error:
            print(f"[WARNING] Statistics save failed: {error}")

        last_saved = time.time()


if __name__ == "__main__":

    print("===================================")
    print("       NETWATCH SOC STARTED")
    print("===================================")
    print("Live packet monitoring active...")
    print("Press CTRL+C to stop.\n")

    try:
        sniff(iface=INTERFACE, prn=process_packet, store=False)

    except KeyboardInterrupt:
        print("\nMonitoring stopped.")

    finally:
        try:
            save_stats()
            print("Final packet statistics saved.")
        except OSError as error:
            print(f"[WARNING] Final statistics save failed: {error}")
