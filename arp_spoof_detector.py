from scapy.all import ARP
from alert_manager import create_alert

arp_table = {}
alerted_changes = set()


def detect_arp(packet):

    if ARP not in packet:
        return

    ip = packet[ARP].psrc
    mac = packet[ARP].hwsrc.lower()

    if not ip or not mac:
        return

    if ip not in arp_table:
        arp_table[ip] = mac
        print(f"[ARP] Learned: {ip} -> {mac}")
        return

    old_mac = arp_table[ip]

    if old_mac != mac:

        change = (ip, old_mac, mac)

        if change in alerted_changes:
            return

        create_alert(
            alert_type="Possible ARP Spoofing",
            source_ip=ip,
            severity="HIGH",
            description=f"MAC changed from {old_mac} to {mac}",
            mitre_id="T1557.002",
        )

        alerted_changes.add(change)


print("NetWatch SOC - ARP Detection Loaded")
