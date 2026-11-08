from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime

packet_count = 0


def analyze_packet(packet):
    global packet_count
    packet_count += 1

    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst

        protocol = "OTHER"
        sport = "-"
        dport = "-"

        if TCP in packet:
            protocol = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport

        elif UDP in packet:
            protocol = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport

        print("\n" + "=" * 45)
        print("NETWATCH SOC - PACKET DETAILS")
        print("=" * 45)
        print("Time       :", datetime.now())
        print("Packet ID  :", packet_count)
        print("Source IP  :", src)
        print("Dest IP    :", dst)
        print("Protocol   :", protocol)
        print("Source Port:", sport)
        print("Dest Port  :", dport)


print("NetWatch SOC Monitoring Started...")

iface = r"\Device\NPF_{EB749E75-A93A-41BD-862E-AA733BAD09AE}"

sniff(iface=iface, count=10, prn=analyze_packet, store=False)

print("\nTotal Packets Captured:", packet_count)
print("Monitoring Finished.")
