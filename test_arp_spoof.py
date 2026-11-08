from scapy.all import ARP
from arp_spoof_detector import detect_arp

print("Testing ARP Spoofing Detection...")

# Original router mapping
packet1 = ARP(psrc="192.168.1.1", hwsrc="AA:AA:AA:AA:AA:AA")

# Suspicious changed mapping
packet2 = ARP(psrc="192.168.1.1", hwsrc="BB:BB:BB:BB:BB:BB")

detect_arp(packet1)
detect_arp(packet2)

print("\nARP Detection Test Finished")
