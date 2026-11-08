from scapy.all import ARP
from arp_spoof_detector import detect_arp

print("Testing ARP Spoofing Detection...")

# Original IP-to-MAC mapping
packet1 = ARP(psrc="192.0.2.1", hwsrc="AA:AA:AA:AA:AA:AA")

# Changed MAC address
packet2 = ARP(psrc="192.0.2.1", hwsrc="BB:BB:BB:BB:BB:BB")

detect_arp(packet1)
detect_arp(packet2)

print("ARP Spoofing Test Completed.")
