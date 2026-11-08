from scapy.all import IP, TCP, ARP, UDP, DNS, DNSQR

from port_scan_detector import remember_port
from arp_spoof_detector import detect_arp
from dns_tunnel_detector import detect_dns

print("\nTesting all NetWatch detection modules...")

# Test 1: Port Scan
for port in range(1, 21):
    packet = IP(src="192.168.1.50", dst="192.168.1.100") / TCP(dport=port, flags="S")
    remember_port(packet)

# Test 2: ARP Spoofing
detect_arp(ARP(psrc="192.168.1.1", hwsrc="AA:AA:AA:AA:AA:AA"))

detect_arp(ARP(psrc="192.168.1.1", hwsrc="BB:BB:BB:BB:BB:BB"))

# Test 3: DNS Tunnelling
dns_packet = (
    IP(src="192.168.1.50", dst="8.8.8.8")
    / UDP(dport=53)
    / DNS(rd=1, qd=DNSQR(qname="a8f92kd83j29x7q4m8v2n6b5c1d9e7f3.example.com"))
)

detect_dns(dns_packet)

print("\nAll detector tests completed.")
