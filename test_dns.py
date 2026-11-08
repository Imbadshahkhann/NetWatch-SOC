from scapy.all import IP, UDP, DNS, DNSQR
from dns_tunnel_detector import detect_dns

print("Testing DNS Tunnelling Detection...")

packet = (
    IP(src="192.0.2.10", dst="203.0.113.53")
    / UDP(dport=53)
    / DNS(rd=1, qd=DNSQR(qname="a8f92kd83j29x7q4m8v2n6b5c1d9e7f3.example.com"))
)

detect_dns(packet)

print("DNS Detection Test Completed.")
