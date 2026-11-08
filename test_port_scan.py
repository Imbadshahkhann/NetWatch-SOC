from scapy.all import IP, TCP
from port_scan_detector import remember_port

print("Testing NetWatch Port Scan Detection...")

for port in range(1, 21):
    packet = IP(src="192.0.2.10", dst="198.51.100.10") / TCP(dport=port, flags="S")
    remember_port(packet)

print("Port Scan Detection Test Completed.")
