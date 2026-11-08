from scapy.all import IP, TCP
from port_scan_detector import remember_port

print("Testing NetWatch Port Scan Detection...")

for port in range(1, 21):
    packet = IP(src="192.168.1.50", dst="192.168.1.100") / TCP(dport=port, flags="S")

    remember_port(packet)

print("Detection test completed.")
