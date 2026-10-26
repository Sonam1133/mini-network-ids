from pathlib import Path
from scapy.all import Ether, IP, TCP, wrpcap

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
DATA.mkdir(exist_ok=True)

packets = []

# Simulated SYN probes across multiple TCP ports.
# These packets are saved to a file, not transmitted.
for port in range(20, 36):
    packet = (
        Ether()
        / IP(src="192.168.1.50", dst="192.168.1.10")
        / TCP(sport=45000 + port, dport=port, flags="S")
    )
    packets.append(packet)

# One additional connection attempt for comparison.
packets.append(
    Ether()
    / IP(src="192.168.1.25", dst="192.168.1.10")
    / TCP(sport=51000, dport=443, flags="S")
)

output = DATA / "test_traffic.pcap"
wrpcap(str(output), packets)

print(f"Created: {output}")
print(f"Total packets: {len(packets)}")