
import time
from scapy.all import IP, TCP, send

TARGET = "127.0.0.1"

print("Sending controlled TCP SYN test packets to localhost.")
print("Target:", TARGET)

try:
    for port in range(45000, 45012):
        packet = (
            IP(dst=TARGET)
            / TCP(sport=40000 + port, dport=port, flags="S")
        )
        send(packet, verbose=False)
        print(f"Sent local test packet to port {port}")
        time.sleep(0.05)

    print("Local test traffic complete.")

except PermissionError:
    print("Permission denied. Reopen CMD as Administrator and retry.")
