import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from scapy.all import rdpcap

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from detector import detect_port_scans, detect_repeated_syn

DATA = ROOT / "data"
LOGS = ROOT / "logs"
ALERTS = LOGS / "test_alerts.json"


def main():
    # Use a supplied PCAP path, or default to synthetic test traffic.
    if len(sys.argv) > 1:
        pcap_file = Path(sys.argv[1])
        if not pcap_file.is_absolute():
            pcap_file = ROOT / pcap_file
    else:
        pcap_file = DATA / "test_traffic.pcap"

    if not pcap_file.exists():
        print(f"Capture file not found: {pcap_file}")
        print("Example: python src\\ids.py data\\test_traffic.pcap")
        return

    LOGS.mkdir(exist_ok=True)

    packets = rdpcap(str(pcap_file))
    alerts = (
        detect_port_scans(packets)
        + detect_repeated_syn(packets)
    )

    print("=" * 45)
    print("          MINI NETWORK IDS")
    print("=" * 45)
    print(f"Capture file: {pcap_file.name}")
    print(f"Packets analyzed: {len(packets)}")
    print(f"Alerts detected: {len(alerts)}")

    for alert in alerts:
        alert["timestamp"] = datetime.now(timezone.utc).isoformat()

        print("\n[!] SECURITY ALERT")
        for key, value in alert.items():
            print(f"{key}: {value}")

    with ALERTS.open("w", encoding="utf-8") as file:
        json.dump(alerts, file, indent=4)

    print(f"\nAlert report saved to: {ALERTS}")


if __name__ == "__main__":
    main()