
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from scapy.all import sniff

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from detector import detect_port_scans, detect_repeated_syn

LOGS = ROOT / "logs"
ALERTS = LOGS / "alerts.json"

# Change this to the correct Npcap interface for your computer.
INTERFACE = r"\Device\NPF_Loopback"

BATCH_SECONDS = 10


def main():
    LOGS.mkdir(exist_ok=True)
    print("=" * 45)
    print("       MINI NETWORK IDS - LIVE MONITOR")
    print("=" * 45)
    print(f"Interface: {INTERFACE}")
    print(f"Analysis interval: {BATCH_SECONDS} seconds")
    print("Monitoring authorized traffic. Press Ctrl+C to stop.")

    try:
        while True:
            packets = sniff(
                iface=INTERFACE,
                timeout=BATCH_SECONDS,
                store=True
            )

            if not packets:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] No packets captured.")
                continue

            alerts = (
                detect_port_scans(packets)
                + detect_repeated_syn(packets)
            )

            print(
                f"[{datetime.now().strftime('%H:%M:%S')}] "
                f"Analyzed {len(packets)} packets; "
                f"{len(alerts)} alert(s)."
            )

            if alerts:
                # Preserve alerts from previous batches.
                if ALERTS.exists():
                    try:
                        with ALERTS.open("r", encoding="utf-8") as file:
                            all_alerts = json.load(file)
                        if not isinstance(all_alerts, list):
                            all_alerts = []
                    except (json.JSONDecodeError, OSError):
                        all_alerts = []
                else:
                    all_alerts = []

                for alert in alerts:
                    alert["timestamp"] = datetime.now(
                        timezone.utc
                    ).isoformat()
                    all_alerts.append(alert)
                    print(f"  ALERT: {alert['alert_type']}")

                with ALERTS.open("w", encoding="utf-8") as file:
                    json.dump(all_alerts, file, indent=4)

                print(f"  Saved alerts to: {ALERTS}")

    except KeyboardInterrupt:
        print("\nLive monitoring stopped.")
    except PermissionError:
        print(
            "Permission denied. Close this terminal and reopen "
            "Command Prompt as Administrator."
        )
    except Exception as error:
        print(f"Monitoring error: {error}")
        print("Check the interface name and Npcap installation.")


if __name__ == "__main__":
    main()
