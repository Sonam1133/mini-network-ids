from pathlib import Path
from datetime import datetime
from scapy.all import sniff, wrpcap, get_if_list, conf

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
DATA_DIR.mkdir(exist_ok=True)

# Use the active Wi-Fi adapter identified in your interface list.
INTERFACE = r"\Device\NPF_{D06140B0-FA35-47E6-BEE9-F85060F889F0}"

def main():
    available = get_if_list()

    if INTERFACE not in available:
        print("Selected interface was not found.")
        print("Available interfaces:")
        for interface in available:
            print(interface)
        return

    filename = (
        "live_capture_"
        + datetime.now().strftime("%Y%m%d_%H%M%S")
        + ".pcap"
    )
    output = DATA_DIR / filename

    print("Mini Network IDS - Live Capture")
    print(f"Interface: {INTERFACE}")
    print("Capturing for 30 seconds. Press Ctrl+C to stop early.")
    print("Only capture traffic you are authorized to inspect.")

    try:
        packets = sniff(
            iface=INTERFACE,
            timeout=30,
            store=True,
        )
    except PermissionError:
        print("Permission denied. Close this terminal and reopen CMD as Administrator.")
        return
    except Exception as error:
        print(f"Capture failed: {error}")
        return

    if packets:
        wrpcap(str(output), packets)
        print(f"Captured packets: {len(packets)}")
        print(f"Saved capture: {output}")
    else:
        print("No packets captured. Check the adapter and Npcap permissions.")

if __name__ == "__main__":
    main()