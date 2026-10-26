
# Mini Network Intrusion Detection System (IDS)

## Overview
A beginner-friendly Network Intrusion Detection System built with Python and Scapy. It analyzes packet captures and monitors network traffic for suspicious TCP SYN activity.

## Features
- Detects possible TCP SYN port scans.
- Detects repeated TCP SYN attempts to the same destination port.
- Analyzes saved PCAP files.
- Monitors live traffic using Scapy and Npcap.
- Stores live alerts in JSON format.
- Displays live alerts through a Streamlit dashboard.
- Includes automated unit tests.

## Technologies Used
- Python
- Scapy
- Streamlit
- Npcap
- JSON
- Wireshark-compatible PCAP files
- unittest

## Detection Rules
1. **Possible TCP SYN Port Scan:** Flags traffic when a source sends SYN probes to at least 10 unique destination ports on the same destination within 10 seconds.
2. **Repeated TCP SYN Attempts:** Flags repeated SYN attempts to the same destination port within a 10-second window.

These thresholds are configurable in the detector code.

## Project Structure
```text
mini-network-ids/
├── src/
│   ├── detector.py
│   ├── ids.py
│   ├── make_test_traffic.py
│   ├── capture_live.py
│   ├── live_monitor.py
│   ├── dashboard.py
│   └── send_local_test.py
├── tests/
│   └── test_detector.py
├── data/
│   └── test_traffic.pcap
├── logs/
│   ├── test_alerts.json
│   └── alerts.json
└── README.md
```

## Setup
Requires Python and Npcap for live packet capture on Windows.

```cmd
python -m venv .venv
.venv\Scripts\activate
pip install scapy streamlit
```

Install Npcap separately if it is not already installed. Live capture may require running CMD as Administrator.

## Run Unit Tests
```cmd
python -m unittest discover -s tests -v
```

## Analyze the Sample PCAP
```cmd
python src\make_test_traffic.py
python src\ids.py data\test_traffic.pcap
```

Test alerts are written to `logs/test_alerts.json`.

## Start Live Monitoring
Open an Administrator CMD window:

```cmd
cd C:\Users\sonam\mini-network-ids
.venv\Scripts\activate
python src\live_monitor.py
```

## Start the Dashboard
Open a second CMD window:

```cmd
cd C:\Users\sonam\mini-network-ids
.venv\Scripts\activate
streamlit run src\dashboard.py
```

Open `http://localhost:8501` in your browser.

## Run the Local Test
With the live monitor running, open a third CMD window:

```cmd
cd C:\Users\sonam\mini-network-ids
.venv\Scripts\activate
python src\send_local_test.py
```

This sends test SYN packets to localhost for controlled validation.

## Limitations
- This is an educational prototype, not a production-grade IDS.
- Detection relies on simple threshold-based rules and may produce false positives or miss sophisticated attacks.
- The localhost test validates controlled local traffic; it does not prove detection of attacks from external machines.
- Only the traffic visible to the selected capture interface can be analyzed.
- Run tests only on systems and networks you own or are authorized to monitor.

## Future Improvements
- Add more detection rules.
- Add configurable thresholds and whitelisting.
- Improve alert severity and investigation details.
- Add PCAP replay and additional test cases.
- Integrate threat intelligence and automated response.
