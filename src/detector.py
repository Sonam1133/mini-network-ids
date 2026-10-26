from collections import Counter, defaultdict, deque


def collect_syn_events(packets):
    """Collect initial TCP SYN events from IP packets."""
    traffic = defaultdict(list)

    for packet in packets:
        if not packet.haslayer("IP") or not packet.haslayer("TCP"):
            continue

        ip = packet["IP"]
        tcp = packet["TCP"]
        flags = int(tcp.flags)

        # SYN set, ACK unset: initial connection attempt.
        if flags & 0x02 and not flags & 0x10:
            key = (ip.src, ip.dst)
            traffic[key].append(
                (float(packet.time), int(tcp.dport))
            )

    for events in traffic.values():
        events.sort(key=lambda event: event[0])

    return traffic


def detect_port_scans(packets, threshold=10, window_seconds=10):
    """Detect probes to many unique TCP ports within a time window."""
    traffic = collect_syn_events(packets)
    alerts = []

    for (src, dst), events in traffic.items():
        window = deque()
        port_counts = Counter()
        scan_ports = None

        for timestamp, port in events:
            window.append((timestamp, port))
            port_counts[port] += 1

            while window and timestamp - window[0][0] > window_seconds:
                _, old_port = window.popleft()
                port_counts[old_port] -= 1

                if port_counts[old_port] == 0:
                    del port_counts[old_port]

            if len(port_counts) >= threshold:
                scan_ports = sorted(port_counts)

        if scan_ports is not None:
            alerts.append({
                "alert_type": "Possible TCP SYN Port Scan",
                "severity": "HIGH",
                "source_ip": src,
                "destination_ip": dst,
                "unique_ports": len(scan_ports),
                "ports": scan_ports,
                "window_seconds": window_seconds,
            })

    return alerts


def detect_repeated_syn(packets, threshold=10, window_seconds=10):
    """
    Detect repeated initial SYN attempts to the same destination
    port within a time window. This is a heuristic, not proof of
    malicious activity.
    """
    traffic = collect_syn_events(packets)
    alerts = []

    for (src, dst), events in traffic.items():
        by_port = defaultdict(list)

        for timestamp, port in events:
            by_port[port].append(timestamp)

        for port, timestamps in by_port.items():
            window = deque()

            for timestamp in timestamps:
                window.append(timestamp)

                while (
                    window
                    and timestamp - window[0] > window_seconds
                ):
                    window.popleft()

                if len(window) >= threshold:
                    alerts.append({
                        "alert_type": "Repeated TCP SYN Attempts",
                        "severity": "MEDIUM",
                        "source_ip": src,
                        "destination_ip": dst,
                        "destination_port": port,
                        "attempts_in_window": len(window),
                        "window_seconds": window_seconds,
                    })
                    break

    return alerts