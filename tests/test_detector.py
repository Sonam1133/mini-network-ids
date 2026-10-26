from src.detector import detect_repeated_syn

import unittest

from scapy.all import Ether, IP, TCP

from src.detector import detect_port_scans


def make_packet(src, dst, port, timestamp, flags="S"):
    packet = (
        Ether()
        / IP(src=src, dst=dst)
        / TCP(sport=45000, dport=port, flags=flags)
    )
    packet.time = timestamp
    return packet


class TestPortScanDetector(unittest.TestCase):

    def test_detects_scan_within_time_window(self):
        packets = [
            make_packet(
                "192.168.1.50",
                "192.168.1.10",
                port,
                index * 0.1,
            )
            for index, port in enumerate(range(20, 36))
        ]

        alerts = detect_port_scans(packets)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["unique_ports"], 16)

    def test_normal_single_port_traffic_is_not_flagged(self):
        packets = [
            make_packet(
                "192.168.1.25",
                "192.168.1.10",
                443,
                1.0,
            )
        ]

        alerts = detect_port_scans(packets)

        self.assertEqual(alerts, [])

    def test_probes_spread_out_over_time_are_not_flagged(self):
        packets = [
            make_packet(
                "192.168.1.50",
                "192.168.1.10",
                port,
                index * 20.0,
            )
            for index, port in enumerate(range(20, 36))
        ]

        alerts = detect_port_scans(packets)

        self.assertEqual(alerts, [])

    def test_repeated_probes_to_same_port_are_not_flagged(self):
        packets = [
            make_packet(
                "192.168.1.50",
                "192.168.1.10",
                443,
                index * 0.1,
            )
            for index in range(15)
        ]

        alerts = detect_port_scans(packets)

        self.assertEqual(alerts, [])

    def test_repeated_syn_attempts_are_detected(self):
        packets = [
            make_packet(
                "192.168.1.50",
                "192.168.1.10",
                443,
                index * 0.1,
            )
            for index in range(10)
        ]

        alerts = detect_repeated_syn(packets)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(
            alerts[0]["alert_type"],
            "Repeated TCP SYN Attempts",
        )
        self.assertEqual(alerts[0]["destination_port"], 443)
        self.assertEqual(alerts[0]["attempts_in_window"], 10)

if __name__ == "__main__":
    unittest.main()

    def test_repeated_syn_attempts_are_detected(self):
        packets = [
            make_packet(
                "192.168.1.50",
                "192.168.1.10",
                443,
                index * 0.1,
            )
            for index in range(10)
        ]

        alerts = detect_repeated_syn(packets)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(
            alerts[0]["alert_type"],
            "Repeated TCP SYN Attempts",
        )
        self.assertEqual(alerts[0]["destination_port"], 443)
        self.assertEqual(alerts[0]["attempts_in_window"], 10)