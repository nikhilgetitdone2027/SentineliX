# -*- coding: utf-8 -*-
"""
Unit tests for the PacketParserService state management and telemetry calculations.
"""

# Monkeypatch Scapy's Linux rtnetlink IPv6 routing table loader before other imports
try:
    import scapy.config
    scapy.config.conf.ipv6_enabled = False
except Exception:
    pass

try:
    import scapy.arch
    scapy.arch.read_routes6 = lambda *args, **kwargs: []
except Exception:
    pass

try:
    import scapy.arch.linux.rtnetlink
    scapy.arch.linux.rtnetlink.read_routes6 = lambda *args, **kwargs: []
except Exception:
    pass

try:
    import scapy.route6
    scapy.route6.read_routes6 = lambda *args, **kwargs: []
except Exception:
    pass

import unittest
from datetime import datetime, timezone

from backend.packet_parser.models import ParsedPacket
from backend.packet_parser.service import PacketParserService

class TestPacketParserService(unittest.TestCase):
    """
    Test suite for in-memory packet buffering and telemetry reporting.
    """

    def setUp(self):
        """
        Setup the Singleton service instance and clear existing cached state before every test.
        """
        self.service = PacketParserService()
        self.service.clear_packets()

    def test_add_and_retrieve_packets(self):
        """
        Verify that parsed packets are successfully cached in memory and can be fetched.
        """
        self.assertEqual(len(self.service.get_all_packets()), 0)

        packet = ParsedPacket(
            timestamp=datetime.now(timezone.utc).isoformat(),
            src_ip="192.168.1.5",
            dst_ip="8.8.8.8",
            protocol="DNS",
            packet_len=128
        )
        
        # Manually inject into packet buffer for isolated service testing
        self.service.packets.append(packet)
        
        stored = self.service.get_all_packets()
        self.assertEqual(len(stored), 1)
        self.assertEqual(stored[0].src_ip, "192.168.1.5")
        self.assertEqual(stored[0].protocol, "DNS")

    def test_statistics_calculation(self):
        """
        Verify that statistics, protocol distributions, and top source/destination IPs are computed correctly.
        """
        ts = datetime.now(timezone.utc).isoformat()
        
        packets_to_add = [
            ParsedPacket(timestamp=ts, src_ip="10.0.0.1", dst_ip="10.0.0.2", protocol="TCP", packet_len=64),
            ParsedPacket(timestamp=ts, src_ip="10.0.0.1", dst_ip="10.0.0.3", protocol="TCP", packet_len=128),
            ParsedPacket(timestamp=ts, src_ip="10.0.0.2", dst_ip="10.0.0.3", protocol="UDP", packet_len=256),
            ParsedPacket(timestamp=ts, src_ip="10.0.0.4", dst_ip="10.0.0.3", protocol="DNS", packet_len=512),
            ParsedPacket(timestamp=ts, src_ip="10.0.0.1", dst_ip="10.0.0.5", protocol="HTTP", packet_len=1024),
            ParsedPacket(timestamp=ts, src_ip="10.0.0.6", dst_ip="10.0.0.2", protocol="ICMP", packet_len=32),
        ]

        self.service.packets.extend(packets_to_add)

        stats = self.service.get_statistics()

        # Check general packet counts
        self.assertEqual(stats["total_packets"], 6)
        
        # Verify specific protocol mapping counts
        self.assertEqual(stats["tcp_packets"], 3)  # 2 TCP + 1 HTTP
        self.assertEqual(stats["udp_packets"], 2)  # 1 UDP + 1 DNS
        self.assertEqual(stats["icmp_packets"], 1) # 1 ICMP
        self.assertEqual(stats["dns_packets"], 1)  # 1 DNS
        self.assertEqual(stats["http_packets"], 1) # 1 HTTP

        # Verify top sources ordering: "10.0.0.1" has 3 packets, others have 1
        self.assertEqual(stats["top_sources"][0]["ip"], "10.0.0.1")
        self.assertEqual(stats["top_sources"][0]["count"], 3)

        # Verify top destinations ordering: "10.0.0.3" has 3 packets, others have 1 or 2
        self.assertEqual(stats["top_destinations"][0]["ip"], "10.0.0.3")
        self.assertEqual(stats["top_destinations"][0]["count"], 3)

if __name__ == "__main__":
    unittest.main()
