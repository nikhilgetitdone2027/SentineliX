# -*- coding: utf-8 -*-
"""
Integration tests for the FastAPI routing endpoints using TestClient.
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
from fastapi.testclient import TestClient

from backend.packet_parser.main import app
from backend.packet_parser.service import PacketParserService
from backend.packet_parser.models import ParsedPacket

class TestPacketParserAPI(unittest.TestCase):
    """
    Test suite for FastAPI routing contract validations.
    """

    def setUp(self):
        """
        Setup the TestClient and flush state.
        """
        self.client = TestClient(app)
        self.service = PacketParserService()
        self.service.clear_packets()

    def test_health_check(self):
        """
        Verify that the health check endpoint returns 200 OK and expected online metadata.
        """
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "ONLINE")
        self.assertEqual(data["service"], "packet_parser_microservice")

    def test_get_packets_empty(self):
        """
        Verify that returning packets from an empty cache succeeds and returns an empty JSON list.
        """
        response = self.client.get("/packet-parser/packets")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [])

    def test_get_packets_populated(self):
        """
        Verify that populated packets are serialized correctly via the `/packet-parser/packets` endpoint.
        """
        # Inject mock packet
        packet = ParsedPacket(
            timestamp="2026-07-03T08:12:59.601Z",
            src_mac="00:11:22:33:44:55",
            dst_mac="66:77:88:99:aa:bb",
            src_ip="10.0.60.100",
            dst_ip="185.220.101.43",
            src_port=55021,
            dst_port=443,
            protocol="TLS",
            packet_len=1460,
            tcp_flags="PA",
            ttl=64,
            tls_sni="secure-relay-onion.net"
        )
        self.service.packets.append(packet)

        response = self.client.get("/packet-parser/packets")
        self.assertEqual(response.status_code, 200)
        
        data = response.json()
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["src_ip"], "10.0.60.100")
        self.assertEqual(data[0]["dst_ip"], "185.220.101.43")
        self.assertEqual(data[0]["protocol"], "TLS")
        self.assertEqual(data[0]["tls_sni"], "secure-relay-onion.net")

    def test_get_statistics(self):
        """
        Verify that calling `/packet-parser/statistics` returns the computed statistics schema.
        """
        response = self.client.get("/packet-parser/statistics")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("total_packets", data)
        self.assertIn("tcp_packets", data)
        self.assertIn("udp_packets", data)
        self.assertIn("top_sources", data)
        self.assertIn("top_destinations", data)

    def test_clear_packets(self):
        """
        Verify that clearing the cache works as expected.
        """
        packet = ParsedPacket(
            timestamp="2026-07-03T08:12:59.601Z",
            src_ip="10.0.60.100",
            dst_ip="185.220.101.43",
            protocol="TCP",
            packet_len=64
        )
        self.service.packets.append(packet)
        self.assertEqual(len(self.service.packets), 1)

        response = self.client.post("/packet-parser/clear")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(self.service.packets), 0)
        self.assertEqual(response.json()["status"], "cleared")

if __name__ == "__main__":
    unittest.main()
