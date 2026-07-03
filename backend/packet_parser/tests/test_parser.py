# -*- coding: utf-8 -*-
"""
Unit tests for the PacketParser and byte-level utilities.
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
from unittest.mock import MagicMock
from scapy.all import Ether, IP, TCP, UDP, ICMP, DNS

from backend.packet_parser.utils import parse_tls_sni, parse_http_metadata, format_tcp_flags
from backend.packet_parser.parser import PacketParser
from backend.packet_parser.models import ParsedPacket

class TestPacketParserAndUtils(unittest.TestCase):
    """
    Test suite verifying telemetry extraction algorithms.
    """

    def test_format_tcp_flags(self):
        """
        Verify that integers representing TCP flags are correctly decoded into shorthand character strings.
        """
        self.assertEqual(format_tcp_flags(0x02), "S")  # SYN
        self.assertEqual(format_tcp_flags(0x12), "SA") # SYN-ACK
        self.assertEqual(format_tcp_flags(0x18), "PA") # PSH-ACK
        self.assertEqual(format_tcp_flags(0x01), "F")  # FIN
        self.assertEqual(format_tcp_flags(None), "")

    def test_parse_http_metadata(self):
        """
        Verify that raw byte payloads containing HTTP headers are dissected correctly.
        """
        # Test valid HTTP GET request
        http_payload = b"GET /index.html HTTP/1.1\r\nHost: internal-portal.sentinelx.gov\r\nUser-Agent: Mozilla\r\n\r\n"
        method, host = parse_http_metadata(http_payload)
        self.assertEqual(method, "GET")
        self.assertEqual(host, "internal-portal.sentinelx.gov")

        # Test valid HTTP POST request
        http_post = b"POST /api/v1/alert HTTP/1.1\r\nHost: 10.0.50.10\r\nContent-Length: 15\r\n\r\n{'status':'ok'}"
        method, host = parse_http_metadata(http_post)
        self.assertEqual(method, "POST")
        self.assertEqual(host, "10.0.50.10")

        # Test non-HTTP traffic
        junk_payload = b"\x00\x11\x22\x33random junk bytes"
        method, host = parse_http_metadata(junk_payload)
        self.assertIsNone(method)
        self.assertIsNone(host)

    def test_parse_tls_sni(self):
        """
        Verify that Server Name Indication (SNI) is successfully parsed from raw TLS Client Hello bytes.
        """
        # A mocked client hello starting with TLS handshake record content-type 22 (0x16) and version 3.1 (0x03 0x01)
        # and SNI extension containing "secure-relay-onion.net"
        raw_client_hello = (
            b"\x16\x03\x01\x00\xba\x01\x00\x00\xb6\x03\x03"  # TLS Record Header & Client Hello Header
            + b"\x00" * 32                                  # 32 bytes random
            + b"\x00"                                      # Session ID len = 0
            + b"\x00\x02\x00\x2f"                          # Cipher Suites (2 bytes len, suites)
            + b"\x01\x00"                                  # Compression (1 byte len, methods)
            + b"\x00\x7d"                                  # Extensions Length (125 bytes)
            # Extension: Server Name Indication (Type 0x0000, Length 0x001d)
            + b"\x00\x00\x00\x1d"
            # Server Name List Length (0x001b)
            + b"\x00\x1b"
            # Server Name: Type Host Name (0x00), Length 0x0018, Name "secure-relay-onion.net"
            + b"\x00\x00\x18secure-relay-onion.net"
            + b"\x00" * 80                                  # Padding trailing extensions
        )
        
        sni = parse_tls_sni(raw_client_hello)
        self.assertEqual(sni, "secure-relay-onion.net")

        # Test too short payload
        self.assertIsNone(parse_tls_sni(b"\x16\x03\x01\x00"))

    def test_dissect_packet_ether_ip_tcp(self):
        """
        Tests the dissect_packet static method with a mock Scapy Ethernet/IP/TCP packet.
        """
        # Build mock Scapy packet layers
        pkt = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / \
              IP(src="10.0.60.100", dst="185.220.101.43", ttl=64) / \
              TCP(sport=55021, dport=443, flags=0x18)
        
        # Override packet time for deterministic testing
        pkt.time = 1783066381.347
        
        parsed = PacketParser.dissect_packet(pkt)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.src_mac, "00:11:22:33:44:55")
        self.assertEqual(parsed.dst_mac, "66:77:88:99:aa:bb")
        self.assertEqual(parsed.src_ip, "10.0.60.100")
        self.assertEqual(parsed.dst_ip, "185.220.101.43")
        self.assertEqual(parsed.src_port, 55021)
        self.assertEqual(parsed.dst_port, 443)
        self.assertEqual(parsed.protocol, "TCP")
        self.assertEqual(parsed.ttl, 64)
        self.assertEqual(parsed.tcp_flags, "PA")

    def test_dissect_packet_dns(self):
        """
        Tests the dissect_packet static method with a mock Scapy DNS packet.
        """
        pkt = Ether() / IP(src="10.0.70.44", dst="10.0.50.10") / UDP(sport=51221, dport=53) / DNS(qd=MagicMock(qname=b"sentinelx.gov."))
        pkt.time = 1783066381.347

        parsed = PacketParser.dissect_packet(pkt)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.protocol, "DNS")
        self.assertEqual(parsed.dns_query, "sentinelx.gov")

if __name__ == "__main__":
    unittest.main()
