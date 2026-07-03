# -*- coding: utf-8 -*-
"""
Unit tests for the Feature Extraction Engine.
"""

import unittest
from datetime import datetime, timedelta, timezone

from backend.packet_parser.models import ParsedPacket
from backend.flow_engine.flow import NetworkFlow
from backend.feature_engine.models import BehaviouralFeatureVector
from backend.feature_engine.extractor import FeatureExtractor, is_private_ip
from backend.feature_engine.feature_builder import FeatureBuilder, map_packets_to_flows
from backend.feature_engine.statistics import FeatureStatisticsCalculator

class TestFeatureEngine(unittest.TestCase):
    """
    Unit test cases for feature extraction logic, heuristics, statistics, and mapping pipelines.
    """

    def setUp(self):
        self.base_time = datetime(2026, 7, 3, 12, 0, 0, tzinfo=timezone.utc)

    def test_ip_private_or_public(self):
        """
        Verify that is_private_ip correctly labels RFC1918 and public IPs.
        """
        # RFC1918 Private IPs
        self.assertTrue(is_private_ip("192.168.1.1"))
        self.assertTrue(is_private_ip("10.0.4.5"))
        self.assertTrue(is_private_ip("172.16.42.10"))
        self.assertTrue(is_private_ip("127.0.0.1"))

        # Public IPs
        self.assertFalse(is_private_ip("8.8.8.8"))
        self.assertFalse(is_private_ip("185.220.101.43"))

    def test_risk_feature_heuristics(self):
        """
        Validate threat and behaviour indicator heuristics (Risk Features).
        """
        # Case A: Default standard connection
        flow_a = NetworkFlow(
            flow_id="f_a",
            src_ip="192.168.1.15",
            dst_ip="192.168.1.1",
            src_port=51000,
            dst_port=80,
            protocol="TCP",
            start_time=self.base_time
        )
        flow_a.add_packet(self.base_time, is_forward=True, length=100)
        
        vector_a = FeatureExtractor.extract_features(flow=flow_a, packets=[], connection_count=1)
        risk_a = vector_a.risk_features
        
        self.assertFalse(risk_a.large_upload)
        self.assertFalse(risk_a.long_session)
        self.assertFalse(risk_a.high_packet_rate)
        self.assertFalse(risk_a.high_byte_rate)
        self.assertFalse(risk_a.repeated_connections)
        self.assertFalse(risk_a.external_ip) # Both are private
        self.assertTrue(risk_a.internal_ip)
        self.assertTrue(risk_a.common_port) # Port 80 is common
        self.assertFalse(risk_a.rare_port)
        self.assertFalse(risk_a.encrypted_traffic)

        # Case B: High risk/anomalous public connection
        flow_b = NetworkFlow(
            flow_id="f_b",
            src_ip="192.168.1.15",
            dst_ip="8.8.8.8",
            src_port=51001,
            dst_port=443,
            protocol="TLS",
            start_time=self.base_time
        )
        # Simulate active timeout and duration > 5 mins, and bytes > 1MB sent
        flow_b.add_packet(self.base_time, is_forward=True, length=1_500_000)
        flow_b.add_packet(self.base_time + timedelta(seconds=350), is_forward=True, length=100)
        
        vector_b = FeatureExtractor.extract_features(flow=flow_b, packets=[], connection_count=12)
        risk_b = vector_b.risk_features
        
        self.assertTrue(risk_b.large_upload)
        self.assertTrue(risk_b.long_session)
        self.assertTrue(risk_b.repeated_connections)
        self.assertTrue(risk_b.external_ip) # dst is public
        self.assertFalse(risk_b.internal_ip)
        self.assertTrue(risk_b.common_port) # 443 is common
        self.assertFalse(risk_b.rare_port)
        self.assertTrue(risk_b.encrypted_traffic) # Protocol is TLS / Port 443

    def test_protocol_handling(self):
        """
        Verify protocol-specific field extraction (DNS, HTTP, TLS, TCP flags counts).
        """
        # Case A: DNS flow
        flow_dns = NetworkFlow(
            flow_id="f_dns",
            src_ip="192.168.1.15",
            dst_ip="8.8.8.8",
            src_port=53000,
            dst_port=53,
            protocol="DNS",
            start_time=self.base_time
        )
        flow_dns.add_packet(self.base_time, is_forward=True, length=60, dns_query="malicious-domain.com")
        flow_dns.add_packet(self.base_time + timedelta(seconds=1), is_forward=False, length=120)
        
        vector_dns = FeatureExtractor.extract_features(flow=flow_dns, packets=[], connection_count=1)
        self.assertEqual(vector_dns.dns_query_count, 1)
        self.assertEqual(vector_dns.dns_unique_domains, 1)
        self.assertEqual(vector_dns.dns_avg_query_len, 20.0) # len("malicious-domain.com") = 20

        # Case B: TCP Flags counts from packets
        flow_tcp = NetworkFlow(
            flow_id="f_tcp",
            src_ip="192.168.1.15",
            dst_ip="10.0.0.1",
            src_port=49000,
            dst_port=80,
            protocol="TCP",
            start_time=self.base_time
        )
        flow_tcp.add_packet(self.base_time, is_forward=True, length=64)
        flow_tcp.add_packet(self.base_time + timedelta(seconds=1), is_forward=True, length=64)
        
        associated_packets = [
            ParsedPacket(timestamp=self.base_time.isoformat(), protocol="TCP", packet_len=64, tcp_flags="S"),
            ParsedPacket(timestamp=(self.base_time + timedelta(seconds=1)).isoformat(), protocol="TCP", packet_len=64, tcp_flags="SA"),
            ParsedPacket(timestamp=(self.base_time + timedelta(seconds=2)).isoformat(), protocol="TCP", packet_len=64, tcp_flags="F"),
            ParsedPacket(timestamp=(self.base_time + timedelta(seconds=3)).isoformat(), protocol="TCP", packet_len=64, tcp_flags="R")
        ]
        
        vector_tcp = FeatureExtractor.extract_features(flow=flow_tcp, packets=associated_packets, connection_count=1)
        self.assertEqual(vector_tcp.syn_count, 2)  # "S" and "SA"
        self.assertEqual(vector_tcp.ack_count, 1)  # "SA"
        self.assertEqual(vector_tcp.fin_count, 1)  # "F"
        self.assertEqual(vector_tcp.rst_count, 1)  # "R"

    def test_statistics_aggregation(self):
        """
        Verify statistics calculations over multiple feature vectors.
        """
        # Create mock features
        f1 = BehaviouralFeatureVector(
            flow_id="f1",
            duration=10.0,
            packet_count=5,
            bytes_sent=1000,
            bytes_received=2000,
            total_bytes=3000,
            avg_packet_size=600.0,
            min_packet_size=100,
            max_packet_size=1500,
            packets_per_second=0.5,
            bytes_per_second=300.0,
            byte_ratio=33.33,
            protocol="TCP",
            src_port=1234,
            dst_port=80,
            direction="bidirectional",
            connection_count=1,
            tls_sni=None,
            http_host="my-website.org"
        )
        f2 = BehaviouralFeatureVector(
            flow_id="f2",
            duration=20.0,
            packet_count=10,
            bytes_sent=3000,
            bytes_received=4000,
            total_bytes=7000,
            avg_packet_size=700.0,
            min_packet_size=200,
            max_packet_size=1000,
            packets_per_second=0.5,
            bytes_per_second=350.0,
            byte_ratio=42.86,
            protocol="TLS",
            src_port=5678,
            dst_port=443,
            direction="bidirectional",
            connection_count=1,
            tls_sni="my-website.org",
            http_host=None
        )

        stats = FeatureStatisticsCalculator.calculate_statistics([f1, f2])
        
        self.assertEqual(stats["total_features"], 2)
        self.assertEqual(stats["average_flow_duration"], 15.0)
        self.assertEqual(stats["protocol_distribution"]["TCP"], 1)
        self.assertEqual(stats["protocol_distribution"]["TLS"], 1)
        
        # Verify average sent/received
        self.assertEqual(stats["average_upload_bytes"], 2000.0) # (1000 + 3000) / 2
        self.assertEqual(stats["average_download_bytes"], 3000.0) # (2000 + 4000) / 2

        # Verify top ports
        ports = {p["port"]: p["count"] for p in stats["top_ports"]}
        self.assertEqual(ports[80], 1)
        self.assertEqual(ports[443], 1)

        # Verify top hosts (both TLS SNI and HTTP host count towards 'my-website.org')
        hosts = {h["host"]: h["count"] for h in stats["top_hosts"]}
        self.assertEqual(hosts["my-website.org"], 2)

if __name__ == "__main__":
    unittest.main()
