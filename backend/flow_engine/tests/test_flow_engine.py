# -*- coding: utf-8 -*-
"""
Unit tests for the Flow Reconstruction Engine.
"""

import unittest
from datetime import datetime, timedelta, timezone

from backend.packet_parser.models import ParsedPacket
from backend.flow_engine.flow import NetworkFlow
from backend.flow_engine.builder import FlowBuilder
from backend.flow_engine.service import FlowEngineService

class TestFlowEngine(unittest.TestCase):
    """
    Unit test cases for validating network flow reconstruction, bidirectional matching,
    timeout handling, and statistics calculation.
    """

    def setUp(self):
        # Sample base datetime
        self.base_time = datetime(2026, 7, 3, 12, 0, 0, tzinfo=timezone.utc)

    def test_tcp_flow(self):
        """
        Verify that sequential TCP packets from the same source to destination
        are correctly reconstructed into a single unidirectional TCP flow.
        """
        packets = [
            ParsedPacket(
                timestamp=(self.base_time).isoformat(),
                src_ip="192.168.1.50",
                dst_ip="10.0.0.1",
                src_port=49201,
                dst_port=80,
                protocol="TCP",
                packet_len=100,
                tcp_flags="S"
            ),
            ParsedPacket(
                timestamp=(self.base_time + timedelta(seconds=1)).isoformat(),
                src_ip="192.168.1.50",
                dst_ip="10.0.0.1",
                src_port=49201,
                dst_port=80,
                protocol="TCP",
                packet_len=1500,
                tcp_flags="A"
            )
        ]

        flows = FlowBuilder.build_flows(packets, idle_timeout_seconds=60.0)
        self.assertEqual(len(flows), 1)
        
        flow = flows[0]
        self.assertEqual(flow.src_ip, "192.168.1.50")
        self.assertEqual(flow.dst_ip, "10.0.0.1")
        self.assertEqual(flow.src_port, 49201)
        self.assertEqual(flow.dst_port, 80)
        self.assertEqual(flow.protocol, "TCP")
        self.assertEqual(flow.packet_count, 2)
        self.assertEqual(flow.forward_packets_count, 2)
        self.assertEqual(flow.reverse_packets_count, 0)
        self.assertEqual(flow.total_bytes, 1600)
        self.assertEqual(flow.bytes_sent, 1600)
        self.assertEqual(flow.bytes_received, 0)
        self.assertEqual(flow.calculated_duration, 1.0)
        self.assertEqual(flow.min_packet_size, 100)
        self.assertEqual(flow.max_packet_size, 1500)
        self.assertEqual(flow.avg_packet_size, 800.0)
        self.assertIn("S", flow.tcp_flags_seen)
        self.assertIn("A", flow.tcp_flags_seen)

    def test_udp_flow(self):
        """
        Verify UDP packets are successfully reconstructed.
        """
        packets = [
            ParsedPacket(
                timestamp=(self.base_time).isoformat(),
                src_ip="192.168.1.10",
                dst_ip="8.8.8.8",
                src_port=53535,
                dst_port=53,
                protocol="UDP",
                packet_len=64
            )
        ]

        flows = FlowBuilder.build_flows(packets, idle_timeout_seconds=60.0)
        self.assertEqual(len(flows), 1)
        flow = flows[0]
        self.assertEqual(flow.protocol, "UDP")
        self.assertEqual(flow.packet_count, 1)
        self.assertEqual(flow.total_bytes, 64)

    def test_bidirectional_matching(self):
        """
        Verify that forward and reverse packets are correctly merged into a single
        bidirectional flow with proper byte attribution.
        """
        packets = [
            # Client Request (Forward)
            ParsedPacket(
                timestamp=(self.base_time).isoformat(),
                src_ip="192.168.1.50",
                dst_ip="10.0.0.1",
                src_port=49201,
                dst_port=80,
                protocol="TCP",
                packet_len=100,
                tcp_flags="S"
            ),
            # Server Response (Reverse)
            ParsedPacket(
                timestamp=(self.base_time + timedelta(milliseconds=50)).isoformat(),
                src_ip="10.0.0.1",
                dst_ip="192.168.1.50",
                src_port=80,
                dst_port=49201,
                protocol="TCP",
                packet_len=200,
                tcp_flags="SA"
            ),
            # Client ACK (Forward)
            ParsedPacket(
                timestamp=(self.base_time + timedelta(milliseconds=100)).isoformat(),
                src_ip="192.168.1.50",
                dst_ip="10.0.0.1",
                src_port=49201,
                dst_port=80,
                protocol="TCP",
                packet_len=50,
                tcp_flags="A"
            )
        ]

        flows = FlowBuilder.build_flows(packets, idle_timeout_seconds=60.0)
        self.assertEqual(len(flows), 1)
        
        flow = flows[0]
        self.assertEqual(flow.packet_count, 3)
        self.assertEqual(flow.forward_packets_count, 2)
        self.assertEqual(flow.reverse_packets_count, 1)
        self.assertEqual(flow.total_bytes, 350)
        self.assertEqual(flow.bytes_sent, 150)       # 100 + 50
        self.assertEqual(flow.bytes_received, 200)   # 200
        self.assertEqual(flow.flow_direction, "bidirectional")
        self.assertEqual(flow.tcp_flags_summary, "A, S")

    def test_timeout_handling(self):
        """
        Verify that packets exceeding the idle timeout are split into distinct flows.
        """
        packets = [
            ParsedPacket(
                timestamp=(self.base_time).isoformat(),
                src_ip="192.168.1.50",
                dst_ip="10.0.0.1",
                src_port=49201,
                dst_port=80,
                protocol="TCP",
                packet_len=100,
                tcp_flags="S"
            ),
            # Packet arriving 65 seconds later (idle timeout is 60s)
            ParsedPacket(
                timestamp=(self.base_time + timedelta(seconds=65)).isoformat(),
                src_ip="192.168.1.50",
                dst_ip="10.0.0.1",
                src_port=49201,
                dst_port=80,
                protocol="TCP",
                packet_len=500,
                tcp_flags="A"
            )
        ]

        flows = FlowBuilder.build_flows(packets, idle_timeout_seconds=60.0)
        self.assertEqual(len(flows), 2)
        
        flow1 = flows[0]
        flow2 = flows[1]
        
        self.assertNotEqual(flow1.flow_id, flow2.flow_id)
        self.assertEqual(flow1.packet_count, 1)
        self.assertEqual(flow1.total_bytes, 100)
        
        self.assertEqual(flow2.packet_count, 1)
        self.assertEqual(flow2.total_bytes, 500)

    def test_statistics(self):
        """
        Verify the in-memory statistics calculation by the FlowEngineService.
        """
        packets = [
            ParsedPacket(
                timestamp=(self.base_time).isoformat(),
                src_ip="192.168.1.50",
                dst_ip="10.0.0.1",
                src_port=49201,
                dst_port=80,
                protocol="TCP",
                packet_len=100
            ),
            ParsedPacket(
                timestamp=(self.base_time + timedelta(seconds=2)).isoformat(),
                src_ip="10.0.0.1",
                dst_ip="192.168.1.50",
                src_port=80,
                dst_port=49201,
                protocol="TCP",
                packet_len=200
            ),
            ParsedPacket(
                timestamp=(self.base_time + timedelta(seconds=5)).isoformat(),
                src_ip="192.168.1.10",
                dst_ip="8.8.8.8",
                src_port=53535,
                dst_port=53,
                protocol="UDP",
                packet_len=50
            )
        ]

        # Use mock flow list inside FlowEngineService
        service = FlowEngineService()
        reconstructed = FlowBuilder.build_flows(packets)
        
        with service.state_lock:
            service.flows = reconstructed
            
        stats = service.get_statistics()
        
        self.assertEqual(stats["total_flows"], 2)
        self.assertEqual(stats["protocol_distribution"].get("TCP"), 1)
        self.assertEqual(stats["protocol_distribution"].get("UDP"), 1)
        
        # Verify average duration (one flow of 2s, one flow of 0s -> avg = 1.0s)
        self.assertEqual(stats["average_duration"], 1.0)
        
        # Verify top talkers ranking
        # 192.168.1.50 is involved in flow1 (300 bytes)
        # 10.0.0.1 is involved in flow1 (300 bytes)
        # 192.168.1.10 is involved in flow2 (50 bytes)
        # 8.8.8.8 is involved in flow2 (50 bytes)
        talkers = {t["ip"]: t["total_bytes"] for t in stats["top_talkers"]}
        self.assertEqual(talkers["192.168.1.50"], 300)
        self.assertEqual(talkers["10.0.0.1"], 300)
        self.assertEqual(talkers["192.168.1.10"], 50)
        self.assertEqual(talkers["8.8.8.8"], 50)

if __name__ == "__main__":
    unittest.main()
