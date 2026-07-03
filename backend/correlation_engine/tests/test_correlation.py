# -*- coding: utf-8 -*-
"""
Unit tests for the Threat Correlation Engine.
"""

import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta, timezone

from backend.flow_engine.flow import NetworkFlow
from backend.feature_engine.models import BehaviouralFeatureVector, RiskFeatures
from backend.ai.behavior.schemas import PredictResponse
from backend.correlation_engine.correlator import ThreatCorrelator
from backend.correlation_engine.service import CorrelationService

class TestThreatCorrelationEngine(unittest.TestCase):
    """
    Test suite for ThreatCorrelator rules and CorrelationService integration.
    """

    def setUp(self):
        self.base_time = datetime(2026, 7, 3, 12, 0, 0, tzinfo=timezone.utc)

        # 1. Flow for Data Exfiltration (DNS flow followed by a massive outbound flow)
        self.dns_flow = NetworkFlow(
            flow_id="flow_dns",
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=52000,
            dst_port=53,
            protocol="DNS",
            start_time=self.base_time
        )
        self.dns_feat = BehaviouralFeatureVector(
            flow_id="flow_dns", duration=0.1, packet_count=2, bytes_sent=100, bytes_received=200,
            total_bytes=300, avg_packet_size=150.0, min_packet_size=50, max_packet_size=250,
            packets_per_second=20.0, bytes_per_second=3000.0, byte_ratio=33.3, protocol="DNS",
            src_port=52000, dst_port=53, direction="bidirectional", connection_count=1,
            dns_query_count=1, dns_unique_domains=1, dns_avg_query_len=12.0,
            risk_features=RiskFeatures(common_port=True, external_ip=True)
        )
        self.dns_pred = PredictResponse(
            flow_id="flow_dns", prediction="Anomaly", anomaly_score=0.8, risk_score=50.0,
            confidence=90.0, top_reasons=["High frequency DNS query"], risk_level="MEDIUM"
        )

        self.exfil_flow = NetworkFlow(
            flow_id="flow_exfil",
            src_ip="192.168.1.100",
            dst_ip="45.1.2.3",
            src_port=52001,
            dst_port=443,
            protocol="TCP",
            start_time=self.base_time + timedelta(seconds=30)
        )
        self.exfil_feat = BehaviouralFeatureVector(
            flow_id="flow_exfil", duration=15.0, packet_count=500, bytes_sent=2_500_000, bytes_received=1000,
            total_bytes=2_501_000, avg_packet_size=1500.0, min_packet_size=60, max_packet_size=1500,
            packets_per_second=33.3, bytes_per_second=166733.3, byte_ratio=99.9, protocol="TCP",
            src_port=52001, dst_port=443, direction="bidirectional", connection_count=1,
            risk_features=RiskFeatures(large_upload=True, rare_port=False, external_ip=True)
        )
        self.exfil_pred = PredictResponse(
            flow_id="flow_exfil", prediction="Normal", anomaly_score=0.2, risk_score=40.0,
            confidence=85.0, top_reasons=["Large outbound transfer"], risk_level="MEDIUM"
        )

        # 2. Flows for C2 Beaconing (3 repetitive flows between same endpoints)
        self.c2_flows = []
        self.c2_feats = []
        self.c2_preds = []
        for i in range(3):
            fid = f"flow_c2_{i}"
            flow = NetworkFlow(
                flow_id=fid,
                src_ip="192.168.1.50",
                dst_ip="99.99.99.99",
                src_port=49000 + i,
                dst_port=9999,
                protocol="TCP",
                start_time=self.base_time + timedelta(minutes=i * 5)
            )
            feat = BehaviouralFeatureVector(
                flow_id=fid, duration=2.0, packet_count=10, bytes_sent=400, bytes_received=400,
                total_bytes=800, avg_packet_size=80.0, min_packet_size=40, max_packet_size=150,
                packets_per_second=5.0, bytes_per_second=400.0, byte_ratio=50.0, protocol="TCP",
                src_port=49000 + i, dst_port=9999, direction="bidirectional", connection_count=3,
                risk_features=RiskFeatures(repeated_connections=True, rare_port=True, encrypted_traffic=True)
            )
            # Make the first one anomalous to trigger the rule
            pred = PredictResponse(
                flow_id=fid, prediction="Anomaly" if i == 0 else "Normal",
                anomaly_score=0.75 if i == 0 else 0.1,
                risk_score=60.0 if i == 0 else 30.0,
                confidence=95.0, top_reasons=["Anomalous behaviour"], risk_level="HIGH" if i == 0 else "LOW"
            )
            self.c2_flows.append(flow)
            self.c2_feats.append(feat)
            self.c2_preds.append(pred)

        # 3. Flows for Port Scanning (1 IP contacting 3 different ports)
        self.scan_flows = []
        self.scan_feats = []
        self.scan_preds = []
        for i in range(3):
            fid = f"flow_scan_{i}"
            flow = NetworkFlow(
                flow_id=fid,
                src_ip="192.168.1.200",
                dst_ip="10.0.0.1",
                src_port=53000,
                dst_port=80 + i * 10,
                protocol="TCP",
                start_time=self.base_time + timedelta(seconds=i * 5)
            )
            feat = BehaviouralFeatureVector(
                flow_id=fid, duration=0.2, packet_count=2, bytes_sent=100, bytes_received=0,
                total_bytes=100, avg_packet_size=50.0, min_packet_size=50, max_packet_size=50,
                packets_per_second=10.0, bytes_per_second=500.0, byte_ratio=100.0, protocol="TCP",
                src_port=53000, dst_port=80 + i * 10, direction="bidirectional", connection_count=1,
                risk_features=RiskFeatures(rare_port=True)
            )
            pred = PredictResponse(
                flow_id=fid, prediction="Normal", anomaly_score=0.3, risk_score=25.0,
                confidence=80.0, top_reasons=["Single probe"], risk_level="LOW"
            )
            self.scan_flows.append(flow)
            self.scan_feats.append(feat)
            self.scan_preds.append(pred)

    @patch('backend.flow_engine.service.FlowEngineService.get_all_flows')
    @patch('backend.feature_engine.service.FeatureEngineService.get_all_features')
    @patch('backend.ai.behavior.anomaly_service.AnomalyService.get_results')
    def test_correlation_data_exfiltration(self, mock_results, mock_features, mock_flows):
        """
        Verify that a large upload and a co-occurring DNS anomaly trigger an exfiltration incident.
        """
        mock_flows.return_value = [self.dns_flow, self.exfil_flow]
        mock_features.return_value = [self.dns_feat, self.exfil_feat]
        mock_results.return_value = [self.dns_pred, self.exfil_pred]

        incidents = ThreatCorrelator.correlate_incidents()
        
        # Check that one incident is returned
        self.assertEqual(len(incidents), 1)
        inc = incidents[0]
        self.assertEqual(inc.incident_type, "Data Exfiltration")
        self.assertEqual(inc.severity, "HIGH")
        self.assertEqual(inc.src_ip, "192.168.1.100")
        self.assertEqual(inc.dst_ip, "45.1.2.3")
        self.assertIn("flow_dns", inc.related_flow_ids)
        self.assertIn("flow_exfil", inc.related_flow_ids)
        self.assertIn("data exfiltration", inc.attack_summary)
        self.assertEqual(len(inc.timeline), 2)

    @patch('backend.flow_engine.service.FlowEngineService.get_all_flows')
    @patch('backend.feature_engine.service.FeatureEngineService.get_all_features')
    @patch('backend.ai.behavior.anomaly_service.AnomalyService.get_results')
    def test_correlation_c2_beaconing(self, mock_results, mock_features, mock_flows):
        """
        Verify that multiple repetitive flows with consistent spacing trigger a C2 beaconing incident.
        """
        mock_flows.return_value = self.c2_flows
        mock_features.return_value = self.c2_feats
        mock_results.return_value = self.c2_preds

        incidents = ThreatCorrelator.correlate_incidents()
        
        self.assertEqual(len(incidents), 1)
        inc = incidents[0]
        self.assertEqual(inc.incident_type, "Persistent Beaconing")
        self.assertEqual(inc.severity, "MEDIUM")
        self.assertEqual(inc.src_ip, "192.168.1.50")
        self.assertEqual(inc.dst_ip, "99.99.99.99")
        self.assertEqual(len(inc.related_flow_ids), 3)

    @patch('backend.flow_engine.service.FlowEngineService.get_all_flows')
    @patch('backend.feature_engine.service.FeatureEngineService.get_all_features')
    @patch('backend.ai.behavior.anomaly_service.AnomalyService.get_results')
    def test_correlation_port_scanning(self, mock_results, mock_features, mock_flows):
        """
        Verify that contacting multiple target ports within 5 minutes triggers a Port Scanning incident.
        """
        mock_flows.return_value = self.scan_flows
        mock_features.return_value = self.scan_feats
        mock_results.return_value = self.scan_preds

        incidents = ThreatCorrelator.correlate_incidents()
        
        self.assertEqual(len(incidents), 1)
        inc = incidents[0]
        self.assertEqual(inc.incident_type, "Port Scanning")
        self.assertEqual(inc.src_ip, "192.168.1.200")
        self.assertEqual(len(inc.related_flow_ids), 3)

    @patch('backend.flow_engine.service.FlowEngineService.get_all_flows')
    @patch('backend.feature_engine.service.FeatureEngineService.get_all_features')
    @patch('backend.ai.behavior.anomaly_service.AnomalyService.get_results')
    def test_correlation_service_state_and_stats(self, mock_results, mock_features, mock_flows):
        """
        Verify that CorrelationService aggregates stats and handles cache correctly.
        """
        mock_flows.return_value = [self.dns_flow, self.exfil_flow]
        mock_features.return_value = [self.dns_feat, self.exfil_feat]
        mock_results.return_value = [self.dns_pred, self.exfil_pred]

        service = CorrelationService()
        service.clear_incidents()
        
        incidents = service.get_incidents()
        self.assertEqual(len(incidents), 1)
        
        stats = service.get_statistics()
        self.assertEqual(stats["total_incidents"], 1)
        self.assertEqual(stats["severity_distribution"]["HIGH"], 1)
        self.assertEqual(stats["type_distribution"]["Data Exfiltration"], 1)
        self.assertEqual(stats["total_correlated_flows"], 2)

if __name__ == "__main__":
    unittest.main()
