# -*- coding: utf-8 -*-
"""
Unit tests for the MITRE ATT&CK Mapping Engine.
"""

import unittest
from backend.correlation_engine.schemas import Incident, TimelineEvent
from backend.mitre.mapper import MitreMapper
from backend.mitre.service import MitreService

class TestMitreMapper(unittest.TestCase):
    """
    Test suite verifying correctness of the rule-based mapping heuristics and statistic aggregations.
    """

    def setUp(self):
        # Sample base incident
        self.base_incident = Incident(
            incident_id="inc-test-01",
            incident_type="Potential Attack",
            related_flow_ids=["flow-01"],
            timeline=[
                TimelineEvent(
                    timestamp="2026-07-03T00:00:00Z",
                    message="Initial log detected",
                    flow_id="flow-01",
                    src_ip="10.0.0.5",
                    dst_ip="10.0.0.10",
                    protocol="TCP",
                    details="Base connection details"
                )
            ],
            severity="MEDIUM",
            confidence=80.0,
            risk_score=75.0,
            attack_summary="Standard threat activity detected on host",
            src_ip="10.0.0.5",
            dst_ip="10.0.0.10"
        )

    def test_powershell_mapping(self):
        # Update summary to include PowerShell execution details
        self.base_incident.attack_summary = "An adversary initiated a PowerShell command on the engineering computer."
        mappings = MitreMapper.map_incident(self.base_incident)
        
        # Verify PowerShell technique was mapped
        mapped_ids = {m.mitre_id for m in mappings}
        self.assertIn("T1059.001", mapped_ids)
        
        # Check details
        p_map = [m for m in mappings if m.mitre_id == "T1059.001"][0]
        self.assertEqual(p_map.tactic, "EXECUTION")
        self.assertEqual(p_map.technique, "Command and Scripting Interpreter: PowerShell")
        self.assertEqual(p_map.confidence, 90.0)

    def test_credential_stuffing_mapping(self):
        # Update summary and timeline to show brute-forcing
        self.base_incident.attack_summary = "Repeated failed login attempts on server."
        self.base_incident.timeline.append(
            TimelineEvent(
                timestamp="2026-07-03T00:01:00Z",
                message="Brute force dictionary attack on login interface",
                flow_id="flow-01",
                src_ip="10.0.0.5",
                dst_ip="10.0.0.10",
                protocol="TCP",
                details="Auth Status: FAILURE"
            )
        )
        mappings = MitreMapper.map_incident(self.base_incident)
        mapped_ids = {m.mitre_id for m in mappings}
        self.assertIn("T1110", mapped_ids)

    def test_exfiltration_mapping(self):
        # Update incident to show data transfer and high-entropy uploads
        self.base_incident.incident_type = "Potential Data Exfiltration"
        self.base_incident.attack_summary = "High-entropy TLS tunnel transferring large db backup files to Tor exit node."
        mappings = MitreMapper.map_incident(self.base_incident)
        mapped_ids = {m.mitre_id for m in mappings}
        self.assertIn("T1048", mapped_ids)

    def test_port_scanning_mapping(self):
        # Update summary to show network scans
        self.base_incident.attack_summary = "Probing and network service discovery sweep from external ip."
        mappings = MitreMapper.map_incident(self.base_incident)
        mapped_ids = {m.mitre_id for m in mappings}
        self.assertIn("T1046", mapped_ids)

    def test_fallback_heuristic(self):
        # Test generic fallback mapping
        self.base_incident.incident_type = "Unknown Anomaly"
        self.base_incident.attack_summary = "Generic behavioral spike"
        mappings = MitreMapper.map_incident(self.base_incident)
        mapped_ids = {m.mitre_id for m in mappings}
        self.assertIn("T1190", mapped_ids)


class TestMitreService(unittest.TestCase):
    """
    Test suite verifying singleton service behaviors and aggregated statistics.
    """

    def setUp(self):
        self.service = MitreService()

    def test_singleton(self):
        another_service = MitreService()
        self.assertIs(self.service, another_service)

    def test_statistics_aggregation(self):
        stats = self.service.get_statistics()
        self.assertIn("total_mapped_incidents", stats)
        self.assertIn("tactic_distribution", stats)
        self.assertIn("technique_distribution", stats)
        self.assertIn("average_confidence", stats)
        self.assertIn("top_tactic", stats)


if __name__ == "__main__":
    unittest.main()
