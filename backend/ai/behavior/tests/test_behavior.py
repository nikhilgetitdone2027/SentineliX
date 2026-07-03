# -*- coding: utf-8 -*-
"""
Unit tests for the AI Behaviour Engine.
"""

import unittest
from datetime import datetime, timezone
import numpy as np

from backend.feature_engine.models import BehaviouralFeatureVector, RiskFeatures
from backend.ai.behavior.feature_processor import FeatureProcessor
from backend.ai.behavior.models import IsolationForestModel, LocalOutlierFactorModel
from backend.ai.behavior.risk_engine import RiskEngine
from backend.ai.behavior.predictor import ModelPredictor
from backend.ai.behavior.trainer import ModelTrainer
from backend.ai.behavior.anomaly_service import AnomalyService

class TestAIBehaviorEngine(unittest.TestCase):
    """
    Unit test cases covering Feature Processor, ML Models, Risk scoring, and Explainability.
    """

    def setUp(self):
        self.base_time = datetime(2026, 7, 3, 12, 0, 0, tzinfo=timezone.utc)
        
        # 1. Normal Sample
        self.normal_fv = BehaviouralFeatureVector(
            flow_id="f_normal",
            duration=2.5,
            packet_count=6,
            bytes_sent=400,
            bytes_received=800,
            total_bytes=1200,
            avg_packet_size=200.0,
            min_packet_size=64,
            max_packet_size=1024,
            packets_per_second=2.4,
            bytes_per_second=480.0,
            byte_ratio=33.3,
            protocol="TCP",
            src_port=51100,
            dst_port=443,
            direction="bidirectional",
            connection_count=1,
            syn_count=1,
            ack_count=3,
            fin_count=1,
            rst_count=0,
            risk_features=RiskFeatures(
                large_upload=False,
                long_session=False,
                high_packet_rate=False,
                high_byte_rate=False,
                repeated_connections=False,
                external_ip=False,
                internal_ip=True,
                common_port=True,
                rare_port=False,
                encrypted_traffic=True
            )
        )

        # 2. Highly Anomalous Sample (Large upload, long session, rare port, etc.)
        self.anomaly_fv = BehaviouralFeatureVector(
            flow_id="f_anomaly",
            duration=450.0,
            packet_count=1500,
            bytes_sent=2_500_000,
            bytes_received=500_000,
            total_bytes=3_000_000,
            avg_packet_size=1500.0,
            min_packet_size=64,
            max_packet_size=1500,
            packets_per_second=3.33,
            bytes_per_second=6666.6,
            byte_ratio=83.3,
            protocol="TCP",
            src_port=51200,
            dst_port=9999,
            direction="bidirectional",
            connection_count=12,
            syn_count=10,
            ack_count=1000,
            fin_count=5,
            rst_count=2,
            risk_features=RiskFeatures(
                large_upload=True,
                long_session=True,
                high_packet_rate=False,
                high_byte_rate=False,
                repeated_connections=True,
                external_ip=True,
                internal_ip=False,
                common_port=False,
                rare_port=True,
                encrypted_traffic=True
            )
        )

    def test_feature_processor_extraction(self):
        """
        Verify FeatureProcessor accurately serializes BehaviouralFeatureVector properties into a 2D float matrix.
        """
        processor = FeatureProcessor()
        matrix = processor.vectors_to_matrix([self.normal_fv, self.anomaly_fv])
        
        self.assertEqual(matrix.shape, (2, 18))  # 18 features extracted
        self.assertEqual(matrix[0, 0], 2.5)      # duration normal
        self.assertEqual(matrix[1, 0], 450.0)    # duration anomaly
        self.assertEqual(matrix[0, 2], 400.0)    # bytes_sent normal
        self.assertEqual(matrix[1, 2], 2500000.0)# bytes_sent anomaly

    def test_models_fit_and_prediction(self):
        """
        Validate fit, predict_score, and predict methods for IForest and LOF wrappers.
        """
        processor = FeatureProcessor()
        # Train on a synthetic set of normal vectors plus one outlier
        training_data = [self.normal_fv] * 15 + [self.anomaly_fv]
        X_scaled = processor.fit_transform(training_data)

        # A. Isolation Forest
        iforest = IsolationForestModel(random_state=42)
        iforest.fit(X_scaled)
        scores = iforest.predict_score(X_scaled)
        preds = iforest.predict(X_scaled)

        self.assertEqual(len(scores), len(training_data))
        self.assertEqual(len(preds), len(training_data))
        # The outlier (index 15) should have a higher anomaly score than normal samples (index 0)
        self.assertTrue(scores[15] > scores[0])

        # B. Local Outlier Factor
        lof = LocalOutlierFactorModel()
        lof.fit(X_scaled)
        lof_scores = lof.predict_score(X_scaled)
        self.assertEqual(len(lof_scores), len(training_data))

    def test_risk_scoring_and_explainability(self):
        """
        Verify that the RiskEngine calculates risk scores and levels based on indicators.
        """
        # Case 1: Normal FV (no rule indicators triggered, 0.0 model anomaly score)
        risk_score, risk_level, reasons = RiskEngine.calculate_risk(self.normal_fv, 0.0)
        self.assertTrue(risk_score < 40.0)
        self.assertEqual(risk_level, "LOW")
        self.assertIn("Normal baseline profile", reasons)

        # Case 2: Highly Anomalous FV (multiple rules triggered, high model score)
        # Weights: large_upload(20) + rare_port(10) + repeated_connections(10) + long_session(15) + external_ip(10) + encrypted_unknown_traffic(15) = 80
        # Plus model anomaly contribution of 1.0 * 20 = 20
        # Total = 100
        risk_score, risk_level, reasons = RiskEngine.calculate_risk(self.anomaly_fv, 1.0)
        self.assertEqual(risk_score, 100.0)
        self.assertEqual(risk_level, "CRITICAL")
        self.assertIn("Large outbound traffic", reasons)
        self.assertIn("Rare destination port", reasons)
        self.assertIn("Very long session", reasons)
        self.assertIn("Encrypted unknown traffic", reasons)

    def test_model_predictor(self):
        """
        Test prediction wrapper compiles complete PredictResponse payloads.
        """
        model = IsolationForestModel(random_state=42)
        processor = FeatureProcessor()
        
        training_data = [self.normal_fv] * 12
        X_scaled = processor.fit_transform(training_data)
        model.fit(X_scaled)

        predictor = ModelPredictor(model, processor)
        response = predictor.predict_single(self.normal_fv)

        self.assertEqual(response.flow_id, "f_normal")
        self.assertIn(response.prediction, ["Normal", "Anomaly"])
        self.assertTrue(0.0 <= response.anomaly_score <= 1.0)
        self.assertTrue(0.0 <= response.risk_score <= 100.0)
        self.assertTrue(50.0 <= response.confidence <= 100.0)

    def test_anomaly_service_flow(self):
        """
        Test the singleton coordinator service and statistics calculations.
        """
        service = AnomalyService()
        self.assertIsNotNone(service.model)
        self.assertIsNotNone(service.processor)

        # Clear results and manually feed a mock prediction
        service.clear_results()
        self.assertEqual(len(service.get_results()), 0)

        # Mock results population to check stats calculations
        from backend.ai.behavior.schemas import PredictResponse
        mock_response = PredictResponse(
            flow_id="f_mock",
            prediction="Normal",
            anomaly_score=0.1,
            risk_score=15.0,
            confidence=95.0,
            top_reasons=["Normal baseline profile"],
            risk_level="LOW"
        )
        service.results = [mock_response]
        
        stats = service.get_statistics()
        self.assertEqual(stats["total_analyzed"], 1)
        self.assertEqual(stats["normal_count"], 1)
        self.assertEqual(stats["average_risk_score"], 15.0)

if __name__ == "__main__":
    unittest.main()
