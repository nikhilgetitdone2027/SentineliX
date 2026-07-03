# -*- coding: utf-8 -*-
"""
Model Trainer for managing the lifecycle, training, and saving of anomaly models.
"""

import os
import joblib
from typing import List, Dict, Any, Tuple
from backend.feature_engine.models import BehaviouralFeatureVector
from .models import IsolationForestModel, LocalOutlierFactorModel, BaseAnomalyModel
from .feature_processor import FeatureProcessor

MODEL_DIR = os.path.join(os.path.dirname(__file__), "saved_models")
os.makedirs(MODEL_DIR, exist_ok=True)

MODEL_PATH = os.path.join(MODEL_DIR, "isolation_forest.joblib")
SCALER_PATH = os.path.join(MODEL_DIR, "scaler.joblib")

class ModelTrainer:
    """
    Manages fitting, saving, loading, and retraining of primary and secondary models.
    """
    @staticmethod
    def train_model(
        features: List[BehaviouralFeatureVector],
        model_type: str = "IsolationForest"
    ) -> Tuple[BaseAnomalyModel, FeatureProcessor]:
        """
        Fits a FeatureProcessor and an unsupervised model on the provided dataset.
        If the dataset is too small, generates robust synthetic baseline data to train on.
        """
        processor = FeatureProcessor()

        # Handle tiny or empty dataset by generating normal synthetic vectors as a baseline
        training_features = list(features)
        if len(training_features) < 10:
            training_features.extend(ModelTrainer._generate_synthetic_baseline(100))

        # Fit feature processor
        X_scaled = processor.fit_transform(training_features)

        # Instantiate and train model
        if model_type.lower() == "localoutlierfactor":
            model = LocalOutlierFactorModel()
        else:
            model = IsolationForestModel()

        model.fit(X_scaled)

        # Save model and scaler
        ModelTrainer.save_model_and_scaler(model, processor)

        return model, processor

    @staticmethod
    def save_model_and_scaler(model: BaseAnomalyModel, processor: FeatureProcessor) -> None:
        """
        Serializes and saves the trained model and scaler.
        """
        joblib.dump(model, MODEL_PATH)
        joblib.dump(processor, SCALER_PATH)

    @staticmethod
    def load_model_and_scaler() -> Tuple[BaseAnomalyModel, FeatureProcessor]:
        """
        Loads the trained model and scaler from storage.
        If files do not exist, runs training on a synthetic baseline to create them.
        """
        if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
            try:
                model = joblib.load(MODEL_PATH)
                processor = joblib.load(SCALER_PATH)
                return model, processor
            except Exception:
                # If loading fails due to environment mismatches, fallback to retraining
                pass

        # Create baseline if not found
        model, processor = ModelTrainer.train_model([])
        return model, processor

    @staticmethod
    def _generate_synthetic_baseline(count: int) -> List[dict]:
        """
        Generates normal synthetic baseline features representing common network transactions.
        Ensures the model is fit and works reliably even if no real flows are available.
        """
        synthetic_flows = []
        for i in range(count):
            # Baseline normal web traffic: brief duration, standard sizes, low risk
            synthetic_flows.append({
                "flow_id": f"synthetic_normal_{i}",
                "duration": round(1.0 + (i % 5) * 0.5, 2),
                "packet_count": 4 + (i % 3) * 2,
                "bytes_sent": 200 + (i % 10) * 50,
                "bytes_received": 500 + (i % 10) * 150,
                "total_bytes": 700 + (i % 10) * 200,
                "avg_packet_size": 100.0,
                "min_packet_size": 60,
                "max_packet_size": 1500,
                "packets_per_second": 5.0,
                "bytes_per_second": 500.0,
                "byte_ratio": 30.0,
                "protocol": "TCP" if i % 2 == 0 else "HTTP",
                "src_port": 50000 + i,
                "dst_port": 80 if i % 2 == 0 else 443,
                "direction": "bidirectional",
                "connection_count": 1,
                "dns_query_count": 0,
                "dns_unique_domains": 0,
                "dns_avg_query_len": 0.0,
                "http_host": "google.com" if i % 2 == 0 else None,
                "http_method": "GET" if i % 2 == 0 else None,
                "http_uri_len": 15 if i % 2 == 0 else None,
                "tls_sni": "google.com" if i % 2 != 0 else None,
                "tls_version": "TLSv1.3",
                "syn_count": 1,
                "ack_count": 3,
                "fin_count": 1,
                "rst_count": 0,
                "risk_features": {
                    "large_upload": False,
                    "long_session": False,
                    "high_packet_rate": False,
                    "high_byte_rate": False,
                    "repeated_connections": False,
                    "external_ip": False,
                    "internal_ip": True,
                    "common_port": True,
                    "rare_port": False,
                    "encrypted_traffic": i % 2 != 0
                }
            })
        return synthetic_flows
