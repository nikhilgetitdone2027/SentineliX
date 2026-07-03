# -*- coding: utf-8 -*-
"""
Anomaly Service managing coordination, prediction caching, and thread-safe operations.
"""

import threading
from typing import List, Dict, Any, Tuple
from backend.feature_engine.service import FeatureEngineService
from backend.feature_engine.models import BehaviouralFeatureVector
from .models import BaseAnomalyModel
from .feature_processor import FeatureProcessor
from .trainer import ModelTrainer
from .predictor import ModelPredictor
from .schemas import PredictResponse

class AnomalyService:
    """
    Singleton service managing model persistence, in-memory results, and thread-safe training operations.
    """
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if not cls._instance:
                cls._instance = super(AnomalyService, cls).__new__(cls, *args, **kwargs)
                cls._instance._init_service()
            return cls._instance

    def _init_service(self):
        """
        Initializes the service by auto-loading the saved model and scaler.
        """
        self.state_lock = threading.Lock()
        self.results: List[PredictResponse] = []
        
        # Load or initialize model and scaler
        self.model, self.processor = ModelTrainer.load_model_and_scaler()
        self.predictor = ModelPredictor(self.model, self.processor)

    def train_model(self, model_type: str = "IsolationForest") -> int:
        """
        Gathers features from the FeatureEngineService, trains a new model, and hot-swaps it.
        """
        feature_service = FeatureEngineService()
        features = feature_service.get_all_features()

        with self.state_lock:
            # Fit and save the new model and scaler
            self.model, self.processor = ModelTrainer.train_model(features, model_type)
            self.predictor = ModelPredictor(self.model, self.processor)
            
            # Clear previous results to avoid stale prediction mismatches
            self.results.clear()

        return len(features)

    def predict_single(self, feature_vector: BehaviouralFeatureVector) -> PredictResponse:
        """
        Performs a single flow inference thread-safely.
        """
        with self.state_lock:
            return self.predictor.predict_single(feature_vector)

    def analyze_flows(self) -> Tuple[int, List[PredictResponse]]:
        """
        Pulls all active extracted feature vectors, runs batch prediction, caches results, and returns them.
        """
        feature_service = FeatureEngineService()
        features = feature_service.get_all_features()

        if not features:
            with self.state_lock:
                self.results.clear()
            return 0, []

        with self.state_lock:
            predictions = self.predictor.predict_batch(features)
            self.results = predictions

        return len(predictions), predictions

    def get_results(self) -> List[PredictResponse]:
        """
        Retrieves cached prediction results.
        """
        with self.state_lock:
            return list(self.results)

    def get_statistics(self) -> Dict[str, Any]:
        """
        Aggregates summary statistics over previously analyzed flows.
        """
        with self.state_lock:
            snapshot = list(self.results)

        if not snapshot:
            return {
                "total_analyzed": 0,
                "normal_count": 0,
                "anomaly_count": 0,
                "average_risk_score": 0.0,
                "highest_risk_score": 0.0,
                "protocol_distribution": {}
            }

        total_analyzed = len(snapshot)
        normal_count = sum(1 for r in snapshot if r.prediction == "Normal")
        anomaly_count = sum(1 for r in snapshot if r.prediction == "Anomaly")
        average_risk_score = round(sum(r.risk_score for r in snapshot) / total_analyzed, 2)
        highest_risk_score = max(r.risk_score for r in snapshot)

        # Retrieve feature vectors to map protocols accurately
        feature_service = FeatureEngineService()
        features = {f.flow_id: f.protocol for f in feature_service.get_all_features()}

        protocol_distribution: Dict[str, int] = {}
        for r in snapshot:
            proto = features.get(r.flow_id, "UNKNOWN").upper()
            protocol_distribution[proto] = protocol_distribution.get(proto, 0) + 1

        return {
            "total_analyzed": total_analyzed,
            "normal_count": normal_count,
            "anomaly_count": anomaly_count,
            "average_risk_score": average_risk_score,
            "highest_risk_score": highest_risk_score,
            "protocol_distribution": protocol_distribution
        }

    def clear_results(self):
        """
        Clears prediction caches.
        """
        with self.state_lock:
            self.results.clear()
