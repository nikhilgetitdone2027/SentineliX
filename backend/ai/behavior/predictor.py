# -*- coding: utf-8 -*-
"""
Model Predictor for running inferences and generating detailed explainable anomaly labels.
"""

from typing import List, Dict, Any
import numpy as np
from backend.feature_engine.models import BehaviouralFeatureVector
from .models import BaseAnomalyModel
from .feature_processor import FeatureProcessor
from .risk_engine import RiskEngine
from .schemas import PredictResponse

class ModelPredictor:
    """
    Handles making predictions on feature vectors, calculating confidence, and compiling risk metrics.
    """
    def __init__(self, model: BaseAnomalyModel, processor: FeatureProcessor):
        self.model = model
        self.processor = processor

    def predict_single(self, feature_vector: BehaviouralFeatureVector) -> PredictResponse:
        """
        Runs model inference on a single BehaviouralFeatureVector and returns a complete PredictResponse.
        """
        # 1. Scale and prepare feature vector
        X_scaled = self.processor.transform([feature_vector])

        # 2. Extract raw machine learning model output
        anomaly_score = float(self.model.predict_score(X_scaled)[0])
        model_prediction = int(self.model.predict(X_scaled)[0])  # 1 for Anomaly, 0 for Normal

        # 3. Compute risk scores and compile explanations via the RiskEngine
        risk_score, risk_level, top_reasons = RiskEngine.calculate_risk(feature_vector, anomaly_score)

        # 4. Determine final consensus prediction label (Anomaly vs Normal)
        # Marked as Anomaly if:
        # - The ML model strongly predicts anomaly (model_prediction == 1 or anomaly_score > 0.5)
        # - OR if the final computed risk level is HIGH or CRITICAL
        is_anomaly = (model_prediction == 1) or (anomaly_score > 0.5) or (risk_level in ["HIGH", "CRITICAL"])
        prediction_label = "Anomaly" if is_anomaly else "Normal"

        # 5. Compute the AI confidence percentage [50, 100]
        # Margin of difference from the decision boundary (0.5)
        confidence_val = 50.0 + abs(anomaly_score - 0.5) * 100.0
        confidence = min(100.0, max(50.0, round(confidence_val, 1)))

        return PredictResponse(
            flow_id=feature_vector.flow_id,
            prediction=prediction_label,
            anomaly_score=round(anomaly_score, 4),
            risk_score=risk_score,
            confidence=confidence,
            top_reasons=top_reasons,
            risk_level=risk_level
        )

    def predict_batch(self, feature_vectors: List[BehaviouralFeatureVector]) -> List[PredictResponse]:
        """
        Infers predictions over a batch of feature vectors.
        """
        if not feature_vectors:
            return []
            
        return [self.predict_single(fv) for fv in feature_vectors]
