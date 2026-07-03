# -*- coding: utf-8 -*-
"""
Model wrappers and interfaces for unsupervised anomaly detection.
Provides an extensible architecture to easily swap or add new models.
"""

from abc import ABC, abstractmethod
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor

class BaseAnomalyModel(ABC):
    """
    Abstract Base Class for all unsupervised anomaly detection models in SentinelX.
    """
    @abstractmethod
    def fit(self, X: np.ndarray) -> None:
        """
        Trains the model on the provided numerical feature matrix.
        """
        pass

    @abstractmethod
    def predict_score(self, X: np.ndarray) -> np.ndarray:
        """
        Calculates and returns a normalized anomaly score in the range [0, 1] for each sample.
        Higher score means more anomalous.
        """
        pass

    @abstractmethod
    def predict(self, X: np.ndarray) -> np.ndarray:
        """
        Predicts labels: 1 for Anomaly, 0 for Normal.
        """
        pass


class IsolationForestModel(BaseAnomalyModel):
    """
    Isolation Forest implementation (Primary Unsupervised Model).
    """
    def __init__(self, n_estimators: int = 100, contamination: float = 0.1, random_state: int = 42):
        self.model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=random_state
        )

    def fit(self, X: np.ndarray) -> None:
        self.model.fit(X)

    def predict_score(self, X: np.ndarray) -> np.ndarray:
        # decision_function returns negative values for outliers, positive for inliers
        # Values range roughly from -0.5 to 0.5.
        decision_vals = self.model.decision_function(X)
        # Shift and scale so that:
        # -0.5 (most anomalous) maps to 1.0
        # 0.5 (most normal) maps to 0.0
        scores = (0.5 - decision_vals) / 1.0
        return np.clip(scores, 0.0, 1.0)

    def predict(self, X: np.ndarray) -> np.ndarray:
        # scikit-learn returns -1 for outliers, 1 for inliers
        predictions = self.model.predict(X)
        # Convert to 1 for Anomaly, 0 for Normal
        return np.where(predictions == -1, 1, 0)


class LocalOutlierFactorModel(BaseAnomalyModel):
    """
    Local Outlier Factor implementation (Secondary Unsupervised Model).
    """
    def __init__(self, n_neighbors: int = 20, contamination: float = 0.1):
        # novelty=True is mandatory to predict on unseen data
        self.model = LocalOutlierFactor(
            n_neighbors=n_neighbors,
            contamination=contamination,
            novelty=True
        )

    def fit(self, X: np.ndarray) -> None:
        self.model.fit(X)

    def predict_score(self, X: np.ndarray) -> np.ndarray:
        # decision_function returns negative values for outliers, positive for inliers
        decision_vals = self.model.decision_function(X)
        # Bounded between roughly -10 and 1. LOF is unbounded but typically close to 1.
        # Let's map negative values to high score, and positive values to lower.
        # A robust mapping:
        scores = -decision_vals
        # Map scores to [0, 1] using simple scaling and clipping
        # LOF decision_function returns negative offset of local density (closer to 0 is normal, more negative is outlier)
        # For novelty=True, normal samples are around 0, outliers are negative (e.g., -1.5, -5.0)
        # Let's map -1.5 to 1.0, 0.0 to 0.0
        norm_scores = np.abs(scores) / 1.5
        return np.clip(norm_scores, 0.0, 1.0)

    def predict(self, X: np.ndarray) -> np.ndarray:
        # Returns -1 for outliers, 1 for inliers
        predictions = self.model.predict(X)
        return np.where(predictions == -1, 1, 0)
