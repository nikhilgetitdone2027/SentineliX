# -*- coding: utf-8 -*-
"""
Feature processor for standardizing and scaling network feature vectors for ML models.
"""

from typing import List, Union, Dict, Any
import numpy as np
from sklearn.preprocessing import StandardScaler
from backend.feature_engine.models import BehaviouralFeatureVector

# List of numerical feature attributes to extract from BehaviouralFeatureVector
FEATURE_KEYS = [
    "duration",
    "packet_count",
    "bytes_sent",
    "bytes_received",
    "total_bytes",
    "avg_packet_size",
    "packets_per_second",
    "bytes_per_second",
    "byte_ratio",
    "connection_count",
    "dns_query_count",
    "dns_unique_domains",
    "dns_avg_query_len",
    "http_uri_len",
    "syn_count",
    "ack_count",
    "fin_count",
    "rst_count"
]

class FeatureProcessor:
    """
    Handles scaling and conversion of BehaviouralFeatureVectors to numerical arrays.
    """
    def __init__(self):
        self.scaler = StandardScaler()
        self.is_fit = False

    def _vector_to_list(self, f: Union[BehaviouralFeatureVector, Dict[str, Any]]) -> List[float]:
        """
        Extracts a flat list of numerical values from a BehaviouralFeatureVector.
        """
        # Support both Pydantic models and raw dicts
        data = f if isinstance(f, dict) else f.model_dump()
        
        row = []
        for key in FEATURE_KEYS:
            val = data.get(key)
            if val is None:
                row.append(0.0)
            else:
                row.append(float(val))
        return row

    def vectors_to_matrix(self, features: List[Union[BehaviouralFeatureVector, Dict[str, Any]]]) -> np.ndarray:
        """
        Converts a list of feature vectors into a 2D numpy array.
        """
        if not features:
            return np.empty((0, len(FEATURE_KEYS)))
        rows = [self._vector_to_list(f) for f in features]
        return np.array(rows, dtype=np.float64)

    def fit(self, features: List[Union[BehaviouralFeatureVector, Dict[str, Any]]]) -> 'FeatureProcessor':
        """
        Fits the scaler to the provided feature vectors.
        """
        if not features:
            return self
            
        matrix = self.vectors_to_matrix(features)
        self.scaler.fit(matrix)
        self.is_fit = True
        return self

    def transform(self, features: List[Union[BehaviouralFeatureVector, Dict[str, Any]]]) -> np.ndarray:
        """
        Normalizes and returns the scaled feature matrix.
        """
        if not features:
            return np.empty((0, len(FEATURE_KEYS)))
            
        matrix = self.vectors_to_matrix(features)
        if self.is_fit:
            return self.scaler.transform(matrix)
        else:
            # Fallback if scaler hasn't been fit yet
            return matrix

    def fit_transform(self, features: List[Union[BehaviouralFeatureVector, Dict[str, Any]]]) -> np.ndarray:
        """
        Fits the scaler and returns the scaled matrix.
        """
        self.fit(features)
        return self.transform(features)
