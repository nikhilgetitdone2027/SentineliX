# -*- coding: utf-8 -*-
"""
Service layer managing state, coordination, and building of flow behavioral feature vectors.
"""

import threading
from typing import List, Dict, Any, Tuple

from backend.packet_parser.service import PacketParserService
from backend.flow_engine.service import FlowEngineService
from .models import BehaviouralFeatureVector
from .feature_builder import FeatureBuilder
from .statistics import FeatureStatisticsCalculator

class FeatureEngineService:
    """
    Singleton service managing the lifecycle and persistence of extracted flow feature vectors.
    """
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if not cls._instance:
                cls._instance = super(FeatureEngineService, cls).__new__(cls, *args, **kwargs)
                cls._instance._init_service()
            return cls._instance

    def _init_service(self):
        """
        Initializes in-memory storage of feature vectors and thread-safety locks.
        """
        self.features: List[BehaviouralFeatureVector] = []
        self.state_lock = threading.Lock()

    def build_features(self, idle_timeout_seconds: float = 60.0) -> Tuple[int, Dict[str, Any]]:
        """
        Retrieves reconstructed flows and raw packets from their respective services,
        runs the FeatureBuilder pipeline, stores the generated vectors, and returns stats.
        """
        flow_service = FlowEngineService()
        packet_service = PacketParserService()

        flows = flow_service.get_all_flows()
        packets = packet_service.get_all_packets()

        # Build behavioural feature vectors
        new_features = FeatureBuilder.build_feature_vectors(
            flows=flows,
            packets=packets,
            idle_timeout_seconds=idle_timeout_seconds
        )

        with self.state_lock:
            self.features = new_features

        total_features = len(new_features)
        stats = FeatureStatisticsCalculator.calculate_statistics(new_features)

        summary_statistics = {
            "total_features": total_features,
            "average_flow_duration_seconds": stats["average_flow_duration"],
            "protocol_distribution": stats["protocol_distribution"],
            "top_ports_count": len(stats["top_ports"]),
            "top_hosts_count": len(stats["top_hosts"])
        }

        return total_features, summary_statistics

    def get_all_features(self) -> List[BehaviouralFeatureVector]:
        """
        Returns all stored feature vectors.
        """
        with self.state_lock:
            return list(self.features)

    def get_statistics(self) -> Dict[str, Any]:
        """
        Computes analytical statistics over all extracted feature vectors.
        """
        with self.state_lock:
            snapshot = list(self.features)
        return FeatureStatisticsCalculator.calculate_statistics(snapshot)

    def clear_features(self):
        """
        Flushes the stored feature vectors.
        """
        with self.state_lock:
            self.features.clear()
