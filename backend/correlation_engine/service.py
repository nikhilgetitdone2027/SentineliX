# -*- coding: utf-8 -*-
"""
Coordinating Service layer managing state, caching, and statistic aggregation for correlated incidents.
"""

import threading
from typing import List, Dict, Any, Tuple
from .correlator import ThreatCorrelator
from .schemas import Incident

class CorrelationService:
    """
    Singleton service managing the lifecycle and query interfaces of security incidents.
    """
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if not cls._instance:
                cls._instance = super(CorrelationService, cls).__new__(cls, *args, **kwargs)
                cls._instance._init_service()
            return cls._instance

    def _init_service(self):
        """
        Initializes thread lock and memory cache for incidents.
        """
        self.state_lock = threading.Lock()
        self.incidents: List[Incident] = []

    def analyze_incidents(self) -> List[Incident]:
        """
        Triggers ThreatCorrelator to scan active network flows and updates the cache.
        """
        new_incidents = ThreatCorrelator.correlate_incidents()
        with self.state_lock:
            self.incidents = new_incidents
        return new_incidents

    def get_incidents(self) -> List[Incident]:
        """
        Retrieves cached security incidents. Re-runs analysis automatically if cache is empty.
        """
        with self.state_lock:
            if self.incidents:
                return list(self.incidents)
        
        # Auto-analyze if empty to ensure initial data populates seamlessly
        return self.analyze_incidents()

    def get_statistics(self) -> Dict[str, Any]:
        """
        Aggregates statistical metrics across all identified incidents.
        """
        with self.state_lock:
            snapshot = list(self.incidents)

        # Initialize structure
        severity_dist = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        type_dist: Dict[str, int] = {}
        unique_flows = set()
        total_risk = 0.0

        for inc in snapshot:
            severity_dist[inc.severity.upper()] = severity_dist.get(inc.severity.upper(), 0) + 1
            type_dist[inc.incident_type] = type_dist.get(inc.incident_type, 0) + 1
            total_risk += inc.risk_score
            for flow_id in inc.related_flow_ids:
                unique_flows.add(flow_id)

        total_incidents = len(snapshot)
        avg_risk = round(total_risk / total_incidents, 2) if total_incidents > 0 else 0.0

        return {
            "total_incidents": total_incidents,
            "severity_distribution": severity_dist,
            "type_distribution": type_dist,
            "average_risk_score": avg_risk,
            "total_correlated_flows": len(unique_flows)
        }

    def clear_incidents(self):
        """
        Clears the cached incidents from memory.
        """
        with self.state_lock:
            self.incidents.clear()
