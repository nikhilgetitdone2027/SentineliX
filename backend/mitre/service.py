# -*- coding: utf-8 -*-
"""
Coordinating Service layer managing state, caching, and statistic aggregation for MITRE ATT&CK mapping.
"""

import threading
from typing import List, Dict, Any, Optional
from .mapper import MitreMapper, MITRE_KNOWLEDGE_BASE
from .schemas import MitreMapping
from backend.correlation_engine.service import CorrelationService

class MitreService:
    """
    Singleton service managing MITRE ATT&CK mapping processes and statistics.
    """
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if not cls._instance:
                cls._instance = super(MitreService, cls).__new__(cls, *args, **kwargs)
                cls._instance._init_service()
            return cls._instance

    def _init_service(self):
        """
        Initializes the service locks and references.
        """
        self.state_lock = threading.Lock()
        self.correlation_service = CorrelationService()

    def map_incident_by_id(self, incident_id: str) -> List[MitreMapping]:
        """
        Finds a correlated incident by ID and maps it to MITRE ATT&CK techniques.
        """
        incidents = self.correlation_service.get_incidents()
        target_incident = None
        for inc in incidents:
            if inc.incident_id == incident_id:
                target_incident = inc
                break

        if not target_incident:
            # If not found in dynamic correlation, try to search the pre-seeded static list if needed
            return []

        return MitreMapper.map_incident(target_incident)

    def map_all_incidents(self) -> Dict[str, List[MitreMapping]]:
        """
        Maps all currently correlated incidents to MITRE ATT&CK techniques.
        """
        incidents = self.correlation_service.get_incidents()
        return MitreMapper.map_all(incidents)

    def get_statistics(self) -> Dict[str, Any]:
        """
        Aggregates statistical metrics across all mapped tactics and techniques.
        """
        incidents = self.correlation_service.get_incidents()
        mapped_results = MitreMapper.map_all(incidents)

        tactic_dist = {}
        technique_dist = {}
        total_confidence = 0.0
        mapping_count = 0

        for inc_id, mappings in mapped_results.items():
            for mapping in mappings:
                # Track tactic count
                tactic_dist[mapping.tactic] = tactic_dist.get(mapping.tactic, 0) + 1
                
                # Track technique count
                technique_dist[mapping.technique] = technique_dist.get(mapping.technique, 0) + 1
                
                total_confidence += mapping.confidence
                mapping_count += 1

        total_mapped_incidents = len(mapped_results)
        avg_confidence = round(total_confidence / mapping_count, 2) if mapping_count > 0 else 0.0

        # Find the most common tactic
        top_tactic = None
        if tactic_dist:
            top_tactic = max(tactic_dist, key=tactic_dist.get)

        return {
            "total_mapped_incidents": total_mapped_incidents,
            "tactic_distribution": tactic_dist,
            "technique_distribution": technique_dist,
            "average_confidence": avg_confidence,
            "top_tactic": top_tactic
        }
