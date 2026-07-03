# -*- coding: utf-8 -*-
"""
Pydantic schemas for MITRE ATT&CK Mapping Engine request and response validation.
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

class MitreMapping(BaseModel):
    """
    Detailed MITRE ATT&CK mapping entry for a specific incident.
    """
    tactic: str = Field(..., description="MITRE Tactic category (e.g. EXECUTION, CREDENTIAL_ACCESS)")
    technique: str = Field(..., description="MITRE Technique name (e.g. PowerShell Interpreter)")
    confidence: float = Field(..., description="Mapping confidence score/percentage [0, 100]")
    mitre_id: str = Field(..., alias="mitreId", description="MITRE ID of the technique (e.g. T1059.001)")
    description: str = Field(..., description="Detailed description of the technique")
    recommended_mitigation: str = Field(..., alias="recommendedMitigation", description="Recommended mitigation action")

    class Config:
        populate_by_name = True


class MapRequest(BaseModel):
    """
    Optional request payload to map specific incidents.
    """
    incident_id: Optional[str] = Field(None, description="Optional single incident ID to map")


class MapResponse(BaseModel):
    """
    Response containing all successfully mapped incidents and their techniques.
    """
    success: bool = Field(..., description="Success flag")
    mapped_incidents: Dict[str, List[MitreMapping]] = Field(..., alias="mappedIncidents", description="Mapping of incident IDs to their MITRE mappings")

    class Config:
        populate_by_name = True


class MitreStatisticsResponse(BaseModel):
    """
    Response schema for MITRE engine statistics.
    """
    total_mapped_incidents: int = Field(..., alias="totalMappedIncidents", description="Total number of incidents mapped to MITRE techniques")
    tactic_distribution: Dict[str, int] = Field(..., alias="tacticDistribution", description="Count of occurrences per MITRE tactic")
    technique_distribution: Dict[str, int] = Field(..., alias="techniqueDistribution", description="Count of occurrences per MITRE technique")
    average_confidence: float = Field(..., alias="averageConfidence", description="Average mapping confidence score")
    top_tactic: Optional[str] = Field(None, alias="topTactic", description="The tactic with the highest occurrence count")

    class Config:
        populate_by_name = True
