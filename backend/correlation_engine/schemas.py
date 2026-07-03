# -*- coding: utf-8 -*-
"""
Pydantic schemas for Threat Correlation Engine request and response validation.
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

class TimelineEvent(BaseModel):
    """
    Represents an event in an incident timeline.
    """
    timestamp: str = Field(..., description="ISO 8601 timestamp of the event")
    message: str = Field(..., description="Human-readable event message")
    flow_id: str = Field(..., description="Associated flow identifier")
    src_ip: str = Field(..., description="Source IP address")
    dst_ip: str = Field(..., description="Destination IP address")
    protocol: str = Field(..., description="IP network protocol")
    dst_port: Optional[int] = Field(None, description="Destination port")
    details: str = Field(..., description="Dynamic key performance indicators or event details")


class Incident(BaseModel):
    """
    Model representing a correlated security incident.
    """
    incident_id: str = Field(..., description="Unique correlated incident identifier")
    incident_type: str = Field(..., description="Classification of the security threat")
    related_flow_ids: List[str] = Field(..., description="List of contributing network flow IDs")
    timeline: List[TimelineEvent] = Field(..., description="Chronological timeline of suspicious activities")
    severity: str = Field(..., description="Severity rating (LOW, MEDIUM, HIGH, CRITICAL)")
    confidence: float = Field(..., description="Correlation confidence percentage [0, 100]")
    risk_score: float = Field(..., description="Unified risk score reflecting combined threat [0, 100]")
    attack_summary: str = Field(..., description="Contextual narrative summarizing the malicious activity")
    src_ip: Optional[str] = Field(None, description="Inferred source IP of the attacker")
    dst_ip: Optional[str] = Field(None, description="Inferred destination IP or target of the attack")


class AnalyzeResponse(BaseModel):
    """
    Response schema for correlation analysis.
    """
    success: bool = Field(..., description="Whether correlation analysis succeeded")
    total_incidents: int = Field(..., description="Number of correlated security incidents identified")
    incidents: List[Incident] = Field(..., description="Identified security incidents")


class StatisticsResponse(BaseModel):
    """
    Response schema for threat correlation engine statistics.
    """
    total_incidents: int = Field(..., description="Total correlated incidents")
    severity_distribution: Dict[str, int] = Field(..., description="Count of incidents per severity level")
    type_distribution: Dict[str, int] = Field(..., description="Count of incidents per threat type")
    average_risk_score: float = Field(..., description="Average risk score across all incidents")
    total_correlated_flows: int = Field(..., description="Total count of unique flows associated with incidents")
