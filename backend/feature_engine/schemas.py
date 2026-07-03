# -*- coding: utf-8 -*-
"""
Pydantic schemas for Feature Extraction Engine request/response validation.
"""

from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field
from .models import BehaviouralFeatureVector

class FeatureBuildResponse(BaseModel):
    """
    Response schema returning metrics about the generated feature vectors.
    """
    success: bool = Field(True, description="Indicates if feature vectors were built successfully")
    total_features: int = Field(..., description="Number of extracted feature vectors")
    summary_statistics: Dict[str, Any] = Field(..., description="Overview of generated features")

class PortStat(BaseModel):
    """
    Occurrences statistic for top ports.
    """
    port: int = Field(..., description="TCP/UDP port number")
    count: int = Field(..., description="Number of flows targeted to or from this port")

class HostStat(BaseModel):
    """
    Occurrences statistic for top hosts (DNS query, HTTP Host, or TLS SNI).
    """
    host: str = Field(..., description="Host name, SNI or query name")
    count: int = Field(..., description="Number of occurrences of this host")

class FeatureStatisticsResponse(BaseModel):
    """
    Response schema containing analytical statistics aggregated over all behavioural feature vectors.
    """
    total_features: int = Field(..., description="Total count of feature vectors")
    average_flow_duration: float = Field(..., description="Average flow duration in seconds")
    protocol_distribution: Dict[str, int] = Field(..., description="Frequency of protocols among extracted features")
    top_ports: List[PortStat] = Field(..., description="Top targeted destination ports")
    top_hosts: List[HostStat] = Field(..., description="Top domain hosts queried or visited")
    average_upload_bytes: float = Field(..., description="Average bytes sent in forward direction")
    average_download_bytes: float = Field(..., description="Average bytes received in reverse direction")
