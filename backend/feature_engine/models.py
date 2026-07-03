# -*- coding: utf-8 -*-
"""
Data model definitions for behavioural feature vectors.
"""

from typing import Dict, Any, Optional
from pydantic import BaseModel, Field

class RiskFeatures(BaseModel):
    """
    Heuristic behavioural risk indicators useful for AI anomaly detection and rule engines.
    """
    large_upload: bool = Field(False, description="True if bytes sent exceed threshold (e.g., 1MB)")
    long_session: bool = Field(False, description="True if flow duration exceeds threshold (e.g., 5 minutes)")
    high_packet_rate: bool = Field(False, description="True if packets per second exceed threshold (e.g., 100 pps)")
    high_byte_rate: bool = Field(False, description="True if bytes per second exceed threshold (e.g., 50KB/s)")
    repeated_connections: bool = Field(False, description="True if connection frequency is high")
    external_ip: bool = Field(False, description="True if target IP is an external public IP")
    internal_ip: bool = Field(False, description="True if target IP is a private RFC1918 IP")
    common_port: bool = Field(False, description="True if destination port is a standard service port (e.g., 80, 443, 53)")
    rare_port: bool = Field(False, description="True if destination port is non-standard or highly unusual")
    encrypted_traffic: bool = Field(False, description="True if communication protocol or port indicates encryption (e.g., TLS, port 443)")


class BehaviouralFeatureVector(BaseModel):
    """
    Telemetry feature vector capturing behavioural patterns of a network flow.
    Designed for ingestion by ML classifiers or LLM threat detection modules.
    """
    flow_id: str = Field(..., description="Unique flow identifier mapped back to Flow Engine")
    duration: float = Field(..., description="Flow duration in seconds")
    packet_count: int = Field(..., description="Total packet count")
    bytes_sent: int = Field(..., description="Bytes transmitted in forward direction")
    bytes_received: int = Field(..., description="Bytes received in reverse direction")
    total_bytes: int = Field(..., description="Total bytes exchanged")
    avg_packet_size: float = Field(..., description="Average packet size in bytes")
    min_packet_size: int = Field(..., description="Minimum packet size in bytes")
    max_packet_size: int = Field(..., description="Maximum packet size in bytes")
    packets_per_second: float = Field(..., description="Packets per second (PPS)")
    bytes_per_second: float = Field(..., description="Bytes per second (BPS)")
    byte_ratio: float = Field(..., description="Percentage of bytes sent relative to total bytes")
    
    # Communication Tuple Characteristics
    protocol: str = Field(..., description="Grouped or high-level protocol")
    src_port: Optional[int] = Field(None, description="Source port")
    dst_port: Optional[int] = Field(None, description="Destination port")
    direction: str = Field(..., description="Flow direction (forward, reverse, bidirectional)")
    connection_count: int = Field(0, description="Co-occurring connection count for same endpoints")
    
    # Protocol Specifics: DNS
    dns_query_count: int = Field(0, description="Total DNS queries observed")
    dns_unique_domains: int = Field(0, description="Unique DNS domains requested")
    dns_avg_query_len: float = Field(0.0, description="Average length of DNS query strings")
    
    # Protocol Specifics: HTTP
    http_host: Optional[str] = Field(None, description="HTTP Host header")
    http_method: Optional[str] = Field(None, description="HTTP Method")
    http_uri_len: Optional[int] = Field(None, description="HTTP request URI length")
    
    # Protocol Specifics: TLS
    tls_sni: Optional[str] = Field(None, description="TLS SNI hostname")
    tls_version: Optional[str] = Field(None, description="TLS handshake version")
    
    # TCP Specifics (Flags counts)
    syn_count: int = Field(0, description="SYN flag count")
    ack_count: int = Field(0, description="ACK flag count")
    fin_count: int = Field(0, description="FIN flag count")
    rst_count: int = Field(0, description="RST flag count")
    
    # Threat & Behaviour Heuristics
    risk_features: RiskFeatures = Field(default_factory=RiskFeatures, description="Risk scoring indicators")

    def to_dict(self) -> Dict[str, Any]:
        """
        Export feature vector to dictionary.
        """
        return self.model_dump()
