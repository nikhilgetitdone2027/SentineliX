# -*- coding: utf-8 -*-
"""
Schemas module containing Pydantic models for Flow Reconstruction Engine validation.
"""

from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any

class FlowSchema(BaseModel):
    """
    Schema for a single reconstructed bidirectional network flow.
    """
    flow_id: str = Field(..., description="Unique string identifier for the flow")
    src_ip: str = Field(..., description="Source IP address of the flow initiator")
    dst_ip: str = Field(..., description="Destination IP address of the flow initiator")
    src_port: Optional[int] = Field(None, description="Source port of the flow")
    dst_port: Optional[int] = Field(None, description="Destination port of the flow")
    protocol: str = Field(..., description="Transport or application protocol of the flow")
    start_time: str = Field(..., description="ISO 8601 timestamp of flow start")
    end_time: str = Field(..., description="ISO 8601 timestamp of flow end")
    duration: float = Field(..., description="Duration of the flow in seconds")
    packet_count: int = Field(..., description="Total packet count in both directions")
    forward_packet_count: int = Field(..., description="Packet count in the forward direction")
    reverse_packet_count: int = Field(..., description="Packet count in the reverse direction")
    total_bytes: int = Field(..., description="Total bytes exchanged in both directions")
    bytes_sent: int = Field(..., description="Total bytes sent (forward direction)")
    bytes_received: int = Field(..., description="Total bytes received (reverse direction)")
    average_packet_size: float = Field(..., description="Average packet size in bytes")
    minimum_packet_size: int = Field(..., description="Minimum packet size in bytes")
    maximum_packet_size: int = Field(..., description="Maximum packet size in bytes")
    average_inter_arrival_time: float = Field(..., description="Average inter-arrival time in seconds")
    flow_direction: str = Field(..., description="Directionality of the flow (forward, reverse, bidirectional)")
    tcp_flags_summary: str = Field(..., description="Concatenated unique TCP flags seen in the flow")
    
    # Protocol Metadata
    dns_queries: List[str] = Field(default_factory=list, description="Extracted DNS query names")
    dns_responses: List[str] = Field(default_factory=list, description="Extracted DNS responses")
    http_host: Optional[str] = Field(None, description="Extracted HTTP Host header")
    http_method: Optional[str] = Field(None, description="Extracted HTTP method")
    http_uri: Optional[str] = Field(None, description="Extracted HTTP Request URI")
    tls_sni: Optional[str] = Field(None, description="Extracted TLS SNI server name")

    class Config:
        from_attributes = True
        json_schema_extra = {
            "example": {
                "flow_id": "flow_8f3d12c1",
                "src_ip": "10.0.60.100",
                "dst_ip": "185.220.101.43",
                "src_port": 55021,
                "dst_port": 443,
                "protocol": "TLS",
                "start_time": "2026-07-03T08:12:59.601Z",
                "end_time": "2026-07-03T08:13:05.421Z",
                "duration": 5.82,
                "packet_count": 12,
                "forward_packet_count": 7,
                "reverse_packet_count": 5,
                "total_bytes": 4510,
                "bytes_sent": 1200,
                "bytes_received": 3310,
                "average_packet_size": 375.83,
                "minimum_packet_size": 54,
                "maximum_packet_size": 1460,
                "average_inter_arrival_time": 0.529,
                "flow_direction": "bidirectional",
                "tcp_flags_summary": "A, P, S",
                "dns_queries": [],
                "dns_responses": [],
                "http_host": None,
                "http_method": None,
                "http_uri": None,
                "tls_sni": "secure-relay-onion.net"
            }
        }

class FlowBuildResponse(BaseModel):
    """
    Response schema after building flows from parsed packets.
    """
    success: bool = Field(True, description="Indicates if flows were built successfully")
    total_flows: int = Field(..., description="Number of reconstructed flows")
    summary_statistics: Dict[str, Any] = Field(..., description="High-level metrics of the reconstructed flows")

class TalkerStat(BaseModel):
    """
    Statistics representing a top talker IP address.
    """
    ip: str = Field(..., description="IP address")
    total_bytes: int = Field(..., description="Total bytes sent and received by this IP")
    packet_count: int = Field(..., description="Total packet count for this IP")

class FlowStatisticsResponse(BaseModel):
    """
    Response schema containing reconstructed flow telemetry analytics.
    """
    total_flows: int = Field(..., description="Total count of reconstructed flows")
    average_duration: float = Field(..., description="Average duration of flows in seconds")
    protocol_distribution: Dict[str, int] = Field(..., description="Frequency of protocols among flows")
    top_talkers: List[TalkerStat] = Field(..., description="Top talkers IP addresses ranked by total bytes")
    largest_flows: List[FlowSchema] = Field(..., description="Largest flows in bytes")
    longest_flows: List[FlowSchema] = Field(..., description="Longest flows in duration")
