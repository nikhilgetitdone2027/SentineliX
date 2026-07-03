# -*- coding: utf-8 -*-
"""
Schemas module containing Pydantic models for API request/response validation.
"""

from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any

class PacketSchema(BaseModel):
    """
    Schema for a single parsed network packet.
    """
    timestamp: str = Field(..., description="ISO 8601 formatted timestamp of the packet")
    src_mac: Optional[str] = Field(None, description="Source physical MAC address")
    dst_mac: Optional[str] = Field(None, description="Destination physical MAC address")
    src_ip: Optional[str] = Field(None, description="Source IP address")
    dst_ip: Optional[str] = Field(None, description="Destination IP address")
    src_port: Optional[int] = Field(None, description="Source port number")
    dst_port: Optional[int] = Field(None, description="Destination port number")
    protocol: str = Field(..., description="Transport or application protocol (e.g. TCP, UDP, DNS, TLS)")
    packet_len: int = Field(..., description="Total length of packet in bytes")
    tcp_flags: Optional[str] = Field(None, description="TCP header flags representation (e.g. S, A, F)")
    ttl: Optional[int] = Field(None, description="IPv4 Time-To-Live")
    dns_query: Optional[str] = Field(None, description="Extracted DNS domain query")
    http_host: Optional[str] = Field(None, description="Extracted HTTP host header")
    http_method: Optional[str] = Field(None, description="Extracted HTTP request method")
    tls_sni: Optional[str] = Field(None, description="Extracted TLS Server Name Indication (SNI)")

    class Config:
        orm_mode = True
        schema_extra = {
            "example": {
                "timestamp": "2026-07-03T08:12:59.601Z",
                "src_mac": "00:0c:29:3e:fa:11",
                "dst_mac": "00:0c:29:4a:bc:22",
                "src_ip": "10.0.60.100",
                "dst_ip": "185.220.101.43",
                "src_port": 55021,
                "dst_port": 443,
                "protocol": "TLS",
                "packet_len": 1460,
                "tcp_flags": "PA",
                "ttl": 64,
                "dns_query": None,
                "http_host": None,
                "http_method": None,
                "tls_sni": "secure-relay-onion.net"
            }
        }

class UploadResponse(BaseModel):
    """
    Response schema returned after successfully uploading and parsing a PCAP file.
    """
    success: bool = Field(True, description="Indicates whether the upload and parse was successful")
    filename: str = Field(..., description="Name of the uploaded PCAP file")
    total_packets: int = Field(..., description="Total count of successfully parsed packets")
    protocol_distribution: Dict[str, int] = Field(..., description="Distribution of protocols in the PCAP")
    basic_statistics: Dict[str, Any] = Field(..., description="Aggregated statistics (e.g. total bytes, duration)")

class IPStat(BaseModel):
    """
    Representing top IP occurrences.
    """
    ip: str
    count: int

class StatisticsResponse(BaseModel):
    """
    Response schema returning comprehensive parsing telemetry and analytics.
    """
    total_packets: int = Field(..., description="Total count of stored packets")
    tcp_packets: int = Field(..., description="Total count of TCP packets")
    udp_packets: int = Field(..., description="Total count of UDP packets")
    icmp_packets: int = Field(..., description="Total count of ICMP packets")
    dns_packets: int = Field(..., description="Total count of DNS packets")
    http_packets: int = Field(..., description="Total count of HTTP packets")
    top_sources: List[IPStat] = Field(..., description="Top source IP addresses by packet count")
    top_destinations: List[IPStat] = Field(..., description="Top destination IP addresses by packet count")
