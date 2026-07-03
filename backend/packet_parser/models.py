# -*- coding: utf-8 -*-
"""
Models module for network packet records.
"""

from typing import Optional, Dict, Any

class ParsedPacket:
    """
    Domain model representing a fully parsed network packet.
    """
    def __init__(
        self,
        timestamp: str,
        src_mac: Optional[str] = None,
        dst_mac: Optional[str] = None,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        src_port: Optional[int] = None,
        dst_port: Optional[int] = None,
        protocol: str = "UNKNOWN",
        packet_len: int = 0,
        tcp_flags: Optional[str] = None,
        ttl: Optional[int] = None,
        dns_query: Optional[str] = None,
        http_host: Optional[str] = None,
        http_method: Optional[str] = None,
        tls_sni: Optional[str] = None,
    ):
        self.timestamp = timestamp
        self.src_mac = src_mac
        self.dst_mac = dst_mac
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.packet_len = packet_len
        self.tcp_flags = tcp_flags
        self.ttl = ttl
        self.dns_query = dns_query
        self.http_host = http_host
        self.http_method = http_method
        self.tls_sni = tls_sni

    def to_dict(self) -> Dict[str, Any]:
        """
        Converts the ParsedPacket model instance to a dictionary.
        """
        return {
            "timestamp": self.timestamp,
            "src_mac": self.src_mac,
            "dst_mac": self.dst_mac,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "packet_len": self.packet_len,
            "tcp_flags": self.tcp_flags,
            "ttl": self.ttl,
            "dns_query": self.dns_query,
            "http_host": self.http_host,
            "http_method": self.http_method,
            "tls_sni": self.tls_sni,
        }
