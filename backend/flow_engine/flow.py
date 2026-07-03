# -*- coding: utf-8 -*-
"""
Model representing a bidirectional network flow.
"""

from typing import List, Optional, Set
from datetime import datetime

class NetworkFlow:
    """
    Domain model representing a bidirectional network flow reconstructed from parsed packets.
    """
    def __init__(
        self,
        flow_id: str,
        src_ip: str,
        dst_ip: str,
        src_port: Optional[int],
        dst_port: Optional[int],
        protocol: str,
        start_time: datetime,
    ):
        self.flow_id = flow_id
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        
        # Flow state and stats
        self.start_time: datetime = start_time
        self.end_time: datetime = start_time
        self.duration: float = 0.0
        
        self.packet_count: int = 0
        self.forward_packets_count: int = 0
        self.reverse_packets_count: int = 0
        
        self.total_bytes: int = 0
        self.bytes_sent: int = 0
        self.bytes_received: int = 0
        
        self.min_packet_size: Optional[int] = None
        self.max_packet_size: Optional[int] = None
        
        # Inter-arrival times and statistics
        self.timestamps: List[datetime] = []
        self.packet_sizes: List[int] = []
        
        # TCP Flags
        self.tcp_flags_seen: Set[str] = set()
        
        # Protocol Metadata
        self.dns_queries_seen: Set[str] = set()
        self.dns_responses_seen: Set[str] = set()
        self.http_hosts_seen: Set[str] = set()
        self.http_methods_seen: Set[str] = set()
        self.http_uris_seen: Set[str] = set()
        self.tls_snis_seen: Set[str] = set()

    def add_packet(
        self,
        timestamp: datetime,
        is_forward: bool,
        length: int,
        tcp_flags: Optional[str] = None,
        dns_query: Optional[str] = None,
        http_host: Optional[str] = None,
        http_method: Optional[str] = None,
        tls_sni: Optional[str] = None
    ):
        """
        Incorporates packet details into the flow, updating statistics and metadata.
        """
        # Update start and end times
        if timestamp < self.start_time:
            self.start_time = timestamp
        if timestamp > self.end_time:
            self.end_time = timestamp
            
        self.timestamps.append(timestamp)
        self.packet_sizes.append(length)
        
        # Increment counts
        self.packet_count += 1
        if is_forward:
            self.forward_packets_count += 1
            self.bytes_sent += length
        else:
            self.reverse_packets_count += 1
            self.bytes_received += length
            
        self.total_bytes += length
        
        # Update min/max packet sizes
        if self.min_packet_size is None or length < self.min_packet_size:
            self.min_packet_size = length
        if self.max_packet_size is None or length > self.max_packet_size:
            self.max_packet_size = length
            
        # Update TCP Flags
        if tcp_flags:
            # Flags are typically characters, e.g., 'S', 'A', 'P'. Add each character.
            for char in tcp_flags:
                if char.strip() and char != ",":
                    self.tcp_flags_seen.add(char.upper())
                    
        # Update Protocol Metadata
        if dns_query:
            self.dns_queries_seen.add(dns_query)
        if http_host:
            self.http_hosts_seen.add(http_host)
        if http_method:
            self.http_methods_seen.add(http_method)
        if tls_sni:
            self.tls_snis_seen.add(tls_sni)

    @property
    def avg_packet_size(self) -> float:
        if self.packet_count == 0:
            return 0.0
        return round(self.total_bytes / self.packet_count, 2)

    @property
    def avg_inter_arrival_time(self) -> float:
        """
        Average inter-arrival time in seconds.
        """
        if len(self.timestamps) < 2:
            return 0.0
        sorted_ts = sorted(self.timestamps)
        intervals = [(sorted_ts[i] - sorted_ts[i-1]).total_seconds() for i in range(1, len(sorted_ts))]
        return round(sum(intervals) / len(intervals), 4)

    @property
    def calculated_duration(self) -> float:
        return round((self.end_time - self.start_time).total_seconds(), 4)

    @property
    def flow_direction(self) -> str:
        if self.forward_packets_count > 0 and self.reverse_packets_count > 0:
            return "bidirectional"
        elif self.forward_packets_count > 0:
            return "forward"
        else:
            return "reverse"

    @property
    def tcp_flags_summary(self) -> str:
        if not self.tcp_flags_seen:
            return ""
        return ", ".join(sorted(list(self.tcp_flags_seen)))

    def to_dict(self) -> dict:
        """
        Converts the flow object to a dictionary compliant with FlowSchema.
        """
        return {
            "flow_id": self.flow_id,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "start_time": self.start_time.isoformat() + "Z" if not self.start_time.isoformat().endswith("Z") else self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() + "Z" if not self.end_time.isoformat().endswith("Z") else self.end_time.isoformat(),
            "duration": self.calculated_duration,
            "packet_count": self.packet_count,
            "forward_packet_count": self.forward_packets_count,
            "reverse_packet_count": self.reverse_packets_count,
            "total_bytes": self.total_bytes,
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "average_packet_size": self.avg_packet_size,
            "minimum_packet_size": self.min_packet_size or 0,
            "maximum_packet_size": self.max_packet_size or 0,
            "average_inter_arrival_time": self.avg_inter_arrival_time,
            "flow_direction": self.flow_direction,
            "tcp_flags_summary": self.tcp_flags_summary,
            "dns_queries": sorted(list(self.dns_queries_seen)),
            "dns_responses": sorted(list(self.dns_responses_seen)),
            "http_host": next(iter(self.http_hosts_seen)) if self.http_hosts_seen else None,
            "http_method": next(iter(self.http_methods_seen)) if self.http_methods_seen else None,
            "http_uri": next(iter(self.http_uris_seen)) if self.http_uris_seen else None,
            "tls_sni": next(iter(self.tls_snis_seen)) if self.tls_snis_seen else None,
        }
