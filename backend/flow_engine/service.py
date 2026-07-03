# -*- coding: utf-8 -*-
"""
Service layer managing in-memory reconstructed network flows and computing analytics.
"""

import threading
from typing import List, Dict, Any, Tuple

from backend.packet_parser.service import PacketParserService
from .flow import NetworkFlow
from .builder import FlowBuilder

class FlowEngineService:
    """
    Singleton service managing the state of reconstructed network flows.
    """
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if not cls._instance:
                cls._instance = super(FlowEngineService, cls).__new__(cls, *args, **kwargs)
                cls._instance._init_service()
            return cls._instance

    def _init_service(self):
        """
        Initializes in-memory flow storage and thread lock.
        """
        self.flows: List[NetworkFlow] = []
        self.state_lock = threading.Lock()
        self.idle_timeout_seconds = 60.0

    def build_flows(self, idle_timeout_seconds: float = 60.0) -> Tuple[int, Dict[str, Any]]:
        """
        Reconstructs network flows from all currently stored parsed packets in the PacketParserService.
        Stores the reconstructed flows in memory and returns flow count and summary stats.
        """
        self.idle_timeout_seconds = idle_timeout_seconds
        
        # Fetch packets from the Packet Parser Service
        packet_service = PacketParserService()
        packets = packet_service.get_all_packets()
        
        # Build bidirectional flows using the builder
        new_flows = FlowBuilder.build_flows(packets, idle_timeout_seconds=idle_timeout_seconds)
        
        with self.state_lock:
            self.flows = new_flows
            
        total_flows = len(new_flows)
        total_bytes = sum(f.total_bytes for f in new_flows)
        avg_duration = (sum(f.calculated_duration for f in new_flows) / total_flows) if total_flows > 0 else 0.0
        
        summary_stats = {
            "total_flows": total_flows,
            "total_bytes_exchanged": total_bytes,
            "average_duration_seconds": round(avg_duration, 2),
            "tcp_flows_count": sum(1 for f in new_flows if f.protocol.upper() in ["TCP", "HTTP", "TLS"]),
            "udp_flows_count": sum(1 for f in new_flows if f.protocol.upper() in ["UDP", "DNS"]),
            "icmp_flows_count": sum(1 for f in new_flows if f.protocol.upper() == "ICMP")
        }
        
        return total_flows, summary_stats

    def get_all_flows(self) -> List[NetworkFlow]:
        """
        Returns all currently stored flows.
        """
        with self.state_lock:
            return list(self.flows)

    def get_statistics(self) -> Dict[str, Any]:
        """
        Calculates comprehensive analytical statistics for the reconstructed flows,
        including protocol distributions, top talkers, largest flows, and longest flows.
        """
        with self.state_lock:
            snapshot = list(self.flows)
            
        total_flows = len(snapshot)
        total_duration = sum(f.calculated_duration for f in snapshot)
        avg_duration = (total_duration / total_flows) if total_flows > 0 else 0.0
        
        # 1. Protocol Distribution
        protocol_counts: Dict[str, int] = {}
        for f in snapshot:
            proto = f.protocol.upper()
            protocol_counts[proto] = protocol_counts.get(proto, 0) + 1
            
        # 2. Top Talkers (individual IPs aggregated by total traffic in any flow they were part of)
        ip_bytes: Dict[str, int] = {}
        ip_packets: Dict[str, int] = {}
        for f in snapshot:
            # Source IP
            src = f.src_ip
            ip_bytes[src] = ip_bytes.get(src, 0) + f.total_bytes
            ip_packets[src] = ip_packets.get(src, 0) + f.packet_count
            
            # Destination IP
            dst = f.dst_ip
            ip_bytes[dst] = ip_bytes.get(dst, 0) + f.total_bytes
            ip_packets[dst] = ip_packets.get(dst, 0) + f.packet_count
            
        # Sort talkers descending by bytes
        sorted_talkers = sorted(ip_bytes.items(), key=lambda x: x[1], reverse=True)[:10]
        top_talkers = [
            {
                "ip": ip,
                "total_bytes": total_b,
                "packet_count": ip_packets[ip]
            }
            for ip, total_b in sorted_talkers
        ]
        
        # 3. Largest Flows (sorted descending by Total Bytes)
        sorted_by_size = sorted(snapshot, key=lambda f: f.total_bytes, reverse=True)[:10]
        largest_flows = [f.to_dict() for f in sorted_by_size]
        
        # 4. Longest Flows (sorted descending by Duration)
        sorted_by_duration = sorted(snapshot, key=lambda f: f.calculated_duration, reverse=True)[:10]
        longest_flows = [f.to_dict() for f in sorted_by_duration]
        
        return {
            "total_flows": total_flows,
            "average_duration": round(avg_duration, 4),
            "protocol_distribution": protocol_counts,
            "top_talkers": top_talkers,
            "largest_flows": largest_flows,
            "longest_flows": longest_flows
        }

    def clear_flows(self):
        """
        Clears stored flows from the service.
        """
        with self.state_lock:
            self.flows.clear()
