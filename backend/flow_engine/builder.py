# -*- coding: utf-8 -*-
"""
Builder module for reconstructing bidirectional flows from parsed packets.
"""

from typing import List, Dict
import threading

from backend.packet_parser.models import ParsedPacket
from .flow import NetworkFlow
from .utils import parse_iso_timestamp, get_canonical_endpoints, generate_flow_hash

class FlowBuilder:
    """
    Builder class that aggregates parsed packets into session-level bidirectional flows.
    """
    @staticmethod
    def build_flows(packets: List[ParsedPacket], idle_timeout_seconds: float = 60.0) -> List[NetworkFlow]:
        """
        Processes a sequence of packets, sorts them chronologically, and groups them
        into bidirectional communication flows using O(n) hash-map dictionary lookups.
        """
        if not packets:
            return []

        # Sort packets chronologically by timestamp for accurate timeout and IAT metrics
        sorted_packets = []
        for p in packets:
            try:
                ts = parse_iso_timestamp(p.timestamp)
                sorted_packets.append((ts, p))
            except Exception:
                pass
                
        sorted_packets.sort(key=lambda x: x[0])
        
        reconstructed_flows: List[NetworkFlow] = []
        
        # Maps canonical bidirectional key (ep_a, ep_b, grouping_protocol) to the active flow
        active_flows: Dict[tuple, NetworkFlow] = {}
        # Tracks how many times a 5-tuple has expired (suffix index to avoid flow ID collisions)
        flow_indices: Dict[tuple, int] = {}
        
        for ts, p in sorted_packets:
            proto = p.protocol.upper()
            
            # Group high-level application layers by their underlying transport protocol
            # to prevent splitting a single TCP connection/UDP dialogue into separate flows
            if proto in ["HTTP", "TLS", "HTTPS", "HTTP/1.1"]:
                grouping_proto = "TCP"
            elif proto in ["DNS"]:
                grouping_proto = "UDP"
            else:
                grouping_proto = proto
                
            # Get canonical endpoints (lexicographically sorted to achieve bidirectional matching)
            ep_a, ep_b = get_canonical_endpoints(p.src_ip, p.src_port, p.dst_ip, p.dst_port)
            key = (ep_a, ep_b, grouping_proto)
            
            flow = active_flows.get(key)
            
            if flow:
                # Check for idle timeout (inactivity) to see if we should split the flow
                time_diff = (ts - flow.end_time).total_seconds()
                if time_diff > idle_timeout_seconds:
                    # Flow has expired. Close previous and initiate a new flow.
                    flow_indices[key] = flow_indices.get(key, 0) + 1
                    flow_idx = flow_indices[key]
                    flow_id = generate_flow_hash(p.src_ip, p.src_port, p.dst_ip, p.dst_port, grouping_proto, flow_idx)
                    
                    new_flow = NetworkFlow(
                        flow_id=flow_id,
                        src_ip=p.src_ip or "0.0.0.0",
                        dst_ip=p.dst_ip or "0.0.0.0",
                        src_port=p.src_port,
                        dst_port=p.dst_port,
                        protocol=grouping_proto,
                        start_time=ts
                    )
                    
                    # Dynamically elevate protocol if high-layer protocol is present
                    if p.protocol.upper() in ["HTTP", "TLS", "DNS"]:
                        new_flow.protocol = p.protocol.upper()
                        
                    new_flow.add_packet(
                        timestamp=ts,
                        is_forward=True, # Initiated by this packet
                        length=p.packet_len,
                        tcp_flags=p.tcp_flags,
                        dns_query=p.dns_query,
                        http_host=p.http_host,
                        http_method=p.http_method,
                        tls_sni=p.tls_sni
                    )
                    
                    active_flows[key] = new_flow
                    reconstructed_flows.append(new_flow)
                else:
                    # Flow is active. Incorporate the packet.
                    # Determine direction: is_forward matches the initiator's endpoints
                    is_fwd = (p.src_ip == flow.src_ip and p.src_port == flow.src_port)
                    
                    # Elevate protocol to high-level application protocol if observed
                    if flow.protocol in ["TCP", "UDP", "UNKNOWN"] and p.protocol.upper() in ["HTTP", "TLS", "DNS"]:
                        flow.protocol = p.protocol.upper()
                        
                    flow.add_packet(
                        timestamp=ts,
                        is_forward=is_fwd,
                        length=p.packet_len,
                        tcp_flags=p.tcp_flags,
                        dns_query=p.dns_query,
                        http_host=p.http_host,
                        http_method=p.http_method,
                        tls_sni=p.tls_sni
                    )
            else:
                # Flow does not exist yet. Create the initial flow.
                flow_indices[key] = 0
                flow_id = generate_flow_hash(p.src_ip, p.src_port, p.dst_ip, p.dst_port, grouping_proto, 0)
                
                new_flow = NetworkFlow(
                    flow_id=flow_id,
                    src_ip=p.src_ip or "0.0.0.0",
                    dst_ip=p.dst_ip or "0.0.0.0",
                    src_port=p.src_port,
                    dst_port=p.dst_port,
                    protocol=grouping_proto,
                    start_time=ts
                )
                
                # Dynamically elevate protocol if high-layer protocol is present
                if p.protocol.upper() in ["HTTP", "TLS", "DNS"]:
                    new_flow.protocol = p.protocol.upper()
                    
                new_flow.add_packet(
                    timestamp=ts,
                    is_forward=True, # Initiated by this packet
                    length=p.packet_len,
                    tcp_flags=p.tcp_flags,
                    dns_query=p.dns_query,
                    http_host=p.http_host,
                    http_method=p.http_method,
                    tls_sni=p.tls_sni
                )
                
                active_flows[key] = new_flow
                reconstructed_flows.append(new_flow)
                
        return reconstructed_flows
