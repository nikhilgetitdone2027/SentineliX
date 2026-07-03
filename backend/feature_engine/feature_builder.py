# -*- coding: utf-8 -*-
"""
Builder module for aggregating network flows and packets into feature vector collections.
"""

from typing import List, Dict, Tuple
from datetime import datetime

from backend.packet_parser.models import ParsedPacket
from backend.flow_engine.flow import NetworkFlow
from backend.flow_engine.utils import get_canonical_endpoints, parse_iso_timestamp
from .models import BehaviouralFeatureVector
from .extractor import FeatureExtractor

def map_packets_to_flows(
    packets: List[ParsedPacket],
    flows: List[NetworkFlow],
    idle_timeout_seconds: float = 60.0
) -> Dict[str, List[ParsedPacket]]:
    """
    Chronologically associates raw parsed packets back to their respective reconstructed flows.
    This reconstructs the flow state mapping in O(N log N + M log M) where N=packets and M=flows.
    """
    # 1. Sort packets chronologically
    sorted_packets: List[Tuple[datetime, ParsedPacket]] = []
    for p in packets:
        try:
            ts = parse_iso_timestamp(p.timestamp)
            sorted_packets.append((ts, p))
        except Exception:
            pass
    sorted_packets.sort(key=lambda x: x[0])

    # 2. Group packets by bidirectional 5-tuple canonical key
    grouped_packets: Dict[tuple, List[Tuple[datetime, ParsedPacket]]] = {}
    for ts, p in sorted_packets:
        proto = p.protocol.upper()
        if proto in ["HTTP", "TLS", "HTTPS", "HTTP/1.1"]:
            grouping_proto = "TCP"
        elif proto in ["DNS"]:
            grouping_proto = "UDP"
        else:
            grouping_proto = proto
        
        ep_a, ep_b = get_canonical_endpoints(p.src_ip, p.src_port, p.dst_ip, p.dst_port)
        key = (ep_a, ep_b, grouping_proto)
        if key not in grouped_packets:
            grouped_packets[key] = []
        grouped_packets[key].append((ts, p))

    # 3. Group and sort flows by the same canonical key
    flows_by_key: Dict[tuple, List[NetworkFlow]] = {}
    for f in flows:
        proto = f.protocol.upper()
        if proto in ["HTTP", "TLS", "HTTPS", "HTTP/1.1"]:
            grouping_proto = "TCP"
        elif proto in ["DNS"]:
            grouping_proto = "UDP"
        else:
            grouping_proto = proto
            
        ep_a, ep_b = get_canonical_endpoints(f.src_ip, f.src_port, f.dst_ip, f.dst_port)
        key = (ep_a, ep_b, grouping_proto)
        if key not in flows_by_key:
            flows_by_key[key] = []
        flows_by_key[key].append(f)

    # Sort the flows chronologically by start_time to align with packets
    for key in flows_by_key:
        flows_by_key[key].sort(key=lambda x: x.start_time)

    # 4. Map packet items to their correct flow ID chronologically
    flow_id_to_packets: Dict[str, List[ParsedPacket]] = {f.flow_id: [] for f in flows}
    
    for key, pkts in grouped_packets.items():
        fls = flows_by_key.get(key, [])
        if not fls:
            continue
        
        flow_idx = 0
        for ts, p in pkts:
            # Advance to next flow if packet timestamp matches or exceeds next flow start_time
            while flow_idx < len(fls) - 1:
                next_flow = fls[flow_idx + 1]
                if ts >= next_flow.start_time:
                    flow_idx += 1
                else:
                    break
            
            current_flow = fls[flow_idx]
            flow_id_to_packets[current_flow.flow_id].append(p)

    return flow_id_to_packets


class FeatureBuilder:
    """
    Builder class translating collections of flows and packets into high-level behavioral feature vectors.
    """
    @staticmethod
    def build_feature_vectors(
        flows: List[NetworkFlow],
        packets: List[ParsedPacket],
        idle_timeout_seconds: float = 60.0
    ) -> List[BehaviouralFeatureVector]:
        """
        Processes a set of reconstructed flows and maps co-occurring telemetry to build O(n) feature vectors.
        """
        if not flows:
            return []

        # 1. Map packets to their respective flow_id
        flow_packets_map = map_packets_to_flows(
            packets=packets,
            flows=flows,
            idle_timeout_seconds=idle_timeout_seconds
        )

        # 2. Compute co-occurring connection frequencies based on IP endpoints
        # Canonical IP endpoint pairs -> count
        connection_frequencies: Dict[Tuple[str, str], int] = {}
        for f in flows:
            ip_a = f.src_ip or "0.0.0.0"
            ip_b = f.dst_ip or "0.0.0.0"
            ip_key = (min(ip_a, ip_b), max(ip_a, ip_b))
            connection_frequencies[ip_key] = connection_frequencies.get(ip_key, 0) + 1

        # 3. Extract feature vector for each flow
        feature_vectors: List[BehaviouralFeatureVector] = []
        for f in flows:
            # Retrieve associated packets
            associated_packets = flow_packets_map.get(f.flow_id, [])
            
            # Retrieve endpoint connection count
            ip_a = f.src_ip or "0.0.0.0"
            ip_b = f.dst_ip or "0.0.0.0"
            ip_key = (min(ip_a, ip_b), max(ip_a, ip_b))
            conn_count = connection_frequencies.get(ip_key, 1)

            # Build feature vector
            vector = FeatureExtractor.extract_features(
                flow=f,
                packets=associated_packets,
                connection_count=conn_count
            )
            feature_vectors.append(vector)

        return feature_vectors
