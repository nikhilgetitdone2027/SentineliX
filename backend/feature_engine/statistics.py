# -*- coding: utf-8 -*-
"""
Statistics module for computing aggregations and distributions over behavioral feature vectors.
"""

from typing import List, Dict, Any
from collections import Counter
from .models import BehaviouralFeatureVector

class FeatureStatisticsCalculator:
    """
    Calculator of summary analytical metrics over extracted network flow behavioural feature vectors.
    """
    @staticmethod
    def calculate_statistics(features: List[BehaviouralFeatureVector]) -> Dict[str, Any]:
        """
        Computes aggregates (averages, distributions, ranking) over all stored feature vectors.
        """
        if not features:
            return {
                "total_features": 0,
                "average_flow_duration": 0.0,
                "protocol_distribution": {},
                "top_ports": [],
                "top_hosts": [],
                "average_upload_bytes": 0.0,
                "average_download_bytes": 0.0
            }

        total_features = len(features)
        
        # 1. Average Flow Duration
        total_duration = sum(f.duration for f in features)
        average_flow_duration = round(total_duration / total_features, 4)

        # 2. Protocol Distribution
        protocol_counts: Dict[str, int] = {}
        for f in features:
            proto = f.protocol.upper()
            protocol_counts[proto] = protocol_counts.get(proto, 0) + 1

        # 3. Top Destination/Service Ports
        port_counts = Counter()
        for f in features:
            if f.dst_port is not None:
                port_counts[f.dst_port] += 1
            elif f.src_port is not None:
                # Fallback to source port if dst_port is None and src_port is active
                port_counts[f.src_port] += 1

        top_ports = [
            {"port": port, "count": count}
            for port, count in port_counts.most_common(10)
        ]

        # 4. Top Hosts (aggregating HTTP Hosts and TLS SNIs seen across flows)
        host_counts = Counter()
        for f in features:
            if f.tls_sni:
                host_counts[f.tls_sni] += 1
            elif f.http_host:
                host_counts[f.http_host] += 1

        top_hosts = [
            {"host": host, "count": count}
            for host, count in host_counts.most_common(10)
        ]

        # 5. Average Upload and Download Bytes
        total_upload = sum(f.bytes_sent for f in features)
        total_download = sum(f.bytes_received for f in features)
        
        average_upload_bytes = round(total_upload / total_features, 2)
        average_download_bytes = round(total_download / total_features, 2)

        return {
            "total_features": total_features,
            "average_flow_duration": average_flow_duration,
            "protocol_distribution": protocol_counts,
            "top_ports": top_ports,
            "top_hosts": top_hosts,
            "average_upload_bytes": average_upload_bytes,
            "average_download_bytes": average_download_bytes
        }
