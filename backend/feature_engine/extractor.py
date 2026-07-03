# -*- coding: utf-8 -*-
"""
Extractor module for transforming a single NetworkFlow and its packets into a BehaviouralFeatureVector.
"""

import ipaddress
from typing import List, Optional, Set
from backend.packet_parser.models import ParsedPacket
from backend.flow_engine.flow import NetworkFlow
from .models import BehaviouralFeatureVector, RiskFeatures

COMMON_PORTS = {
    21, 22, 23, 25, 53, 80, 110, 123, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080, 8443
}

def is_private_ip(ip_str: Optional[str]) -> bool:
    """
    Checks if an IP address is a private (RFC1918, loopback, link-local) address.
    """
    if not ip_str:
        return True
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private
    except ValueError:
        # Fallback for non-standard or malformed IPs
        if ip_str.startswith(("10.", "192.168.", "127.")):
            return True
        if ip_str.startswith("172."):
            try:
                parts = ip_str.split(".")
                second_octet = int(parts[1])
                return 16 <= second_octet <= 31
            except Exception:
                pass
        return False

class FeatureExtractor:
    """
    Extracts high-fidelity behavioural feature vectors from reconstructed flows and associated raw packets.
    """
    @staticmethod
    def extract_features(
        flow: NetworkFlow,
        packets: List[ParsedPacket],
        connection_count: int = 1
    ) -> BehaviouralFeatureVector:
        """
        Extracts a detailed BehaviouralFeatureVector for a single reconstructed flow.
        """
        duration = flow.calculated_duration
        packet_count = flow.packet_count
        bytes_sent = flow.bytes_sent
        bytes_received = flow.bytes_received
        total_bytes = flow.total_bytes
        
        # Calculates Rates
        packets_per_second = round(packet_count / duration, 4) if duration > 0 else float(packet_count)
        bytes_per_second = round(total_bytes / duration, 4) if duration > 0 else float(total_bytes)
        byte_ratio = round((bytes_sent / total_bytes * 100), 2) if total_bytes > 0 else 0.0

        # TCP Flag Counts (derived from associated packets)
        syn_count = 0
        ack_count = 0
        fin_count = 0
        rst_count = 0
        
        for p in packets:
            flags = p.tcp_flags or ""
            upper_flags = flags.upper()
            if "S" in upper_flags:
                syn_count += 1
            if "A" in upper_flags:
                ack_count += 1
            if "F" in upper_flags:
                fin_count += 1
            if "R" in upper_flags:
                rst_count += 1

        # DNS Metrics
        dns_queries = list(flow.dns_queries_seen)
        dns_query_count = len(dns_queries)
        dns_unique_domains = len(set(dns_queries))
        dns_avg_query_len = (
            round(sum(len(q) for q in dns_queries) / dns_query_count, 2)
            if dns_query_count > 0
            else 0.0
        )

        # HTTP Metrics
        http_host = next(iter(flow.http_hosts_seen)) if flow.http_hosts_seen else None
        http_method = next(iter(flow.http_methods_seen)) if flow.http_methods_seen else None
        
        # Take the length of the first HTTP URI if available
        http_uri_len = None
        if flow.http_uris_seen:
            first_uri = next(iter(flow.http_uris_seen))
            http_uri_len = len(first_uri) if first_uri else 0

        # TLS Metrics
        tls_sni = next(iter(flow.tls_snis_seen)) if flow.tls_snis_seen else None
        tls_version = "TLSv1.3" if flow.protocol.upper() in ["TLS", "HTTPS"] else None

        # --- Threat & Behaviour Heuristics (Risk Features) ---
        # 1. Large Upload: sent bytes > 1MB
        large_upload = bytes_sent > 1_000_000
        
        # 2. Long Session: duration > 5 minutes (300 seconds)
        long_session = duration > 300.0
        
        # 3. High Packet Rate: PPS > 100
        high_packet_rate = packets_per_second > 100.0
        
        # 4. High Byte Rate: BPS > 50KB/s (50,000 bytes/sec)
        high_byte_rate = bytes_per_second > 50_000.0
        
        # 5. Repeated Connections: connection count > 5
        repeated_connections = connection_count > 5
        
        # 6. Public/Private IP Categorization
        src_private = is_private_ip(flow.src_ip)
        dst_private = is_private_ip(flow.dst_ip)
        
        # External IP: True if either is a public IP
        external_ip = (not src_private) or (not dst_private)
        # Internal IP: True if both are private IPs
        internal_ip = src_private and dst_private
        
        # 7. Common/Rare Port Heuristics
        dst_p = flow.dst_port
        common_port = False
        rare_port = False
        
        if dst_p is not None:
            if dst_p in COMMON_PORTS:
                common_port = True
            else:
                rare_port = True

        # 8. Encrypted Traffic Detection
        encrypted_traffic = (
            flow.protocol.upper() in ["TLS", "HTTPS"]
            or dst_p in [443, 8443, 993, 995]
            or flow.src_port in [443, 8443, 993, 995]
        )

        risk_features = RiskFeatures(
            large_upload=large_upload,
            long_session=long_session,
            high_packet_rate=high_packet_rate,
            high_byte_rate=high_byte_rate,
            repeated_connections=repeated_connections,
            external_ip=external_ip,
            internal_ip=internal_ip,
            common_port=common_port,
            rare_port=rare_port,
            encrypted_traffic=encrypted_traffic
        )

        return BehaviouralFeatureVector(
            flow_id=flow.flow_id,
            duration=duration,
            packet_count=packet_count,
            bytes_sent=bytes_sent,
            bytes_received=bytes_received,
            total_bytes=total_bytes,
            avg_packet_size=flow.avg_packet_size,
            min_packet_size=flow.min_packet_size or 0,
            max_packet_size=flow.max_packet_size or 0,
            packets_per_second=packets_per_second,
            bytes_per_second=bytes_per_second,
            byte_ratio=byte_ratio,
            protocol=flow.protocol,
            src_port=flow.src_port,
            dst_port=flow.dst_port,
            direction=flow.flow_direction,
            connection_count=connection_count,
            dns_query_count=dns_query_count,
            dns_unique_domains=dns_unique_domains,
            dns_avg_query_len=dns_avg_query_len,
            http_host=http_host,
            http_method=http_method,
            http_uri_len=http_uri_len,
            tls_sni=tls_sni,
            tls_version=tls_version,
            syn_count=syn_count,
            ack_count=ack_count,
            fin_count=fin_count,
            rst_count=rst_count,
            risk_features=risk_features
        )
