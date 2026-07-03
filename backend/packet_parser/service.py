# -*- coding: utf-8 -*-
"""
Service layer module managing the thread-safe, in-memory database of parsed packets
and computing analytics and distributions.
"""

from typing import List, Dict, Any, Tuple
from collections import Counter
import threading
from datetime import datetime

from .models import ParsedPacket
from .parser import PacketParser

class PacketParserService:
    """
    Service class managing state and logic for network packets telemetry.
    """
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if not cls._instance:
                cls._instance = super(PacketParserService, cls).__new__(cls, *args, **kwargs)
                cls._instance._init_service()
            return cls._instance

    def _init_service(self):
        """
        Initializes the stored memory lists.
        """
        self.packets: List[ParsedPacket] = []
        self.state_lock = threading.Lock()

    def add_packets_from_pcap(self, file_path: str) -> Tuple[int, Dict[str, int], Dict[str, Any]]:
        """
        Parses a PCAP file and appends results to memory.
        Returns:
            (total_new_packets, protocol_distribution, basic_statistics)
        """
        new_packets: List[ParsedPacket] = []
        protocols_count: Dict[str, int] = {}
        total_bytes = 0

        # Stream parse from file
        for parsed in PacketParser.parse_stream(file_path):
            new_packets.append(parsed)
            protocols_count[parsed.protocol] = protocols_count.get(parsed.protocol, 0) + 1
            total_bytes += parsed.packet_len

        # Append to main in-memory list
        with self.state_lock:
            self.packets.extend(new_packets)

        # Calculate basic metrics for this specific PCAP upload
        total_count = len(new_packets)
        avg_packet_size = (total_bytes / total_count) if total_count > 0 else 0

        duration_seconds = 0.0
        if total_count > 1:
            try:
                # Find start/end timestamps to measure duration
                parsed_times = []
                for p in new_packets:
                    # Remove trailing 'Z' and offset-related characters to normalize parsing
                    clean_ts = p.timestamp.replace("Z", "+00:00")
                    parsed_times.append(datetime.fromisoformat(clean_ts))
                
                parsed_times.sort()
                duration_seconds = (parsed_times[-1] - parsed_times[0]).total_seconds()
            except Exception:
                duration_seconds = 0.0

        basic_stats = {
            "total_bytes": total_bytes,
            "avg_packet_size": round(avg_packet_size, 2),
            "stream_duration_sec": round(duration_seconds, 2),
            "start_time": new_packets[0].timestamp if total_count > 0 else None,
            "end_time": new_packets[-1].timestamp if total_count > 0 else None
        }

        return total_count, protocols_count, basic_stats

    def get_all_packets(self) -> List[ParsedPacket]:
        """
        Returns all stored parsed packets in memory.
        """
        with self.state_lock:
            # Return copies to prevent downstream thread race conditions
            return list(self.packets)

    def clear_packets(self):
        """
        Flushes the stored packet buffers.
        """
        with self.state_lock:
            self.packets.clear()

    def get_statistics(self) -> Dict[str, Any]:
        """
        Aggregates packet telemetry statistics over the full stored history.
        """
        with self.state_lock:
            snapshot = list(self.packets)

        total_packets = len(snapshot)
        tcp_count = 0
        udp_count = 0
        icmp_count = 0
        dns_count = 0
        http_count = 0

        src_ips = []
        dst_ips = []

        for p in snapshot:
            proto = p.protocol.upper()
            
            # Count transport & application categories
            if proto == "TCP":
                tcp_count += 1
            elif proto == "UDP":
                udp_count += 1
            elif proto == "ICMP":
                icmp_count += 1
            elif proto == "DNS":
                dns_count += 1
                udp_count += 1  # Standard DNS runs on UDP
            elif proto == "HTTP":
                http_count += 1
                tcp_count += 1  # Standard HTTP runs on TCP
            elif proto == "TLS":
                tcp_count += 1  # Standard TLS runs on TCP

            if p.src_ip:
                src_ips.append(p.src_ip)
            if p.dst_ip:
                dst_ips.append(p.dst_ip)

        # Retrieve Top Source/Destination IPs
        src_counter = Counter(src_ips).most_common(10)
        dst_counter = Counter(dst_ips).most_common(10)

        top_sources = [{"ip": ip, "count": count} for ip, count in src_counter]
        top_destinations = [{"ip": ip, "count": count} for ip, count in dst_counter]

        return {
            "total_packets": total_packets,
            "tcp_packets": tcp_count,
            "udp_packets": udp_count,
            "icmp_packets": icmp_count,
            "dns_packets": dns_count,
            "http_packets": http_count,
            "top_sources": top_sources,
            "top_destinations": top_destinations
        }
