# -*- coding: utf-8 -*-
"""
Core parsing module using Scapy. Parses packet layers and extracts telemetry features.
"""

# Monkeypatch Scapy's Linux rtnetlink IPv6 routing table loader before other imports
try:
    import scapy.config
    scapy.config.conf.ipv6_enabled = False
except Exception:
    pass

try:
    import scapy.arch
    scapy.arch.read_routes6 = lambda *args, **kwargs: []
except Exception:
    pass

try:
    import scapy.arch.linux.rtnetlink
    scapy.arch.linux.rtnetlink.read_routes6 = lambda *args, **kwargs: []
except Exception:
    pass

try:
    import scapy.route6
    scapy.route6.read_routes6 = lambda *args, **kwargs: []
except Exception:
    pass

import os
from typing import List, Generator, Optional
from datetime import datetime, timezone
from scapy.all import PcapReader, Ether, IP, IPv6, TCP, UDP, ICMP, DNS

from .models import ParsedPacket
from .utils import parse_tls_sni, parse_http_metadata, format_tcp_flags

class PacketParser:
    """
    Service responsible for reading PCAP streams and dissecting packets into domain models.
    """

    @staticmethod
    def parse_stream(file_path: str) -> Generator[ParsedPacket, None, None]:
        """
        Streamingly parses a PCAP file from disk to avoid loading massive file trees in memory.
        Gracefully handles malformed packets.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"PCAP file not found at: {file_path}")

        try:
            with PcapReader(file_path) as reader:
                for pkt in reader:
                    try:
                        parsed = PacketParser.dissect_packet(pkt)
                        if parsed:
                            yield parsed
                    except Exception as exc:
                        # Continue processing other packets if individual parsing fails
                        print(f"Error dissecting individual packet: {exc}")
                        continue
        except Exception as exc:
            print(f"Failed to open PCAP reader stream: {exc}")
            return

    @staticmethod
    def dissect_packet(pkt) -> Optional[ParsedPacket]:
        """
        Dissects a single Scapy packet and extracts all requested network telemetry fields.
        """
        # 1. Base metadata: timestamp and length
        try:
            epoch_time = float(pkt.time)
            timestamp = datetime.fromtimestamp(epoch_time, tz=timezone.utc).isoformat()
        except Exception:
            timestamp = datetime.now(timezone.utc).isoformat()

        packet_len = len(pkt)

        # 2. Link Layer (MAC addresses)
        src_mac: Optional[str] = None
        dst_mac: Optional[str] = None
        if pkt.haslayer(Ether):
            src_mac = pkt[Ether].src
            dst_mac = pkt[Ether].dst

        # 3. Network Layer (IP / IPv6 addresses and TTL)
        src_ip: Optional[str] = None
        dst_ip: Optional[str] = None
        ttl: Optional[int] = None
        ip_layer_found = False

        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            ttl = pkt[IP].ttl
            ip_layer_found = True
        elif pkt.haslayer(IPv6):
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst
            ttl = pkt[IPv6].hlim
            ip_layer_found = True

        # 4. Transport and Application Layers (TCP/UDP/ICMP/DNS/HTTP/TLS)
        src_port: Optional[int] = None
        dst_port: Optional[int] = None
        protocol = "UNKNOWN"
        tcp_flags: Optional[str] = None
        dns_query: Optional[str] = None
        http_host: Optional[str] = None
        http_method: Optional[str] = None
        tls_sni: Optional[str] = None

        if pkt.haslayer(TCP):
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            protocol = "TCP"
            tcp_flags = format_tcp_flags(pkt[TCP].flags)

            # Look for HTTP or TLS inside the TCP payload
            payload_bytes = bytes(pkt[TCP].payload)
            if payload_bytes:
                # Try HTTP
                method, host = parse_http_metadata(payload_bytes)
                if method:
                    protocol = "HTTP"
                    http_method = method
                    http_host = host
                else:
                    # Try TLS SNI
                    sni = parse_tls_sni(payload_bytes)
                    if sni:
                        protocol = "TLS"
                        tls_sni = sni

        elif pkt.haslayer(UDP):
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            protocol = "UDP"

            # Check if it has DNS layer
            if pkt.haslayer(DNS):
                protocol = "DNS"
                if pkt[DNS].qd:
                    try:
                        qname = pkt[DNS].qd.qname
                        if isinstance(qname, bytes):
                            dns_query = qname.decode("utf-8", errors="ignore")
                        else:
                            dns_query = str(qname)
                        if dns_query.endswith("."):
                            dns_query = dns_query[:-1]
                    except Exception:
                        pass

        elif pkt.haslayer(ICMP):
            protocol = "ICMP"
            
        elif ip_layer_found:
            # Fallback to general IP-level protocol representation
            if pkt.haslayer(IP):
                proto_num = pkt[IP].proto
                # Common protocols fallback
                if proto_num == 1: protocol = "ICMP"
                elif proto_num == 6: protocol = "TCP"
                elif proto_num == 17: protocol = "UDP"
                else: protocol = f"IP-Proto-{proto_num}"
            else:
                protocol = "IPv6-Payload"

        # Construct and return ParsedPacket object
        return ParsedPacket(
            timestamp=timestamp,
            src_mac=src_mac,
            dst_mac=dst_mac,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            packet_len=packet_len,
            tcp_flags=tcp_flags,
            ttl=ttl,
            dns_query=dns_query,
            http_host=http_host,
            http_method=http_method,
            tls_sni=tls_sni,
        )
