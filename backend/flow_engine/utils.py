# -*- coding: utf-8 -*-
"""
Utils module for the Flow Reconstruction Engine.

================================================================================
FLOW RECONSTRUCTION ENGINE ARCHITECTURE & TECHNICAL DOCUMENTATION
================================================================================

1. Flow Identification
   -------------------
   A network flow is a sequence of packets sharing a common set of properties,
   traditionally identified by the "5-tuple":
   - Source IP Address
   - Destination IP Address
   - Source Port (Transport Layer, e.g., TCP/UDP)
   - Destination Port (Transport Layer, e.g., TCP/UDP)
   - Protocol (Transport Protocol, e.g., TCP, UDP, ICMP, etc.)

   In this module, packets are classified into their respective flows using this
   5-tuple, with support for protocols that do not utilize ports (e.g., ICMP)
   by defaulting port values to None.

2. Bidirectional Flow Matching
   ---------------------------
   To reconstruct an entire communication session (e.g., a complete TCP connection or
   a UDP request-response dialogue), packets travelling in both directions must be
   grouped into the same flow.
   
   To achieve bidirectional matching in O(n) time, we construct a canonical key by
   sorting the two socket endpoints (IP, Port) lexicographically. Specifically:
   
       Endpoint A = (src_ip, src_port)
       Endpoint B = (dst_ip, dst_port)
       
       Canonical Key = (min(Endpoint A, Endpoint B), max(Endpoint A, Endpoint B), protocol)
       
   Using this canonical key, packets sent from IP-A:Port-A to IP-B:Port-B and packets
   sent from IP-B:Port-B to IP-A:Port-A yield the exact same key.
   
   To identify the initiator (or directionality):
   - The first packet observed for a given canonical key establishes the "forward" direction.
   - Any packet matching the original (Source IP, Source Port, Destination IP, Destination Port)
     is categorized as a "forward" packet.
   - Any packet with reversed endpoints is categorized as a "reverse" packet.

3. Flow Lifecycle
   --------------
   A flow has a defined lifecycle governed by:
   - Creation: Initiated when a packet with a new canonical key is observed, or after
     an existing flow has expired.
   - Updates: Subsequent matching packets update the flow's packet count, bytes,
     TCP flag set, and protocol-specific metadata (DNS query list, HTTP headers, TLS SNI).
   - Inactivity Timeout (Idle Timeout): If the gap between the current packet's timestamp
     and the previous packet's timestamp in the flow exceeds a configured threshold
     (e.g., 60 seconds), the existing flow is considered "closed/expired" and a new
     flow is spawned for that key. This handles reuse of 5-tuples over time.
   - Active Timeout: Maximum duration a single flow can remain open before being split
     (e.g., 1800 seconds), though idle timeout is typically sufficient for PCAP analysis.

4. Future AI Integration
   ----------------------
   This engine serves as the clean, highly-structured telemetry layer for downstream AI
   Behavour, Threat Detection, or Classification Engines.
   By aggregating raw packet-level logs into high-level statistical session features
   (such as average packet size, bytes sent/received, packet ratio, and inter-arrival times),
   the Flow Engine outputs a feature vector ready for ML classification or LLM reasoning:
   - Duration, bytes, and ratios can train anomaly detectors (e.g., Exfiltration).
   - Inter-arrival times and packet size standard deviations act as structural footprints
     for traffic profiling (e.g., distinguishing video streaming from command-and-control beaconing).
   - Extracted text metadata (DNS domain, HTTP headers, TLS SNI) allows the AI engine to
     cross-reference threat intelligence lists, search for DGA (Domain Generation Algorithms),
     or perform deep semantic correlation.
"""

import hashlib
from typing import Optional, Tuple
from datetime import datetime, timezone

def parse_iso_timestamp(timestamp_str: str) -> datetime:
    """
    Parses a variety of ISO-8601 string formats into a timezone-aware UTC datetime.
    Handles trailing 'Z', offsets, and sub-second variations.
    """
    try:
        # Standard replacement to make standard datetime.fromisoformat happy
        clean = timestamp_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        # Fallback to current time if parsing fails
        return datetime.now(timezone.utc)

def get_canonical_endpoints(
    src_ip: Optional[str],
    src_port: Optional[int],
    dst_ip: Optional[str],
    dst_port: Optional[int]
) -> Tuple[Tuple[str, int], Tuple[str, int]]:
    """
    Sorts two IP-port socket endpoints lexicographically to provide a standard bidirectional identity.
    """
    ip_a = src_ip or "0.0.0.0"
    port_a = src_port or 0
    ip_b = dst_ip or "0.0.0.0"
    port_b = dst_port or 0
    
    endpoint_a = (ip_a, port_a)
    endpoint_b = (ip_b, port_b)
    
    if endpoint_a <= endpoint_b:
        return endpoint_a, endpoint_b
    else:
        return endpoint_b, endpoint_a

def generate_flow_hash(
    src_ip: Optional[str],
    src_port: Optional[int],
    dst_ip: Optional[str],
    dst_port: Optional[int],
    protocol: str,
    index: int = 0
) -> str:
    """
    Generates a deterministic 8-character hex flow ID based on the endpoints, protocol, and a suffix index.
    The suffix index accommodates multiple flows sharing the same 5-tuple (due to timeouts).
    """
    ep_a, ep_b = get_canonical_endpoints(src_ip, src_port, dst_ip, dst_port)
    proto_normalized = protocol.upper().strip()
    
    raw_str = f"{ep_a[0]}:{ep_a[1]}-{ep_b[0]}:{ep_b[1]}-{proto_normalized}-{index}"
    sha = hashlib.md5(raw_str.encode("utf-8")).hexdigest()
    return f"flow_{sha[:8]}"
