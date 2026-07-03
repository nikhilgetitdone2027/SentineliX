# -*- coding: utf-8 -*-
"""
Utility module for network packet byte parsing, TLS SNI extraction, and HTTP decoding.
"""

from typing import Optional, Tuple
import re

def parse_tls_sni(payload: bytes) -> Optional[str]:
    """
    Parses Server Name Indication (SNI) from raw TCP payload bytes of a TLS Client Hello.
    This raw byte parser is highly reliable and does not depend on dynamic external TLS libraries.
    """
    try:
        # Check if it looks like a TLS Record: Handshake (22) and major version 3 (SSLv3/TLSv1.x)
        if len(payload) < 43 or payload[0] != 0x16 or payload[1] != 0x03:
            return None
        
        # Handshake Type: Client Hello (1)
        # Position 5 of TLS record is handshake type
        if payload[5] != 0x01:
            return None

        # Index tracker
        idx = 43  # Start of session ID length field
        
        # Skip Session ID
        if idx >= len(payload): return None
        session_id_len = payload[idx]
        idx += 1 + session_id_len
        
        # Skip Cipher Suites
        if idx + 1 >= len(payload): return None
        cipher_suites_len = int.from_bytes(payload[idx:idx+2], byteorder="big")
        idx += 2 + cipher_suites_len
        
        # Skip Compression Methods
        if idx >= len(payload): return None
        comp_methods_len = payload[idx]
        idx += 1 + comp_methods_len
        
        # Get Extensions Length
        if idx + 1 >= len(payload): return None
        extensions_len = int.from_bytes(payload[idx:idx+2], byteorder="big")
        idx += 2
        
        target_end = idx + extensions_len
        
        # Iterate over Extensions
        while idx + 3 < len(payload) and idx < target_end:
            ext_type = int.from_bytes(payload[idx:idx+2], byteorder="big")
            ext_len = int.from_bytes(payload[idx+2:idx+4], byteorder="big")
            idx += 4
            
            # SNI Extension is type 0x0000
            if ext_type == 0:
                if idx + 2 > len(payload):
                    return None
                # Server Name List Length
                sn_list_len = int.from_bytes(payload[idx:idx+2], byteorder="big")
                sub_idx = idx + 2
                
                if sub_idx + 3 <= len(payload):
                    name_type = payload[sub_idx]
                    name_len = int.from_bytes(payload[sub_idx+1:sub_idx+3], byteorder="big")
                    sub_idx += 3
                    
                    if name_type == 0 and sub_idx + name_len <= len(payload):
                        sni_bytes = payload[sub_idx:sub_idx+name_len]
                        return sni_bytes.decode("utf-8", errors="ignore").rstrip("\x00")
            
            idx += ext_len
            
    except Exception:
        pass
    return None

def parse_http_metadata(payload: bytes) -> Tuple[Optional[str], Optional[str]]:
    """
    Analyzes TCP payload bytes to extract HTTP request method and Host header.
    Returns: (http_method, http_host)
    """
    try:
        decoded = payload.decode("utf-8", errors="ignore")
        first_line = decoded.split("\r\n")[0]
        
        # Check for standard HTTP Methods
        methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]
        words = first_line.split(" ")
        if not words or words[0] not in methods:
            return None, None
            
        method = words[0]
        host = None
        
        # Search for Host header
        match = re.search(r"(?i)\r\nHost:\s*([^\r\n]+)", decoded)
        if match:
            host = match.group(1).strip()
            
        return method, host
    except Exception:
        pass
    return None, None

def format_tcp_flags(flags) -> str:
    """
    Utility to format Scapy TCP flags into standard single-character shorthand representations.
    """
    if not flags:
        return ""
    # If it is an integer, decode bits
    if isinstance(flags, int):
        flag_chars = []
        if flags & 0x01: flag_chars.append("F")  # FIN
        if flags & 0x02: flag_chars.append("S")  # SYN
        if flags & 0x04: flag_chars.append("R")  # RST
        if flags & 0x08: flag_chars.append("P")  # PSH
        if flags & 0x10: flag_chars.append("A")  # ACK
        if flags & 0x20: flag_chars.append("U")  # URG
        return "".join(flag_chars)
        
    return str(flags)
