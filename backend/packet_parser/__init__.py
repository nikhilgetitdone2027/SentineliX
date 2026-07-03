# -*- coding: utf-8 -*-
"""
Packet Parser package initialization with sandboxed-container compatibility patches.
"""

# Monkeypatch Scapy's Linux rtnetlink IPv6 routing table loader to prevent
# KeyError: 'scope' crashes inside sandboxed Docker/Kubernetes container environments.
try:
    import scapy.arch.linux.rtnetlink
    scapy.arch.linux.rtnetlink.read_routes6 = lambda: []
except Exception:
    pass

try:
    import scapy.route6
    scapy.route6.read_routes6 = lambda: []
except Exception:
    pass
