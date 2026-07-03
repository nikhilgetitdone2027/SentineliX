# -*- coding: utf-8 -*-
"""
Helper utilities for the AI Behaviour Engine.
"""

from typing import Dict, Any
from backend.feature_engine.models import BehaviouralFeatureVector

def sanitize_feature_dict(feature_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Sanitizes dictionary values to make sure types match BehaviouralFeatureVector schema.
    """
    # Safeguard for missing or malformed fields
    sanitized = dict(feature_dict)
    if "duration" in sanitized:
        sanitized["duration"] = float(sanitized["duration"])
    if "packet_count" in sanitized:
        sanitized["packet_count"] = int(sanitized["packet_count"])
    if "bytes_sent" in sanitized:
        sanitized["bytes_sent"] = int(sanitized["bytes_sent"])
    if "bytes_received" in sanitized:
        sanitized["bytes_received"] = int(sanitized["bytes_received"])
    if "total_bytes" in sanitized:
        sanitized["total_bytes"] = int(sanitized["total_bytes"])
    return sanitized
