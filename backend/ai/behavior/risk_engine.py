# -*- coding: utf-8 -*-
"""
Risk Engine for compiling ML scores and structural heuristics into standard risk scores.
Calculates risk levels and provides explanatory indicators for security analysts.
"""

from typing import List, Dict, Any, Tuple
from backend.feature_engine.models import BehaviouralFeatureVector

class RiskEngine:
    """
    Dedicated engine to calculate multi-factor security risk scores and behavioral explanations.
    """
    # Heuristic weights defined by the specification
    RULE_WEIGHTS = {
        "large_upload": 20.0,
        "rare_port": 10.0,
        "repeated_connections": 10.0,
        "long_session": 15.0,
        "external_ip": 10.0,
        "encrypted_unknown_traffic": 15.0
    }

    @staticmethod
    def calculate_risk(
        feature_vector: BehaviouralFeatureVector,
        anomaly_score: float
    ) -> Tuple[float, str, List[str]]:
        """
        Calculates a combined 0-100 risk score, risk level, and top explanatory reasons.
        
        Formula:
          Base Rule Score = sum of active rule-based weights (Max 80)
          Model Score Contribution = anomaly_score * 20 (Max 20)
          Total Raw Score = Base Rule Score + Model Score Contribution (Max 100)
        """
        active_reasons: List[str] = []
        rule_score = 0.0

        rf = feature_vector.risk_features

        # 1. Large Upload (+20)
        if rf.large_upload:
            rule_score += RiskEngine.RULE_WEIGHTS["large_upload"]
            active_reasons.append("Large outbound traffic")

        # 2. Rare Port (+10)
        if rf.rare_port:
            rule_score += RiskEngine.RULE_WEIGHTS["rare_port"]
            active_reasons.append("Rare destination port")

        # 3. Repeated Connections (+10)
        if rf.repeated_connections:
            rule_score += RiskEngine.RULE_WEIGHTS["repeated_connections"]
            active_reasons.append("High connection frequency")

        # 4. Long Session (+15)
        if rf.long_session:
            rule_score += RiskEngine.RULE_WEIGHTS["long_session"]
            active_reasons.append("Very long session")

        # 5. External IP (+10)
        if rf.external_ip:
            rule_score += RiskEngine.RULE_WEIGHTS["external_ip"]
            active_reasons.append("External IP interaction")

        # 6. Encrypted Unknown Traffic (+15)
        # Triggered if traffic is encrypted and uses a non-standard/rare port
        is_encrypted_unknown = rf.encrypted_traffic and rf.rare_port
        # Also fall back to general encrypted traffic if specific flag is active but not standard port
        if is_encrypted_unknown or (rf.encrypted_traffic and feature_vector.dst_port not in {443, 993, 995}):
            rule_score += RiskEngine.RULE_WEIGHTS["encrypted_unknown_traffic"]
            active_reasons.append("Encrypted unknown traffic")
        elif rf.encrypted_traffic:
            # Add general encrypted traffic reason but with slightly lower weight if it's on a common port
            # To respect the user prompt's "Encrypted Unknown Traffic +15"
            pass

        # 7. Model Anomaly Contribution (Max 20)
        model_contribution = anomaly_score * 20.0
        
        if anomaly_score > 0.5:
            active_reasons.append("Anomalous behavioural profile")

        # Calculate final combined risk score (Max 100)
        risk_score = min(100.0, max(0.0, rule_score + model_contribution))
        risk_score = round(risk_score, 2)

        # Map to Risk Level
        if risk_score >= 90.0:
            risk_level = "CRITICAL"
        elif risk_score >= 70.0:
            risk_level = "HIGH"
        elif risk_score >= 40.0:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        # Ensure we always have at least one explanation if it's anomalous or has any risk
        if not active_reasons:
            if risk_score > 20.0:
                active_reasons.append("Elevated traffic metrics")
            else:
                active_reasons.append("Normal baseline profile")

        return risk_score, risk_level, active_reasons
