# -*- coding: utf-8 -*-
"""
Threat Correlation Engine.
Analyzes reconstructed flows, feature vectors, and machine learning predictions 
to group independent events into security incidents with human-readable timelines.
"""

import uuid
from datetime import datetime, timedelta
from typing import List, Dict, Any, Tuple, Set

from backend.flow_engine.service import FlowEngineService
from backend.feature_engine.service import FeatureEngineService
from backend.ai.behavior.anomaly_service import AnomalyService
from .schemas import Incident, TimelineEvent

class ThreatCorrelator:
    """
    Core correlation processor implementing multi-factor security heuristics and temporal grouping.
    """

    @staticmethod
    def correlate_incidents() -> List[Incident]:
        """
        Runs the correlation pipeline over active flows, features, and ML predictions.
        """
        flow_service = FlowEngineService()
        feature_service = FeatureEngineService()
        anomaly_service = AnomalyService()

        flows = flow_service.get_all_flows()
        features = feature_service.get_all_features()
        
        # Ensure predictions are available
        predictions = anomaly_service.get_results()
        if not predictions and features:
            _, predictions = anomaly_service.analyze_flows()
            
        if not flows:
            return []

        # Create indexing maps for fast lookup
        flow_map = {f.flow_id: f for f in flows}
        feat_map = {f.flow_id: f for f in features}
        pred_map = {p.flow_id: p for p in predictions}

        # Build unified correlation data objects
        correlated_flows: List[Dict[str, Any]] = []
        for flow_id, flow in flow_map.items():
            feat = feat_map.get(flow_id)
            pred = pred_map.get(flow_id)
            
            # Safe fallbacks if feature/prediction is missing
            risk_score = pred.risk_score if pred else (40.0 if (feat and feat.risk_features.rare_port) else 10.0)
            prediction_label = pred.prediction if pred else "Normal"
            confidence = pred.confidence if pred else 50.0
            anomaly_score = pred.anomaly_score if pred else 0.0
            top_reasons = pred.top_reasons if pred else []
            risk_level = pred.risk_level if pred else "LOW"

            correlated_flows.append({
                "flow_id": flow_id,
                "flow": flow,
                "feature": feat,
                "prediction": prediction_label,
                "anomaly_score": anomaly_score,
                "risk_score": risk_score,
                "confidence": confidence,
                "top_reasons": top_reasons,
                "risk_level": risk_level,
                "start_time": flow.start_time,
                "src_ip": flow.src_ip,
                "dst_ip": flow.dst_ip,
                "dst_port": flow.dst_port,
                "protocol": flow.protocol,
                "bytes_sent": flow.bytes_sent,
                "total_bytes": flow.total_bytes,
                "dns_query_count": feat.dns_query_count if feat else 0,
            })

        # Sort all flows chronologically
        correlated_flows.sort(key=lambda x: x["start_time"])

        incidents: List[Incident] = []
        used_flow_ids: Set[str] = set()

        # ----------------------------------------------------------------------
        # RULE 1: Potential Data Exfiltration
        # Trigger: Large upload (> 1MB or large_upload flag) preceded/followed by 
        # DNS query anomaly, rare port activity, or ML anomaly within 5 minutes.
        # ----------------------------------------------------------------------
        exfil_incidents = ThreatCorrelator._detect_data_exfiltration(correlated_flows, used_flow_ids)
        incidents.extend(exfil_incidents)

        # ----------------------------------------------------------------------
        # RULE 2: Command & Control (C2) / Persistent Beaconing
        # Trigger: >= 3 flows between same endpoints on standard/rare ports,
        # closely spaced in time, with repeated connections, and at least one anomaly.
        # ----------------------------------------------------------------------
        c2_incidents = ThreatCorrelator._detect_c2_beaconing(correlated_flows, used_flow_ids)
        incidents.extend(c2_incidents)

        # ----------------------------------------------------------------------
        # RULE 3: Scanning & Port Probing (Port Sweep / IP Sweep)
        # Trigger: Single source IP contacting > 3 unique ports or > 3 unique IPs
        # within a sliding 5-minute window.
        # ----------------------------------------------------------------------
        scanning_incidents = ThreatCorrelator._detect_scanning_probing(correlated_flows, used_flow_ids)
        incidents.extend(scanning_incidents)

        # ----------------------------------------------------------------------
        # RULE 4: Distributed Target Probe / Shared Target Scanning
        # Trigger: Multiple different source IPs (>= 3) targeting the same
        # destination IP and port within 5 minutes.
        # ----------------------------------------------------------------------
        distributed_incidents = ThreatCorrelator._detect_distributed_probing(correlated_flows, used_flow_ids)
        incidents.extend(distributed_incidents)

        # ----------------------------------------------------------------------
        # RULE 5: Generic Anomalous Traffic Clustering
        # Trigger: Any remaining anomalous/high-risk flows within a 10-minute window
        # from the same source or destination IP.
        # ----------------------------------------------------------------------
        cluster_incidents = ThreatCorrelator._detect_generic_clusters(correlated_flows, used_flow_ids)
        incidents.extend(cluster_incidents)

        return incidents

    @staticmethod
    def _create_timeline(flows: List[Dict[str, Any]]) -> List[TimelineEvent]:
        """
        Creates a list of TimelineEvent objects sorted chronologically.
        """
        timeline = []
        for f in sorted(flows, key=lambda x: x["start_time"]):
            msg = f"Flow connection from {f['src_ip']}:{f['flow'].src_port} to {f['dst_ip']}:{f['dst_port']} ({f['protocol']})"
            details = (
                f"Duration: {f['flow'].duration}s | "
                f"Exchange: {f['flow'].bytes_sent} bytes sent, {f['flow'].bytes_received} bytes received. "
                f"Classification: {f['prediction']} (Risk: {f['risk_score']}, Level: {f['risk_level']})."
            )
            timeline.append(TimelineEvent(
                timestamp=f["start_time"].isoformat(),
                message=msg,
                flow_id=f["flow_id"],
                src_ip=f["src_ip"],
                dst_ip=f["dst_ip"],
                protocol=f["protocol"],
                dst_port=f["dst_port"],
                details=details
            ))
        return timeline

    @staticmethod
    def _detect_data_exfiltration(flows: List[Dict[str, Any]], used_flows: Set[str]) -> List[Incident]:
        """
        Correlates DNS/rare port anomalies followed by a massive outbound data flow.
        """
        incidents = []
        
        # Filter flows representing large uploads (or flagged large) that aren't yet used
        large_uploads = [
            f for f in flows 
            if f["flow_id"] not in used_flows and (
                f["bytes_sent"] > 1_000_000 or 
                (f["feature"] and f["feature"].risk_features.large_upload)
            )
        ]

        for upload in large_uploads:
            src_ip = upload["src_ip"]
            upload_time = upload["start_time"]
            
            # Find related preceding or co-occurring flows within a 5-minute window from the same source
            related_flows = []
            for f in flows:
                if f["flow_id"] == upload["flow_id"]:
                    continue
                if f["src_ip"] == src_ip and abs((f["start_time"] - upload_time).total_seconds()) <= 300:
                    # DNS queries or rare ports or anomaly predictions are strong indicators
                    is_suspicious_dns = f["dns_query_count"] > 0 and (f["prediction"] == "Anomaly" or f["risk_score"] > 35.0)
                    is_rare_port = f["feature"] and f["feature"].risk_features.rare_port
                    is_ml_anomaly = f["prediction"] == "Anomaly" or f["risk_score"] > 45.0
                    
                    if is_suspicious_dns or is_rare_port or is_ml_anomaly:
                        related_flows.append(f)

            if related_flows:
                # Include the upload flow itself
                all_involved = [upload] + [f for f in related_flows if f["flow_id"] not in used_flows]
                
                # Mark as used
                for f in all_involved:
                    used_flows.add(f["flow_id"])

                timeline = ThreatCorrelator._create_timeline(all_involved)
                
                # Calculate scores
                max_risk = max(f["risk_score"] for f in all_involved)
                risk_score = min(100.0, max_risk + 10.0)  # Exfil multiplier
                avg_conf = sum(f["confidence"] for f in all_involved) / len(all_involved)
                confidence = min(100.0, avg_conf + 5.0)

                # Summary
                mb_sent = round(upload["bytes_sent"] / (1024 * 1024), 2)
                summary = (
                    f"Observed data exfiltration behavior from source host {src_ip}. "
                    f"A large outbound transfer of {mb_sent}MB to target {upload['dst_ip']} "
                    f"occurred in close proximity to suspicious network activities "
                    f"({len(related_flows)} flows) including "
                    f"{'DNS queries' if any(f['dns_query_count'] > 0 for f in related_flows) else 'unusual port connections'}."
                )

                incidents.append(Incident(
                    incident_id=f"INC-EXFIL-{uuid.uuid4().hex[:6].upper()}",
                    incident_type="Data Exfiltration",
                    related_flow_ids=[f["flow_id"] for f in all_involved],
                    timeline=timeline,
                    severity="CRITICAL" if risk_score >= 85.0 else "HIGH",
                    confidence=round(confidence, 1),
                    risk_score=round(risk_score, 2),
                    attack_summary=summary,
                    src_ip=src_ip,
                    dst_ip=upload["dst_ip"]
                ))
                
        return incidents

    @staticmethod
    def _detect_c2_beaconing(flows: List[Dict[str, Any]], used_flows: Set[str]) -> List[Incident]:
        """
        Correlates multiple sequential connections between same host pair indicating a heartbeat/beacon.
        """
        incidents = []
        
        # Group flows by (src_ip, dst_ip, dst_port)
        groups: Dict[Tuple[str, str, int], List[Dict[str, Any]]] = {}
        for f in flows:
            if f["flow_id"] in used_flows:
                continue
            key = (f["src_ip"], f["dst_ip"], f["dst_port"])
            groups.setdefault(key, []).append(f)

        for key, group_flows in groups.items():
            if len(group_flows) < 3:
                continue
            
            src_ip, dst_ip, dst_port = key
            
            # Check for timing consistency (beaconing): gap between consecutive flows <= 10 minutes
            correlated_set = []
            current_set = [group_flows[0]]
            
            for i in range(1, len(group_flows)):
                prev = group_flows[i-1]
                curr = group_flows[i]
                gap = (curr["start_time"] - prev["start_time"]).total_seconds()
                
                if gap <= 600:  # 10 minutes
                    current_set.append(curr)
                else:
                    if len(current_set) >= 3:
                        correlated_set.extend(current_set)
                    current_set = [curr]
                    
            if len(current_set) >= 3:
                correlated_set.extend(current_set)

            if not correlated_set:
                continue

            # Verify that at least one is anomalous or flagged repeated/long session
            has_anomaly = any(f["prediction"] == "Anomaly" or f["risk_score"] > 40.0 for f in correlated_set)
            has_beacon_indicators = any(
                f["feature"] and (
                    f["feature"].risk_features.repeated_connections or 
                    f["feature"].risk_features.long_session
                )
                for f in correlated_set
            )

            if has_anomaly or has_beacon_indicators:
                # Mark as used
                for f in correlated_set:
                    used_flows.add(f["flow_id"])

                timeline = ThreatCorrelator._create_timeline(correlated_set)
                
                # Calculate scores
                max_risk = max(f["risk_score"] for f in correlated_set)
                risk_score = min(100.0, max_risk + (len(correlated_set) * 1.5))
                avg_conf = sum(f["confidence"] for f in correlated_set) / len(correlated_set)
                confidence = min(100.0, avg_conf + 10.0)

                summary = (
                    f"Persistent Command & Control (C2) beaconing pattern detected from "
                    f"internal source {src_ip} connecting to external host {dst_ip} on port {dst_port}. "
                    f"Identified {len(correlated_set)} highly repetitive flows with consistent timing intervals, "
                    f"indicating active malware heartbeat telemetry or reverse shell tunnels."
                )

                incidents.append(Incident(
                    incident_id=f"INC-C2-{uuid.uuid4().hex[:6].upper()}",
                    incident_type="Persistent Beaconing",
                    related_flow_ids=[f["flow_id"] for f in correlated_set],
                    timeline=timeline,
                    severity="HIGH" if risk_score >= 65.0 else "MEDIUM",
                    confidence=round(confidence, 1),
                    risk_score=round(risk_score, 2),
                    attack_summary=summary,
                    src_ip=src_ip,
                    dst_ip=dst_ip
                ))

        return incidents

    @staticmethod
    def _detect_scanning_probing(flows: List[Dict[str, Any]], used_flows: Set[str]) -> List[Incident]:
        """
        Correlates single host scanning multiple ports (Port Sweep) or multiple hosts (IP Sweep).
        """
        incidents = []
        
        # Group flows by source IP
        src_groups: Dict[str, List[Dict[str, Any]]] = {}
        for f in flows:
            if f["flow_id"] in used_flows:
                continue
            src_groups.setdefault(f["src_ip"], []).append(f)

        for src_ip, src_flows in src_groups.items():
            # Sliding 5-minute window scan detection
            i = 0
            while i < len(src_flows):
                window_flows = [src_flows[i]]
                start_time = src_flows[i]["start_time"]
                
                # Collect flows in 5-minute sliding window
                j = i + 1
                while j < len(src_flows) and (src_flows[j]["start_time"] - start_time).total_seconds() <= 300:
                    window_flows.append(src_flows[j])
                    j += 1
                
                # Check scanning characteristics:
                unique_ports = {f["dst_port"] for f in window_flows if f["dst_port"] is not None}
                unique_dests = {f["dst_ip"] for f in window_flows}
                
                is_port_sweep = len(unique_ports) >= 3
                is_ip_sweep = len(unique_dests) >= 3
                
                if (is_port_sweep or is_ip_sweep) and len(window_flows) >= 3:
                    # Filter out already used in this loop
                    valid_flows = [f for f in window_flows if f["flow_id"] not in used_flows]
                    if len(valid_flows) >= 3:
                        for f in valid_flows:
                            used_flows.add(f["flow_id"])

                        timeline = ThreatCorrelator._create_timeline(valid_flows)
                        max_risk = max(f["risk_score"] for f in valid_flows)
                        risk_score = min(100.0, max_risk + (len(valid_flows) * 1.2))
                        avg_conf = sum(f["confidence"] for f in valid_flows) / len(valid_flows)
                        confidence = min(100.0, avg_conf + 5.0)

                        if is_port_sweep and is_ip_sweep:
                            it_type = "Full Network Mapping / Scanning"
                            desc = f"scanning {len(unique_dests)} separate target hosts across {len(unique_ports)} different ports"
                        elif is_port_sweep:
                            it_type = "Port Scanning"
                            desc = f"probing {len(unique_ports)} unique destination ports on {next(iter(unique_dests)) if len(unique_dests) == 1 else 'multiple hosts'}"
                        else:
                            it_type = "IP Sweeping"
                            desc = f"scanning {len(unique_dests)} unique host machines on port {next(iter(unique_ports)) if len(unique_ports) == 1 else 'multiple ports'}"

                        summary = (
                            f"Host reconnaissance incident detected. Inbound host {src_ip} "
                            f"conducted intensive scanning behavior, {desc} within a short 5-minute time window. "
                            f"This indicates reconnaissance activities seeking open sockets or vulnerabilities."
                        )

                        incidents.append(Incident(
                            incident_id=f"INC-SCAN-{uuid.uuid4().hex[:6].upper()}",
                            incident_type=it_type,
                            related_flow_ids=[f["flow_id"] for f in valid_flows],
                            timeline=timeline,
                            severity="HIGH" if risk_score >= 70.0 else "MEDIUM",
                            confidence=round(confidence, 1),
                            risk_score=round(risk_score, 2),
                            attack_summary=summary,
                            src_ip=src_ip,
                            dst_ip=list(unique_dests)[0] if len(unique_dests) == 1 else None
                        ))
                        # Skip past the processed window to avoid overlapping
                        i = j - 1
                i += 1

        return incidents

    @staticmethod
    def _detect_distributed_probing(flows: List[Dict[str, Any]], used_flows: Set[str]) -> List[Incident]:
        """
        Correlates multiple source hosts targeting the same endpoint.
        """
        incidents = []
        
        # Group flows by (dst_ip, dst_port)
        target_groups: Dict[Tuple[str, int], List[Dict[str, Any]]] = {}
        for f in flows:
            if f["flow_id"] in used_flows:
                continue
            if f["dst_port"] is not None:
                key = (f["dst_ip"], f["dst_port"])
                target_groups.setdefault(key, []).append(f)

        for key, target_flows in target_groups.items():
            # Sliding 5-minute window for distributed probe
            i = 0
            while i < len(target_flows):
                window_flows = [target_flows[i]]
                start_time = target_flows[i]["start_time"]
                
                j = i + 1
                while j < len(target_flows) and (target_flows[j]["start_time"] - start_time).total_seconds() <= 300:
                    window_flows.append(target_flows[j])
                    j += 1
                
                unique_srcs = {f["src_ip"] for f in window_flows}
                
                if len(unique_srcs) >= 3:
                    valid_flows = [f for f in window_flows if f["flow_id"] not in used_flows]
                    if len(valid_flows) >= 3:
                        for f in valid_flows:
                            used_flows.add(f["flow_id"])

                        dst_ip, dst_port = key
                        timeline = ThreatCorrelator._create_timeline(valid_flows)
                        max_risk = max(f["risk_score"] for f in valid_flows)
                        risk_score = min(100.0, max_risk + (len(unique_srcs) * 2.0))
                        avg_conf = sum(f["confidence"] for f in valid_flows) / len(valid_flows)
                        confidence = min(100.0, avg_conf + 8.0)

                        summary = (
                            f"Distributed target probe incident detected targeting host {dst_ip} on port {dst_port}. "
                            f"A coordinated sequence of connections from {len(unique_srcs)} unique source IP addresses "
                            f"({', '.join(list(unique_srcs)[:4])}) was observed within a compact 5-minute window. "
                            f"Highly indicative of a distributed scanning mesh, brute force campaign, or joint reconnaissance."
                        )

                        incidents.append(Incident(
                            incident_id=f"INC-DIST-{uuid.uuid4().hex[:6].upper()}",
                            incident_type="Distributed Scanning / Coordinated Probe",
                            related_flow_ids=[f["flow_id"] for f in valid_flows],
                            timeline=timeline,
                            severity="HIGH" if risk_score >= 70.0 else "MEDIUM",
                            confidence=round(confidence, 1),
                            risk_score=round(risk_score, 2),
                            attack_summary=summary,
                            src_ip=None,
                            dst_ip=dst_ip
                        ))
                        i = j - 1
                i += 1

        return incidents

    @staticmethod
    def _detect_generic_clusters(flows: List[Dict[str, Any]], used_flows: Set[str]) -> List[Incident]:
        """
        Clusters remaining anomalous or elevated-risk flows occurring closely in time.
        """
        incidents = []
        
        # Only consider unused flows with elevated risk
        suspicious_flows = [
            f for f in flows 
            if f["flow_id"] not in used_flows and (f["prediction"] == "Anomaly" or f["risk_score"] >= 40.0)
        ]

        if not suspicious_flows:
            return []

        # Simple grouping by source IP or destination IP within a 10-minute sliding window
        i = 0
        while i < len(suspicious_flows):
            base_flow = suspicious_flows[i]
            window_flows = [base_flow]
            start_time = base_flow["start_time"]
            src_ip = base_flow["src_ip"]
            dst_ip = base_flow["dst_ip"]

            j = i + 1
            while j < len(suspicious_flows) and (suspicious_flows[j]["start_time"] - start_time).total_seconds() <= 600:
                curr = suspicious_flows[j]
                # Correlate if it shares source or destination
                if curr["src_ip"] == src_ip or curr["dst_ip"] == dst_ip or curr["src_ip"] == dst_ip or curr["dst_ip"] == src_ip:
                    window_flows.append(curr)
                j += 1

            if len(window_flows) >= 2:
                # Group these into a generic anomaly cluster
                valid_flows = [f for f in window_flows if f["flow_id"] not in used_flows]
                if len(valid_flows) >= 2:
                    for f in valid_flows:
                        used_flows.add(f["flow_id"])

                    timeline = ThreatCorrelator._create_timeline(valid_flows)
                    max_risk = max(f["risk_score"] for f in valid_flows)
                    risk_score = min(100.0, max_risk + (len(valid_flows) * 1.0))
                    avg_conf = sum(f["confidence"] for f in valid_flows) / len(valid_flows)
                    confidence = round(avg_conf, 1)

                    summary = (
                        f"Anomalous transaction cluster observed involving hosts "
                        f"{src_ip} and {dst_ip}. Compiled {len(valid_flows)} highly irregular "
                        f"flow vectors within 10 minutes, representing clustered anomalous operational trends."
                    )

                    incidents.append(Incident(
                        incident_id=f"INC-CLUSTER-{uuid.uuid4().hex[:6].upper()}",
                        incident_type="Anomalous Behaviour Cluster",
                        related_flow_ids=[f["flow_id"] for f in valid_flows],
                        timeline=timeline,
                        severity="MEDIUM" if risk_score < 70.0 else "HIGH",
                        confidence=confidence,
                        risk_score=round(risk_score, 2),
                        attack_summary=summary,
                        src_ip=src_ip,
                        dst_ip=dst_ip
                    ))
                    i = j - 1
            i += 1

        return incidents
