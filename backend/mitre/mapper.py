# -*- coding: utf-8 -*-
"""
Rule-based MITRE ATT&CK Mapping Engine for the MVP.
Maps security incidents and behaviors to specific tactics and techniques based on patterns and heuristics.
"""

from typing import List, Dict, Any, Set
from .schemas import MitreMapping
from backend.correlation_engine.schemas import Incident

# MITRE ATT&CK Technique Knowledge Base matching the frontend definition
MITRE_KNOWLEDGE_BASE = {
    "T1059.001": {
        "tactic": "EXECUTION",
        "technique": "Command and Scripting Interpreter: PowerShell",
        "description": "Adversaries may use PowerShell commands to perform execution, system info collection, and lateral movement.",
        "recommended_mitigation": "Restrict PowerShell execution policy, monitor command-line arguments, and enable transcription logs."
    },
    "T1021.004": {
        "tactic": "EXECUTION",
        "technique": "SSH Remote Command",
        "description": "Adversaries may establish SSH sessions to execute commands and scripts remotely on victim machines.",
        "recommended_mitigation": "Enforce SSH key-based authentication, restrict SSH access to specific administrative hosts, and monitor SSH logs."
    },
    "T1110": {
        "tactic": "CREDENTIAL_ACCESS",
        "technique": "LDAP Brute Force",
        "description": "Adversaries may execute dictionary attacks on authentication directories to crack admin accounts.",
        "recommended_mitigation": "Enforce multi-factor authentication, apply rate-limiting, and isolate offending IPs using network firewalls."
    },
    "T1003.001": {
        "tactic": "CREDENTIAL_ACCESS",
        "technique": "OS Credential Dumping: LSASS Memory",
        "description": "Adversaries may attempt to access LSASS process memory to harvest credentials (e.g., using Mimikatz or raw minidump tools).",
        "recommended_mitigation": "Enable LSA Protection, restrict Debug Privilege (SeDebugPrivilege), and monitor process access to lsass.exe."
    },
    "T1021.002": {
        "tactic": "LATERAL_MOVEMENT",
        "technique": "Remote Services: SMB/Windows Admin Shares",
        "description": "Adversaries may move laterally by accessing network shares over SMB (ports 139, 445) using valid administrative credentials.",
        "recommended_mitigation": "Disable administrative shares if not needed, restrict SMB access to authorized subnets, and monitor share access logs."
    },
    "T1048": {
        "tactic": "EXFILTRATION",
        "technique": "Exfiltration Over Alternative Protocol",
        "description": "Adversaries may steal sensitive records or database backups using alternative protocols instead of HTTP/HTTPS, such as raw TLS tunnels.",
        "recommended_mitigation": "Implement network egress filtering, monitor transfer sizes, and block high-risk IP categories."
    },
    "T1567": {
        "tactic": "EXFILTRATION",
        "technique": "Cloud Storage Leak",
        "description": "Adversaries may leak corporate data over legitimate APIs of cloud providers (Mega, Drive).",
        "recommended_mitigation": "Enforce cloud access security broker (CASB) policies, restrict unapproved cloud storage services, and log outbound API requests."
    },
    "T1071.004": {
        "tactic": "PERSISTENCE",
        "technique": "Application Layer Protocol: DNS",
        "description": "Adversaries may communicate using DNS queries containing encoded subdomains to command external implants (DNS Tunneling).",
        "recommended_mitigation": "Analyze DNS query length, monitor high-entropy subdomains, and use DNS filtering or RPZ."
    },
    "T1566": {
        "tactic": "INITIAL_ACCESS",
        "technique": "Phishing",
        "description": "Adversaries may send malicious attachments or links in emails to compromise internal end-user workstations.",
        "recommended_mitigation": "Implement email authentication protocols (SPF, DKIM, DMARC), use email filtering solutions, and provide security awareness training."
    },
    "T1046": {
        "tactic": "DISCOVERY",
        "technique": "Network Port Scanning",
        "description": "Adversaries may scan network ports to map active services, vulnerable versions, and subnets.",
        "recommended_mitigation": "Deploy network intrusion detection/prevention systems (IDS/IPS), filter external scans, and configure host firewall rules."
    },
    "T1087": {
        "tactic": "DISCOVERY",
        "technique": "Account Discovery",
        "description": "Adversaries may query Active Directory groups or local systems to map administrative accounts.",
        "recommended_mitigation": "Restrict Active Directory queries to authorized systems, monitor LDAP search patterns, and enforce least privilege."
    },
    "T1190": {
        "tactic": "INITIAL_ACCESS",
        "technique": "Exploit Public-Facing Application",
        "description": "Adversaries may exploit a vulnerability in an Internet-facing computer or system to gain unauthorized access.",
        "recommended_mitigation": "Regularly patch all external facing web servers, use WAF (Web Application Firewall), and enforce strict access control."
    },
    "T1543": {
        "tactic": "PERSISTENCE",
        "technique": "Create System Service",
        "description": "Adversaries may create or modify system services to execute malicious binaries on boot.",
        "recommended_mitigation": "Audit service creation events (Event ID 7045), restrict service permissions, and check for unsigned service binaries."
    },
    "T1548": {
        "tactic": "PRIVILEGE_ESCALATION",
        "technique": "Bypass UAC Protections",
        "description": "Adversaries may bypass User Account Control permissions to execute high-privilege binaries.",
        "recommended_mitigation": "Enforce strict UAC settings (Always Notify), disable auto-elevation of administrative files, and audit privilege escalation paths."
    },
    "T1055": {
        "tactic": "PRIVILEGE_ESCALATION",
        "technique": "Process Injection",
        "description": "Adversaries may inject malicious payloads into active legitimate processes to escalate privilege states.",
        "recommended_mitigation": "Utilize Endpoint Detection and Response (EDR) agents, enable credential guard, and restrict DLL loads."
    },
    "T1114": {
        "tactic": "COLLECTION",
        "technique": "Email Store Access",
        "description": "Adversaries may target user mailboxes or Exchange caches to collect sensitive company files.",
        "recommended_mitigation": "Enforce multi-factor authentication for mailboxes, audit mail access logs, and restrict remote mailbox synchronization."
    },
    "T1560": {
        "tactic": "COLLECTION",
        "technique": "Archive Collected Data",
        "description": "Adversaries may compress collected database back-ups to facilitate high-volume exfiltration.",
        "recommended_mitigation": "Monitor file system writes for large archive formats (.zip, .tar, .7z) in temporary locations, restrict compression tools."
    },
    "T1485": {
        "tactic": "IMPACT",
        "technique": "Data Destruction",
        "description": "Adversaries may delete system files, databases, or AD catalogs to disrupt corporate capabilities.",
        "recommended_mitigation": "Maintain off-site, read-only system backups, configure strict access controls on vital data stores, and enable volume shadow copies."
    },
    "T1489": {
        "tactic": "IMPACT",
        "technique": "Service Stop",
        "description": "Adversaries may stop anti-virus daemons or logging services to obfuscate active attacks.",
        "recommended_mitigation": "Deploy tamper-protected security agents, monitor Service Control Manager logs, and configure services to auto-restart upon unexpected termination."
    }
}

class MitreMapper:
    """
    Heuristic rule-based mapping engine that analyzes correlated incidents
    and returns corresponding MITRE ATT&CK tactics and techniques.
    """

    @staticmethod
    def map_incident(incident: Incident) -> List[MitreMapping]:
        """
        Maps a single Incident object to a list of matching MITRE ATT&CK techniques.
        """
        mappings: List[MitreMapping] = []
        mapped_ids: Set[str] = set()

        # Gather text content for keyword checking
        narrative = (incident.attack_summary + " " + incident.incident_type).lower()
        timeline_texts = []
        for event in incident.timeline:
            timeline_texts.append(event.message.lower() + " " + event.details.lower())
        combined_text = narrative + " " + " ".join(timeline_texts)

        # 1. Rule-based checks for specific techniques based on keywords and heuristics

        # PowerShell Execution
        if "powershell" in combined_text or ".ps1" in combined_text or "-enc" in combined_text:
            MitreMapper._add_mapping("T1059.001", 90.0, mappings, mapped_ids)

        # OS Credential Dumping: LSASS
        if "lsass" in combined_text or "credential dump" in combined_text or "rdump" in combined_text or "mimikatz" in combined_text:
            MitreMapper._add_mapping("T1003.001", 95.0, mappings, mapped_ids)

        # LDAP Brute Force / Authentication Failures
        if "brute" in combined_text or "stuffing" in combined_text or "auth status: failure" in combined_text or "failed login" in combined_text or "authentication failures" in combined_text:
            MitreMapper._add_mapping("T1110", 85.0, mappings, mapped_ids)

        # Exfiltration Over Alternative Protocol / TLS Tunnel
        if "exfil" in combined_text or "large upload" in combined_text or "tls tunnel" in combined_text or "entropy" in combined_text or "outbound transfer" in combined_text:
            MitreMapper._add_mapping("T1048", 90.0, mappings, mapped_ids)

        # DNS Tunneling / Command & Control / Beaconing
        if "dns tunnel" in combined_text or "dns beacon" in combined_text or "subdomain query" in combined_text or "beaconing" in combined_text:
            MitreMapper._add_mapping("T1071.004", 85.0, mappings, mapped_ids)

        # Scanning / Port Probing / Recon
        if "scan" in combined_text or "probing" in combined_text or "probe" in combined_text or "sweep" in combined_text or "recon" in combined_text:
            MitreMapper._add_mapping("T1046", 90.0, mappings, mapped_ids)

        # Remote Services / SMB Shares
        if "smb" in combined_text or "admin share" in combined_text or "network share" in combined_text:
            MitreMapper._add_mapping("T1021.002", 80.0, mappings, mapped_ids)

        # SSH Remote Command
        if "ssh" in combined_text or "secure shell" in combined_text:
            MitreMapper._add_mapping("T1021.004", 85.0, mappings, mapped_ids)

        # Phishing
        if "phishing" in combined_text or "attachment" in combined_text or "invoice.pdf.lnk" in combined_text:
            MitreMapper._add_mapping("T1566", 80.0, mappings, mapped_ids)

        # 2. Heuristics fallback based on the core Incident Classification if no keyword match occurred
        if not mappings:
            incident_type = incident.incident_type.lower()
            if "exfiltration" in incident_type:
                MitreMapper._add_mapping("T1048", 75.0, mappings, mapped_ids)
            elif "c2" in incident_type or "beaconing" in incident_type or "command" in incident_type:
                MitreMapper._add_mapping("T1071.004", 75.0, mappings, mapped_ids)
            elif "scanning" in incident_type or "probing" in incident_type or "probe" in incident_type:
                MitreMapper._add_mapping("T1046", 75.0, mappings, mapped_ids)
            elif "credential" in incident_type or "authentication" in incident_type:
                MitreMapper._add_mapping("T1110", 70.0, mappings, mapped_ids)
            else:
                # Generic fallback to Exploit Public Application / General access
                MitreMapper._add_mapping("T1190", 50.0, mappings, mapped_ids)

        return mappings

    @staticmethod
    def _add_mapping(tech_id: str, confidence: float, mappings: List[MitreMapping], mapped_ids: Set[str]):
        """
        Helper method to look up technique details and append to mappings without duplicates.
        """
        if tech_id in mapped_ids:
            return
        
        details = MITRE_KNOWLEDGE_BASE.get(tech_id)
        if details:
            mappings.append(MitreMapping(
                tactic=details["tactic"],
                technique=details["technique"],
                confidence=confidence,
                mitreId=tech_id,
                description=details["description"],
                recommendedMitigation=details["recommended_mitigation"]
            ))
            mapped_ids.add(tech_id)

    @staticmethod
    def map_all(incidents: List[Incident]) -> Dict[str, List[MitreMapping]]:
        """
        Maps a list of Incident objects and groups mappings by incident ID.
        """
        results = {}
        for incident in incidents:
            results[incident.incident_id] = MitreMapper.map_incident(incident)
        return results
