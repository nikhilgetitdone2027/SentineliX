# SentinelX AI: Enterprise Cognitive SOC & Forensics Platform

Welcome to the **SentinelX AI** codebase—a high-fidelity, next-generation Security Operations Center (SOC) designed to solve the cognitive overload of security analysts. SentinelX transforms raw packet capture data into actionable threat intelligence, multi-vector timelines, business impact assessments, AI-driven attacker next-stage predictions, and executive-ready forensic briefs.

---

## 🛠️ The Architecture

SentinelX combines high-performance link-layer parsing, machine learning heuristics, and multi-modal generative AI to automate the entire incident response lifecycle.

```text
       +--------------------------------------------+
       |   User PCAP Upload / Demo Scenario Switch  |
       +---------------------+----------------------+
                             |
                             v [Streaming binary packet block stream]
       +---------------------+----------------------+
       |  Scapy-Powered Deep Packet Inspection (DPI)|
       |  - Decapsulates Ethernet & IPv4 Frames     |
       |  - Reconstructs TLS / TCP Sockets          |
       |  - Extracts SSL SNI & Payload Entropy      |
       +---------------------+----------------------+
                             |
                             v [Unified NetFlow Header Telemetry]
       +---------------------+----------------------+
       |  Behavioral AI ML Anomaly Detection Engine |
       |  - Isolation Forest Anomaly Scoring        |
       |  - Entropy-based Tunneling Detectors       |
       |  - Active Directory Baseline Comparators  |
       +---------------------+----------------------+
                             |
                             v [Correlated Security Alerts]
       +---------------------+----------------------+
       |  Mitre ATT&CK Tactics & Technique Mapper    |
       |  - Translates IOCs to ATT&CK Technique IDs  |
       |  - Combines Endpoint Log Correlation       |
       +---------------------+----------------------+
                             |
                             v [Dossier Assembly]
       +---------------------+----------------------+
       |  Central In-Memory Threat Store            |
       |  - Maps incidents, profiles, and playbooks |
       +---------------------+----------------------+
             /                                \
            /                                  \
           v                                    v
+----------+------------+           +-----------+-----------+
| Business Impact Engine|           |  AI Attack Prediction |
| - Financial exposure  |           |  - Current state      |
| - Legal liability     |           |  - Next likely stage  |
| - Reputation damages  |           |  - Confidence scores  |
+----------+------------+           +-----------+-----------+
            \                                  /
             \                                /
              v                              v
       +---------------------+----------------------+
       |  SentinelX Generative Explainer Framework   |
       |  - Powered by Gemini 3.5 Flash             |
       |  - Automated RAG Threat Intelligence Docs  |
       +---------------------+----------------------+
                             |
                             +--------------> [Interactive SOC Dashboard]
                             +--------------> [Conversational SOC Copilot]
                             +--------------> [Audit-Ready PDF Forensic Report]
```

---

## 🚀 One-Click Demo Instructions (For Hackathon Judges)

SentinelX features a highly detailed, interactive walk-through pipeline supporting **four distinct threat scenarios**.

1. **Launch the Dashboard**:
   Go to the **SOC Control Panel** tab.

2. **Select a Threat Scenario**:
   Choose from the interactive scenario selector buttons:
   - **Data Exfiltration**: Simulates multi-stage database extraction to a Tor exit node over a high-entropy TLS tunnel.
   - **Credential Theft**: Simulates Active Directory brute-forcing followed by LSASS memory dumping and workstation access.
   - **DNS Tunneling**: Simulates C2 signaling heartbeats encapsulated inside malicious, high-frequency DNS query streams.
   - **Port Scanning**: Simulates hostile subnet reconnaissance, mapping active port ranges and services.

3. **Play Walkthrough**:
   Click **"Play One-Click Walkthrough"**. Watch the live terminal parse the simulated packets, perform ML anomaly checks, correlate endpoint events, and create the live database record in real-time.

4. **Investigate**:
   Click **"GO TO OPERATIONS ROOM"** once complete. Under the active dossier, inspect:
   - **Threat Assessment Summary**: A concise breakdown of the threat vectors.
   - **Business Impact Engine**: Translates technical indicators into financial, legal, and operational risks.
   - **AI Attack Prediction Agent**: Forecasts the attacker's next likely action with percentage-based confidence coefficients.
   - **MITRE ATT&CK Techniques**: Clear matrix tagging of the specific Tactics and IDs.

5. **Generate Compliance Brief**:
   Click **"COMPILE FORENSICS REPORT"**. SentinelX queries the Gemini 3.5 Flash engine to assemble a formal cyber command brief.
   - Click **"PRINT / SAVE PDF"** to preview an elegant print dialog that extracts the report into an audit-ready physical/digital layout.

---

## 🔌 API Documentation

### 1. Packet Parser Upload
* **Route**: `POST /api/packet-parser/upload`
* **Content-Type**: `multipart/form-data`
* **Payload**: File binary (`.pcap`, `.pcapng`)
* **Behavior**: Pipes the raw PCAP through the Scapy-based decapsulator, calculates packet lengths, extracts IP flows, counts protocol distribution metrics, and returns the basic statistics.

### 2. Demo Trigger
* **Route**: `POST /api/demo/trigger`
* **Content-Type**: `application/json`
* **Payload**: 
  ```json
  { "scenario": "data_exfiltration" | "credential_theft" | "dns_tunneling" | "port_scanning" }
  ```
* **Behavior**: Erases standard session buffers and injects a fully customized threat dossier, behavioral endpoint logs, MITRE mappings, risk metrics, predictive transition states, and business impacts.

### 3. Generate Forensics Report
* **Route**: `POST /api/copilot/generate-report`
* **Content-Type**: `application/json`
* **Payload**:
  ```json
  { "incidentId": "string" }
  ```
* **Response**: Returns a markdown formatted security audit compliance report dynamically generated via Gemini.

---

## 🏆 Presentation Highlights

- **Enterprise Realism**: Avoids generic, flat visual layouts. SentinelX feels like an active tactical Command Center utilizing deep blues, high-contrast red alerts, and real-time sparklines.
- **Explainability**: Focuses not only on *detecting* threats, but on translating technical jargon into strategic decision-making matrices for executive administrators (Business Impact) and active responders (Attack Prediction).
- **Interactive Frictionless Testing**: Full reset utilities are built-in. Run multiple testing cycles with different parameters effortlessly.
