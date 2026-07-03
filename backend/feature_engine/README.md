# SentinelX — Feature Extraction Engine Documentation

## Overview

The Feature Extraction Engine is a crucial, high-performance telemetry layer designed to turn raw, chronological network flows (reconstructed from packet captures) into rich, AI-ready behavioural feature vectors. 

By aggregating packet-level attributes into session-level and behavioral vectors, the engine shifts focus from raw protocol flags to **traffic behavior**, making the telemetry ready for consumption by downstream machine learning models or rule-based heuristics.

---

## 1. Feature Engineering & Structure

For every reconstructed flow, the engine extracts a multidimensional feature vector containing the following groupings:

### Basic Telemetry Features
- **Duration**: Total session lifetime in seconds.
- **Packet Count**: Number of packets in both directions.
- **Bytes Sent / Received / Total**: Volumetric direction-aware sizes in bytes.
- **Average, Min, Max Packet Size**: Structural fingerprinting of data exchange boundaries.
- **Packets per Second (PPS) & Bytes per Second (BPS)**: Transmission rates indicating intensity.
- **Byte Ratio**: Percentage of data sent in the forward direction vs. overall flow.

### Communication Features
- **Protocol**: Transport or elevated application-level protocol.
- **Source / Destination Ports**: Targets indicating active services.
- **Direction**: flow directionality (`forward`, `reverse`, or `bidirectional`).
- **Connection Count**: Number of co-occurring flows sharing the same socket endpoints in the current analysis batch, indicating traffic intensity.

### Protocol-Specific Features
- **DNS**: Query count, count of unique domains, and average length of domain queries (helps detect Domain Generation Algorithms or tunnel signals).
- **HTTP**: Extracted Host header, request Method, and URI length (helps detect malicious commands or SQLi/XSS payloads embedded in query parameters).
- **TLS**: Server Name Indication (SNI) host and handshake protocol version (indicates traffic intent and secure compliance).
- **TCP**: Direct counts of control flags (`SYN`, `ACK`, `FIN`, `RST`) mapped chronologically from flow packets.

---

## 2. Behavioral Indicators (Heuristics & Risk Features)

Each feature vector is annotated with a suite of boolean heuristics indicating behavioral risk:

| Indicator | Condition | Detection Purpose |
| :--- | :--- | :--- |
| **Large Upload** | Sent bytes > 1MB | Detects data exfiltration, large file transfers, or active beacon payload uploads. |
| **Long Session** | Duration > 300 seconds (5 mins) | Identifies persistent connections, interactive shells, or active tunnels (e.g., reverse shell). |
| **High Packet Rate** | PPS > 100 | Flags potential flood-based Denial of Service (DoS) attacks or automated brute-forcing. |
| **High Byte Rate** | BPS > 50 KB/s | Flags database dumps, streaming data transfers, or malware downloads. |
| **Repeated Connections**| Frequency > 5 connections | Detects periodic malware beaconing, C2 polls, or rapid scraping behavior. |
| **External / Internal IP**| RFC1918 Private vs. Public IP | Classifies boundary crossings (Internal-to-External indicates egress data flows, Internal-to-Internal represents lateral movement). |
| **Common / Rare Port** | Custom common port list match | Highlights suspicious port utilization (e.g., malware running on non-standard ports to bypass simple firewalls). |
| **Encrypted Traffic** | Protocol is TLS/HTTPS or port matches | Distinguishes cleartext protocols from encrypted streams, indicating potential encrypted exfiltration paths. |

---

## 3. How the Behaviour AI Consumes These Vectors

The downstream Behaviour AI Engine can consume these structured JSON-serializable feature vectors in several ways:

1. **Supervised Classification (Random Forests / XGBoost)**:
   - Numerical metrics such as `byte_ratio`, `packets_per_second`, and `bytes_sent` act as core features for classifying flows into categories: e.g., `Normal Web Browsing`, `Malicious Beaconing`, `Exfiltration`, `Port Scan`.

2. **Unsupervised Anomaly Detection (Isolation Forests / Autoencoders)**:
   - By training on baseline normal feature vectors, autoencoders learn to reconstruct normal flow ratios. A flow yielding an unusually high reconstruction error (e.g., highly anomalous `byte_ratio` on a `rare_port`) is immediately flagged as anomalous.

3. **Large Language Model (LLM) Reasoning**:
   - The structured JSON representations of flows (containing high-level fields like `http_host`, `tls_sni`, and boolean risk flags like `large_upload: true`) are perfect for prompt construction. An LLM agent can ingest these summaries to produce readable security incident reports and explain *why* a particular communication pattern is suspicious.
