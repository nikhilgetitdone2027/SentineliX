# SentinelX — AI Behaviour Engine Documentation

## Overview

The AI Behaviour Engine is SentinelX's main unsupervised anomaly detection module. Unlike legacy Signature-Based Intrusion Detection Systems (IDS) which only detect known malware, the SentinelX Behaviour Engine learns what **normal network traffic** looks like and flags outliers representing zero-day exploits, interactive reverse shells, data exfiltration, or beaconing behavior.

---

## 1. Unsupervised vs. Supervised Anomaly Detection

| Feature | Supervised Learning | Unsupervised Learning (SentinelX) |
| :--- | :--- | :--- |
| **Data Requirements** | Large, high-quality, pre-labeled datasets representing both normal and specific threat classes. | Raw, unlabeled, chronological feature vectors. |
| **Detection Scope** | Excellent at identifying known variants of catalogued malware or attacks. | Detects completely novel, previously unseen threat behaviors (Zero-day exploits). |
| **Adaptability** | Hard to adapt to custom, highly variable enterprise environments without retraining. | Learns normal baselines specific to the target environment's specific network layout. |
| **False-Positive Handling**| Low false positives, but completely blind to brand-new, customized attacks. | Capable of adaptive margin threshold adjustments to match local network tolerances. |

By relying strictly on **unsupervised anomaly detection**, SentinelX does not need threat signatures to protect the environment.

---

## 2. Selected AI Models

SentinelX ships with two state-of-the-art unsupervised machine learning models to provide complete threat consensus:

### 1. Isolation Forest (Primary Model)
- **Why Selected**:
  - Outliers are mathematically "few and different" compared to normal data points. 
  - An Isolation Forest isolates anomalies by recursively partitionining numerical feature spaces. Anomalies require fewer partitions to isolate, meaning they appear much closer to the root of the tree.
  - Unlike density-based approaches, Isolation Forests scale exceptionally well to high-dimensional datasets with thousands of flows, maintaining low memory footprints and execution latency.

### 2. Local Outlier Factor (LOF - Secondary Model)
- **Why Selected**:
  - LOF is a density-based algorithm that compares the local density of a flow's feature space against its $k$-nearest neighbors.
  - It identifies points that have a significantly lower density than their surrounding cluster neighbors, indicating unique transaction traits.
  - This secondary model is excellent at capturing local structural anomalies that might look normal on global distributions but stand out on localized cluster neighborhoods.

---

## 3. Mathematical Risk-Score Formulation

The Risk Engine blends machine learning probability outputs with deterministic heuristic risk flags to yield a highly readable risk profile:

$$\text{Total Risk Score (0-100)} = \text{Base Heuristic Score (Max 80)} + (\text{Model Anomaly Score} \times 20.0)$$

### Heuristic Rule Weightings (Max 80)
1. **Large Upload** (+20): Transmitted bytes sent in the forward direction > 1MB.
2. **Rare Port** (+10): Connection targeted towards a non-standard service port.
3. **Repeated Connections** (+10): Rapid, co-occurring connections using identical endpoints.
4. **Long Session** (+15): Network flow duration > 300 seconds (5 minutes).
5. **External IP** (+10): Boundaries crossed, communicating with an external public IP.
6. **Encrypted Unknown Traffic** (+15): Secure TLS/HTTPS connection targets rare or non-standard ports.

### Consensus Risk Levels
- **LOW** (0 – 39.9): Standard operational transactions.
- **MEDIUM** (40.0 – 69.9): Mild anomalies or minor heuristic deviations requiring warning flags.
- **HIGH** (70.0 – 89.9): High-risk anomalies requiring proactive SOC alert queues.
- **CRITICAL** (90.0 – 100): Confirmed compound indicators (multi-factor heuristics + high model score) signifying exfiltration or active exploits.

---

## 4. AI Model Lifecycle & Automation

```
              ┌─────────────────────────────┐
              │  Chronological Packets      │
              └──────────────┬──────────────┘
                             ▼
              ┌─────────────────────────────┐
              │  Feature Extraction Engine  │
              └──────────────┬──────────────┘
                             ▼
              ┌─────────────────────────────┐
              │      Feature Processor      │◄──── Scales feature matrix
              └──────────────┬──────────────┘      using StandardScaler
                             ▼
              ┌─────────────────────────────┐
              │      Model Predictor        │◄──── Isolation Forest + LOF
              └──────────────┬──────────────┘      Consensus Analysis
                             ▼
              ┌─────────────────────────────┐
              │      Risk & Explainer       │◄──── RiskEngine outputs reasons
              └──────────────┬──────────────┘
                             ▼
              ┌─────────────────────────────┐
              │  Results & Statistics APIs  │
              └─────────────────────────────┘
```

1. **Auto-Loading**: On service startup, `AnomalyService` attempts to load the latest saved models. If they do not exist, it runs baseline initialization.
2. **Standardization Cache**: The system utilizes a persistent `StandardScaler` fitted on standard normal baselines to maintain predictable distance calculations during continuous deployment.
3. **Triggered Retraining**: Analysts can invoke `/ai/train` to retrain the active model over recently captured flows, refining the boundary of what represents "normal" as the organization's workloads adapt.

---

## 5. Explainability (The Explainer Pipeline)

A key limitation of legacy deep learning models is their "black box" nature. SentinelX solves this by extracting the most prominent features and indicators responsible for high risk scores. These are compiled into natural, scannable explanations (e.g., `"Large outbound traffic"`, `"Rare destination port"`) for consumption inside the SOC Copilot dashboard.

---

## 6. Future Architectural Scalability

1. **Autoencoders**: Implement deep reconstruction models (PyTorch) to learn structural compression boundaries of complex flow matrices.
2. **Active Learning Feedback**: Allow SOC analysts to mark false positives directly from the dashboard, feeding user labels back to adjust model contamination rates.
3. **Distributed Streaming Detection**: Adapt the pipeline to run over distributed message queues (e.g., Apache Kafka) for true real-time streaming anomaly detection.
