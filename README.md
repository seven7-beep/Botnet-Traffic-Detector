# 🛡️ Botnet Traffic Detector
### Defensive Cybersecurity & Heuristic Network Anomaly Detection Suite

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg?logo=python&logoColor=white)](https://python.org)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.30%2B-FF4B4B.svg?logo=streamlit&logoColor=white)](https://streamlit.io)
[![Scapy](https://img.shields.io/badge/Scapy-2.5%2B-red.svg)](https://scapy.net)
[![SQLite](https://img.shields.io/badge/SQLite-3.0-003B57.svg?logo=sqlite&logoColor=white)](https://sqlite.org)
[![License](https://img.shields.io/badge/Academic-B.Tech%20Project-green.svg)](#)

> **College Project**: B.Tech Cyber Security Capstone / Lab Project  
> **Target Audience**: Students, Viva Evaluators, Cyber Defense Analysts, and Security Researchers  
> **Classification**: Defensive Heuristic & Anomaly Analysis (Educational Tool)

---

## 1. Project Title
**Botnet Traffic Detector — Anomaly & Heuristic Analysis Platform for Network Logs and Packet Captures**

---

## 2. Problem Statement
Modern cyber threats frequently leverage **Botnets** (networks of compromised devices infected with malware such as Mirai, Reaper, Emotet, or Trickbot) to execute coordinated distributed denial-of-service (DDoS) attacks, horizontal port scans for worm propagation, credential brute-forcing, and stealthy data exfiltration. 

Traditional signature-based intrusion detection systems (IDS) often fail when encountering zero-day malware or obfuscated communication payloads. However, the **behavioral communication patterns** (session frequency, port sweeping diversity, beaconing regularity, and sudden volumetric surges) leave detectable statistical anomalies in firewall logs and network telemetry.

---

## 3. Objective
1. **Analyze Network Telemetry**: Parse CSV firewall logs and Scapy-decoded PCAP packet captures into a unified schema.
2. **Behavioral Botnet Detection**: Apply 5 transparent, explainable heuristic detection rules to identify infected hosts without relying on black-box algorithms.
3. **Risk Scoring & Classification**: Calculate a normalized 0–100 threat score for every internal host, categorizing them into *Low*, *Medium*, *High*, and *Critical* severity tiers.
4. **Interactive Cyber Defense Dashboard**: Provide deep-dive host inspection, temporal traffic spike analysis, and incident response checklists.
5. **Demonstrable SQL Analytics**: Store analyzed sessions in SQLite (`botnet_detector.db`) with pre-built safe queries for laboratory and viva demonstrations.

---

## 4. Technologies Used
* **Python**: Core programming language and analytical logic.
* **Streamlit**: Modern interactive web interface and reactive dashboard.
* **Pandas & NumPy**: High-performance data manipulation, aggregation, and time-series resampling.
* **Scapy**: Packet manipulation library for decoding PCAP/PCAPNG network frames.
* **SQLite**: Embedded relational database for telemetry storage and query execution.
* **Matplotlib**: Customized high-contrast dark cybersecurity visual analytics.
* **Custom CSS**: Glassmorphism, neon accents, glowing threat badges, and responsive metric cards.

---

## 5. Main Features

### 📊 1. Cybersecurity Dashboard
* High-level KPI cards: Total logs, unique source hosts, suspicious host count, total traffic volume (KB), average packet size.
* Interactive threat profile distribution (Critical, High, Medium, Low).
* Dark-themed visual charts: Traffic rate timeline, protocol donut breakdown, top talkers, and volume by host.

### 📥 2. Flexible Data Ingestion
* **CSV Import**: Auto-detects and normalizes varying column names (e.g., `src_ip`, `Source`, `client_ip`, `Destination Port`, `len`).
* **PCAP Import**: Scapy-powered packet inspection extracting Layer 3 (IPv4/IPv6/ARP) and Layer 4 (TCP/UDP/ICMP/DNS/HTTP) telemetry.
* **Synthetic Generator**: Deterministic 1-click generator (`seed=42`) producing realistic Mirai scanners, C&C beaconing agents, DDoS flooders, and normal office traffic.

### 🚨 3. Suspicious Hosts & Threat Assessment
* Ranked list of source hosts by risk score (0–100).
* Search, sort, and filter by threat tier.
* **Host Deep-Dive Inspector**: Detailed breakdown of triggered detection rules, evidence strings, destination port sweep charts, and target IP concentration.
* Tailored **Incident Response Action Plans** (Quarantine, firewall blocking, memory forensics, sinkholing).

### 📈 4. Traffic Timeline & Anomaly Spikes
* Dynamic time-series visualization with selectable intervals (`10s`, `30s`, `1min`, `5min`).
* Automatic traffic spike detection highlighting coordinated botnet bursts.
* Host and protocol-level drill-down filters.

### 🔍 5. Log Analysis & Search
* Full-text search and multi-parameter filtering (Source IP, Destination IP, Firewall Action, Threat Level).
* Tabular inspection of individual log events with detection reasons.

### 💾 6. SQLite Database Studio
* Persistent storage in `database/botnet_detector.db`.
* Pre-built viva query presets (Top talkers, potential C&C servers, port sweeps, protocol shares).
* Safe, read-only SQL query editor with execution time profiling.

### 📑 7. Reports & Data Export
* 1-click CSV exports for suspicious hosts and enriched network logs.
* Downloadable Executive Incident Report text summaries.

### 📚 8. Educational Hub & Viva Preparation
* Clear definitions of Botnets, C&C servers, Firewall logs, and Heuristic vs Anomaly detection.
* Viva Defense FAQ with model answers for college examinations.

---

## 6. System Architecture

```
                                    +-----------------------+
                                    |    User Data Input    |
                                    | (CSV / PCAP / Sample) |
                                    +-----------+-----------+
                                                |
                                                v
                                    +-----------------------+
                                    |  packet_parser.py     |
                                    | (Scapy / Pandas Norm) |
                                    +-----------+-----------+
                                                |
                                                v
                                    +-----------------------+
                                    |     detection.py      |
                                    | (5 Heuristic Rules)   |
                                    +-----------+-----------+
                                                |
                        +-----------------------+-----------------------+
                        |                                               |
                        v                                               v
            +-----------------------+                       +-----------------------+
            |      database.py      |                       |     analysis.py       |
            |  (SQLite Persistence) |                       |  (Matplotlib Charts)  |
            +-----------+-----------+                       +-----------+-----------+
                        \                                               /
                         \                                             /
                          v                                           v
                        +-----------------------------------------------+
                        |                   app.py                      |
                        |      (Streamlit Web Application & UI)         |
                        +-----------------------------------------------+
```

---

## 7. Directory Structure

```
c:\Users\blood\OneDrive\Documents\Ddos/
├── app.py                     # Main Streamlit web application & UI orchestrator
├── requirements.txt           # Python dependencies
├── README.md                  # Comprehensive project documentation
├── test_modules.py            # Automated test suite and verification script
├── database/
│   └── botnet_detector.db     # SQLite database (auto-generated)
├── modules/
│   ├── __init__.py
│   ├── detection.py           # Core 5-rule heuristic detection engine & risk scoring
│   ├── packet_parser.py       # Multi-format CSV & Scapy PCAP parsing engine
│   ├── database.py            # SQLite schema, session saving, and safe SQL runner
│   ├── sample_data.py         # Deterministic synthetic botnet & benign traffic generator
│   └── analysis.py            # Dark cybersecurity Matplotlib charts and analytics
├── data/
│   ├── sample_logs.csv        # Pre-generated benchmark synthetic dataset
│   └── test_capture.pcap      # Sample packet capture file
└── assets/
    └── style.css              # Cyber-defense UI stylesheet (dark glassmorphism, neon badges)
```

---

## 8. Installation & Setup

### Prerequisites
* Python 3.10, 3.11, 3.12, 3.13, or 3.14
* Operating System: Windows, macOS, or Linux

### Step 1: Clone or Navigate to Project Directory
```bash
cd "c:\Users\blood\OneDrive\Documents\Ddos"
```

### Step 2: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 3: Run the Test Suite (Optional Verification)
```bash
python test_modules.py
```

### Step 4: Launch the Streamlit Web Application
```bash
python -m streamlit run app.py
```
Open your browser at `http://localhost:8501`.

---

## 9. Detection Methodology (The 5 Core Rules)

The detection engine evaluates every source host IP against 5 configurable heuristic rules:

| Rule # | Anomaly Pattern | Default Weight | Cybersecurity Rationale |
| :--- | :--- | :--- | :--- |
| **Rule 1** | **High Connection Count** | **+30 pts** | Bot nodes under attack orders generate massive session volumes to flood targets or brute-force services. |
| **Rule 2** | **High Target Port Diversity** | **+25 pts** | Sweeping multiple destination ports (21, 22, 23, 80, 445, 3389, 5555, 8080) indicates worm propagation sweeps (e.g. Mirai). |
| **Rule 3** | **High Cumulative Volume (Bytes)** | **+25 pts** | Heavy outbound transfers indicate volumetric amplification attacks or active data exfiltration. |
| **Rule 4** | **Repeated Single Target (Beaconing)** | **+20 pts** | High proportion of connections to a single external IP indicates periodic Command & Control (C&C) heartbeat polling. |
| **Rule 5** | **Burst Traffic Surge (Spike Ratio)** | **+20 pts** | Sudden sharp peaks in 1-minute time windows indicate synchronized botmaster attack broadcast commands. |

### Threat Tier Classification Formula:
$$\text{Raw Score} = \sum_{\text{triggered}} \text{Weight}_i$$

$$\text{Normalized Score} = \min\left(100, \frac{\text{Raw Score}}{\sum \text{Weights}} \times 100\right)$$

* **0 – 29 pts**: 🟢 **Low Risk (Benign)** — Normal routine traffic.
* **30 – 59 pts**: 🟡 **Medium Risk (Suspicious)** — Elevated anomalies, warrants monitoring.
* **60 – 79 pts**: 🟠 **High Risk (Probable Botnet)** — Multi-rule trigger, quarantine recommended.
* **80 – 100 pts**: 🔴 **Critical Risk (Active Botnet / Flooder)** — Severe multi-vector attack activity.

---

## 10. Database Design (`botnet_detector.db`)

### Table: `network_logs`
* `id` (INTEGER PRIMARY KEY AUTOINCREMENT)
* `timestamp` (TEXT)
* `src_ip` (TEXT) — Indexed
* `dst_ip` (TEXT) — Indexed
* `src_port` (INTEGER)
* `dst_port` (INTEGER)
* `protocol` (TEXT) — Indexed
* `bytes` (INTEGER)
* `action` (TEXT)
* `risk_score` (REAL)
* `risk_level` (TEXT) — Indexed
* `primary_reason` (TEXT)
* `session_id` (TEXT)

### Table: `suspicious_hosts`
* `id` (INTEGER PRIMARY KEY AUTOINCREMENT)
* `src_ip` (TEXT)
* `risk_score` (REAL)
* `risk_level` (TEXT)
* `total_connections` (INTEGER)
* `unique_dst_ips` (INTEGER)
* `unique_dst_ports` (INTEGER)
* `total_bytes` (INTEGER)
* `top_dest_ip` (TEXT)
* `primary_reason` (TEXT)
* `detected_at` (TEXT)

---

## 11. Screenshots Section (Placeholders for Project Report)

```
+-----------------------------------------------------------------------------------+
|  [SCREENSHOT 1: Cybersecurity Executive Dashboard with Threat KPI Cards & Charts] |
+-----------------------------------------------------------------------------------+
|  [SCREENSHOT 2: Suspicious Hosts Table & Diagnostic Deep-Dive Inspector]          |
+-----------------------------------------------------------------------------------+
|  [SCREENSHOT 3: Network Traffic Timeline with Highlighted Temporal Burst Spikes]  |
+-----------------------------------------------------------------------------------+
|  [SCREENSHOT 4: SQLite Query Studio executing Read-Only Forensic Presets]        |
+-----------------------------------------------------------------------------------+
```

---

## 12. Limitations
1. **Encrypted Payloads**: Analyzes Layer 3/4 headers and connection metadata; does not decrypt TLS application payloads.
2. **Jitter Evasion**: Sophisticated advanced persistent threats (APTs) using randomized jitter intervals may evade simple static beaconing thresholds.
3. **Internal Proxies**: A legitimate forward proxy or NAT gateway may exhibit high connection counts and requires whitelist tuning.

---

## 13. Future Improvements
* Integration of Unsupervised Machine Learning (Isolation Forest, DBSCAN) alongside heuristic rules.
* Live real-time packet capture streaming via Scapy sniffers with Snort/Suricata rule export.
* Automated IP reputation integration with VirusTotal and AbuseIPDB APIs.
* MITRE ATT&CK framework mapping for detected botnet techniques.

---

## 14. Viva Presentation Guide for Students

When presenting this project to examiners, explain the following 4 stages clearly:

1. **Ingestion & Normalization**: "We take disparate network logs (CSV or PCAPs parsed via Scapy) and normalize them into standard tuples containing timestamp, source/destination IP and port, transport protocol, byte size, and firewall action."
2. **Feature Extraction**: "We group traffic by source IP to compute session frequency, unique destination ports contacted, cumulative bytes transferred, target concentration ratio, and 1-minute burst ratios."
3. **Heuristic Evaluation**: "We evaluate 5 transparent cybersecurity rules representing common botnet behaviors: session floods, horizontal port sweeps, volumetric exfiltration, C&C beaconing, and coordinated surges."
4. **Actionable Defense**: "Rather than just outputting a binary label, we provide an exact diagnostic evidence breakdown, risk score (0-100), and specific incident response actions like subnet isolation and firewall rules."

---

## 15. Team & Academic Credits
* **Project Title**: Botnet Traffic Detector
* **Course**: B.Tech Cyber Security Capstone Project
* **Discipline**: Defensive Cyber Security & Network Forensics
* **Academic Year**: 2026
