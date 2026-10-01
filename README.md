# 🛡️ SENTINEL-X | Real-Time UEBA & Behavioral Threat Analytics Engine

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/architecture-Modular%20Detector%20Pattern-orange.svg)]()
[![Validation](https://img.shields.io/badge/data--validation-Pydantic%20v2-green.svg)](https://docs.pydantic.dev/)
[![MITRE ATT&CK](https://img.shields.io/badge/compliance-MITRE%20ATT%26CK-red.svg)](https://attack.mitre.org/)
[![License](https://img.shields.io/badge/license-MIT-lightgrey.svg)](LICENSE)

> **SENTINEL-X** is a Python-based, modular User and Entity Behavior Analytics (**UEBA**) threat detection engine designed for modern enterprises. It validates raw system and access logs using **Pydantic** models, analyzes behavioral anomalies via **Haversine geographical speed**, **Z-Score statistical deviation**, and **Cyber Threat Intelligence** algorithms, calculates cumulative user risk scores, and generates automated SOC incident reports.

---

## 🗺️ Repository Structure & File Map

```text
sentinel-x/
├── config/
│   └── rules_config.yaml         # Detection rules, threshold parameters, and time windows
├── data/
│   └── system_access_logs.json   # Raw access and activity logs for testing/simulation
├── docs/
│   └── Threat_Detection_Report.md # Automatically generated SOC incident investigation report
├── sentinel_x/
│   ├── __init__.py               # Package exports
│   ├── config.py                 # YAML configuration loader and parser
│   ├── models.py                 # Pydantic schema models (LogEntry, ThreatAlert)
│   ├── scoring.py                # Cumulative user risk scoring and weighting engine
│   ├── reporter.py               # Markdown-formatted incident report generator
│   └── detectors/
│       ├── __init__.py           # Detector module package
│       ├── base.py               # Abstract Base Class for detection engines
│       ├── travel.py             # Haversine impossible travel detection algorithm
│       ├── statistical.py        # Z-Score statistical anomaly detection engine
│       ├── exfiltration.py       # Off-hours bulk data exfiltration analysis engine
│       └── threat_intel.py       # C2/Tor blacklist and privilege escalation engine
├── .gitignore                    # Git ignore rules
├── main.py                       # Pipeline orchestration script (Entrypoint)
├── requirements.txt              # Project dependencies (Pydantic, PyYAML, etc.)
└── README.md                     # Main project documentation

+---------------------------+
                                |  system_access_logs.json  |
                                +---------------------------+
                                              |
                                              v
                                +---------------------------+
                                |   Pydantic Log Entry      |
                                |  Validation & Normalizer  |
                                +---------------------------+
                                              |
     +----------------------------------------+----------------------------------------+
     |                                        |                                        |
     v                                        v                                        v
+-----------------------+          +-----------------------+          +-----------------------+
|  Impossible Travel    |          | Statistical Behavior  |          | Threat Intelligence   |
|   (Haversine Speed)   |          |    (Z-Score Engine)   |          |  (C2 & Tor Feed Match)|
+-----------------------+          +-----------------------+          +-----------------------+
     |                                        |                                        |
     +----------------------------------------+----------------------------------------+
                                              |
                                              v
                                +---------------------------+
                                |    Risk Scoring Engine    |
                                | (Cumulative User Profile) |
                                +---------------------------+
                                              |
                                              v
                                +---------------------------+
                                |     Security Reporter     |
                                | (Automated MD Generation) |
                                +---------------------------+
                                              |
                                              v
                                +---------------------------+
                                | Threat_Detection_Report.md|
                                +---------------------------+
