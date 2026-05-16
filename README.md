# SOC Detection Engineering Lab
### AI-Assisted Threat Detection | MITRE ATT&CK Mapped | Splunk SIEM

**Analyst:** Rahul Teja Kathi  
**Duration:** 2 weeks  
**Status:** Complete  

---

## What This Project Demonstrates

This project simulates a complete adversary kill chain across 4 attack 
phases and builds production-grade detection engineering on top of it.
It demonstrates the ability to think like both an attacker and a defender
— simulating attacks, building detections, and integrating AI into the
SOC workflow.

---

## Lab Architecture
┌─────────────────────────────────────────────┐
│           SOC LAB NETWORK                   │
│         192.168.56.0/24                     │
│                                             │
│  ┌──────────────┐    ┌──────────────────┐   │
│  │ Windows 10   │    │  Ubuntu Server   │   │
│  │ .104         │───▶│  .101            │   │
│  │ Victim VM    │    │  Splunk SIEM     │   │
│  │ + Sysmon     │    │  Port 8000/9997  │   │
│  └──────────────┘    └──────────────────┘   │
│                                             │
│  ┌──────────────┐    ┌──────────────────┐   │
│  │ Kali Linux   │    │  Host PC         │   │
│  │ .103         │    │  Python + AI     │   │
│  │ Attacker VM  │    │  Phi3 Mini Local │   │
│  └──────────────┘    └──────────────────┘   │
└─────────────────────────────────────────────┘

---

## Attack Chain Simulated

| Day | Report | MITRE | Attack | Result |
|-----|--------|-------|--------|--------|
| 4 | IR-2026-001 | T1110.001 | Brute Force via SMB | Credentials stolen |
| 5 | IR-2026-002 | T1053.005 | Privilege Escalation | SYSTEM access |
| 6 | IR-2026-003 | T1021.002 | Lateral Movement | Shares enumerated |
| 7 | IR-2026-004 | T1041 | Data Exfiltration | PII stolen |

---

## Detection Rules Built

| Rule | Technique | Severity | False Positive Rate |
|------|-----------|----------|---------------------|
| DE-001 Brute Force | T1110.001 | AUTO-SCORED | LOW |
| DE-002 Privilege Escalation | T1053.005 | CRITICAL | LOW |
| DE-003 Lateral Movement | T1021.002 | AUTO-SCORED | MEDIUM |
| DE-004 Data Exfiltration | T1041 | AUTO-SCORED | LOW |
| DE-005 Attack Chain Correlation | Full Chain | CRITICAL | VERY LOW |

---

## AI Integration

Built a Python pipeline using local AI (Phi3 Mini via Ollama) that:
- Pulls real alert data from Splunk REST API
- Analyzes each alert automatically
- Returns severity, MITRE mapping, and recommended actions
- Generates CISO-level briefing for full attack chains
- Runs 100% locally — zero API cost

---

## Skills Demonstrated

- Splunk SIEM — search, detection rules, dashboards, alerts
- Detection Engineering — MITRE mapped rules with threat scoring
- Python scripting — Splunk API integration + AI pipeline
- Local AI integration — Ollama + Phi3 Mini for alert analysis
- Incident Response — 4 professional incident reports
- Threat Intelligence — IOC extraction and MITRE mapping
- Network Security — packet analysis, lateral movement detection
- Linux administration — Ubuntu server, SSH, service management

---

## Tools Used

Splunk Enterprise | Sysmon | Python | Ollama | Phi3 Mini |
CrackMapExec | Netcat | Wireshark | VirtualBox | Kali Linux

---

## Roles This Project Targets

- SOC Analyst L1/L2
- Detection Engineer
- Security Operations Engineer  
- Threat Intelligence Analyst
