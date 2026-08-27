# SIEM Detection Rules – 55+ Multi-Platform
**SIEM Engineer & Threat Hunter Pack**

**Version:** 1.0  
**Generated:** 2026-08-27  
**Platforms:** Microsoft Sentinel (KQL), Splunk (SPL), Elastic (EQL), + Sigma-style tags  
**Environment:** Designed for blank / green-field SIEM + EDR deployments

---

## Contents

- **55 Detection Rules** covering:
  - Phishing & Initial Access
  - Brute Force / Password Spray / Credential Dumping
  - Execution (PowerShell, Office macros, LOLBins)
  - Persistence (Run keys, Scheduled Tasks, Services)
  - Lateral Movement (PsExec, WMI, RDP, WinRM, SMB)
  - Command & Control (Beaconing, DNS tunneling, LOLBin C2)
  - Exfiltration
  - Ransomware & Impact (Shadow copy deletion, encryption behavior)
  - Defense Evasion (Log clearing, Defender disable, injection)
  - Privilege Escalation
  - Discovery

## Rule Format

Each rule file contains:
- MITRE ATT&CK mapping
- Severity
- **KQL** (Microsoft Sentinel / Defender XDR)
- **SPL** (Splunk)
- **EQL** (Elastic – where applicable)
- Implementation notes and required data sources

## How to Use

1. Ingest the required data sources (see each rule).
2. Copy the query for your SIEM platform.
3. Adjust thresholds, time windows, and allow-lists.
4. Start in **detection-only / low-severity** mode.
5. Link high-fidelity alerts to your Automated IR Playbooks (AIR-xxx).

## Recommended Deployment Order

1. Credential Access & Brute Force (DET-004 → DET-008)
2. Ransomware precursors (DET-023, DET-024, DET-025, DET-053)
3. Lateral Movement (DET-016 → DET-019, DET-051)
4. Execution & LOLBins (DET-009 → DET-012, DET-038, DET-039)
5. Phishing & Account Takeover (DET-001 → DET-003, DET-035)
6. Remaining rules by priority and data availability

## Mapping to Previous Packages

These detections complement:
- SOC L1 Incident Response Playbooks
- Automated IR Playbooks (AIR-001 → AIR-020)
- Incident Response Scenarios
- Previous Sigma rule packs

---

**Author Role:** SIEM Engineer / Threat Hunter  
Built for real-world blank-environment deployment and continuous tuning.
