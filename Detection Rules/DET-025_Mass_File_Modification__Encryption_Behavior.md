# DET-025: Mass File Modification / Encryption Behavior

**Category:** Impact  
**Severity:** Critical  
**MITRE ATT&CK:** T1486  
**Tags:** attack.impact, attack.t1486

## Description
High rate of file writes/renames by a single process – possible active encryption.

## Microsoft Sentinel / Defender XDR (KQL)
```kql
DeviceFileEvents
| where Timestamp > ago(30m)
| where ActionType in ("FileCreated","FileRenamed","FileModified")
| summarize FileCount=count() by DeviceName, InitiatingProcessFileName, InitiatingProcessId, bin(Timestamp, 5m)
| where FileCount > 100
```

## Splunk (SPL)
```spl
index=sysmon EventCode IN (11,2)
| stats count as files by host, Image, process_id, _time span=5m
| where files > 100
```

## Implementation Notes
- Tune thresholds (counts, time windows) to your environment baseline.
- Add allow-lists for known admin tools, scanners, and service accounts.
- Correlate with EDR alerts for higher fidelity.
- Test in detection-only mode before enabling alerting.
- Map to your Automated IR Playbooks (AIR-xxx) for response.

## Data Sources Required
- Microsoft: SigninLogs, SecurityEvent, DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, EmailEvents, AuditLogs, DeviceRegistryEvents
- Splunk: windows, sysmon, azuread, o365, firewall, proxy, email indexes
- Elastic: process, network, authentication, file, registry events (Endpoint / Winlogbeat / Sysmon)

---
*Generated for blank SIEM + EDR environments. Customize entity names, thresholds, and exclusions.*
