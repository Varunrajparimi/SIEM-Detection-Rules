# DET-028: Process Injection Indicators

**Category:** Defense Evasion  
**Severity:** High  
**MITRE ATT&CK:** T1055  
**Tags:** attack.defense_evasion, attack.t1055

## Description
Suspicious process hollowing, APC injection, or CreateRemoteThread patterns (via EDR telemetry).

## Microsoft Sentinel / Defender XDR (KQL)
```kql
DeviceEvents
| where Timestamp > ago(1h)
| where ActionType has_any ("ProcessInjection","CreateRemoteThread","QueueUserAPC","ProcessHollowing")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ActionType
```

## Splunk (SPL)
```spl
index=sysmon EventCode IN (8,10)
| search (CallTrace="*UNKNOWN*" OR TargetImage!="*\\*")
| table _time, host, SourceImage, TargetImage, EventCode
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
