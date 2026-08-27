# DET-040: Suspicious Service Binary Path

**Category:** Persistence  
**Severity:** High  
**MITRE ATT&CK:** T1543.003  
**Tags:** attack.persistence, attack.t1543.003

## Description
Service ImagePath pointing to Temp, Users, or non-standard writable locations.

## Microsoft Sentinel / Defender XDR (KQL)
```kql
DeviceRegistryEvents
| where Timestamp > ago(24h)
| where RegistryKey has @"Services\" and RegistryValueName == "ImagePath"
| where RegistryValueData has_any (@"\Temp\",@"\Users\",@"\AppData\",@"\ProgramData\")
| project Timestamp, DeviceName, RegistryKey, RegistryValueData, InitiatingProcessFileName
```

## Splunk (SPL)
```spl
index=sysmon EventCode=13 TargetObject="*\\Services\\*" Details="*\\Temp\\*" OR Details="*\\Users\\*"
| table _time, host, TargetObject, Details
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
