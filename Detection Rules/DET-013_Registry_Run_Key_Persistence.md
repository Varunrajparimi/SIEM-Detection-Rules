# DET-013: Registry Run Key Persistence

**Category:** Persistence  
**Severity:** Medium  
**MITRE ATT&CK:** T1547.001  
**Tags:** attack.persistence, attack.t1547.001

## Description
Modification of Run / RunOnce registry keys commonly used for persistence.

## Microsoft Sentinel / Defender XDR (KQL)
```kql
DeviceRegistryEvents
| where Timestamp > ago(24h)
| where RegistryKey has_any (@"CurrentVersion\Run", @"CurrentVersion\RunOnce")
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
```

## Splunk (SPL)
```spl
index=sysmon EventCode=13 TargetObject="*\\CurrentVersion\\Run*" OR TargetObject="*\\CurrentVersion\\RunOnce*"
| table _time, host, TargetObject, Details, Image
```

### Elastic EQL / ES|QL
```eql
registry where registry.path : ("*\\CurrentVersion\\Run*", "*\\CurrentVersion\\RunOnce*") and event.type == "change"
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
