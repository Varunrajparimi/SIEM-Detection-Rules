# DET-054: Suspicious DLL Side-Loading Pattern

**Category:** Defense Evasion  
**Severity:** High  
**MITRE ATT&CK:** T1574.002  
**Tags:** attack.defense_evasion, attack.t1574.002

## Description
Executable loading DLL from unusual path (Temp, AppData, user folders).

## Microsoft Sentinel / Defender XDR (KQL)
```kql
DeviceImageLoadEvents
| where Timestamp > ago(1h)
| where FolderPath has_any (@"\Temp\",@"\AppData\",@"\Users\")
| where FileName endswith ".dll"
| where InitiatingProcessFileName !endswith ".tmp"
| project Timestamp, DeviceName, InitiatingProcessFileName, FolderPath, FileName
```

## Splunk (SPL)
```spl
index=sysmon EventCode=7
| search ImageLoaded="*\\Temp\\*" OR ImageLoaded="*\\AppData\\*"
| search ImageLoaded="*.dll"
| table _time, host, Image, ImageLoaded
```

### Elastic EQL / ES|QL
```eql
library where dll.path : ("*\\Temp\\*", "*\\AppData\\*")
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
