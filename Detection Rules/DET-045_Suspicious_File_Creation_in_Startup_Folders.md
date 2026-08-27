# DET-045: Suspicious File Creation in Startup Folders

**Category:** Persistence  
**Severity:** Medium  
**MITRE ATT&CK:** T1547.001  
**Tags:** attack.persistence, attack.t1547.001

## Description
New executables or scripts written to common startup locations.

## Microsoft Sentinel / Defender XDR (KQL)
```kql
DeviceFileEvents
| where Timestamp > ago(24h)
| where FolderPath has_any (@"\Start Menu\Programs\Startup", @"\Startup")
| where FileName endswith ".exe" or FileName endswith ".dll" or FileName endswith ".js" or FileName endswith ".vbs" or FileName endswith ".bat"
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessFileName
```

## Splunk (SPL)
```spl
index=sysmon EventCode=11
| search TargetFilename="*\\Startup\\*" (TargetFilename="*.exe" OR TargetFilename="*.js" OR TargetFilename="*.vbs")
| table _time, host, TargetFilename, Image
```

### Elastic EQL / ES|QL
```eql
file where file.path : ("*\\Startup\\*") and file.extension in ("exe","dll","js","vbs","bat")
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
