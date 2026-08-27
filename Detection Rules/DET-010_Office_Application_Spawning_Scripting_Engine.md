# DET-010: Office Application Spawning Scripting Engine

**Category:** Execution  
**Severity:** High  
**MITRE ATT&CK:** T1204.002, T1059  
**Tags:** attack.execution, attack.t1204.002

## Description
WinWord, Excel, PowerPoint, or Outlook spawning cmd, powershell, wscript, mshta, or rundll32.

## Microsoft Sentinel / Defender XDR (KQL)
```kql
DeviceProcessEvents
| where Timestamp > ago(1h)
| where InitiatingProcessFileName in ("winword.exe","excel.exe","powerpnt.exe","outlook.exe")
| where FileName in ("cmd.exe","powershell.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

## Splunk (SPL)
```spl
index=sysmon ParentImage IN ("*\\winword.exe","*\\excel.exe","*\\powerpnt.exe","*\\outlook.exe")
| search Image IN ("*\\cmd.exe","*\\powershell.exe","*\\wscript.exe","*\\mshta.exe")
| table _time, host, user, ParentImage, Image, CommandLine
```

### Elastic EQL / ES|QL
```eql
process where process.parent.name in ("winword.exe","excel.exe","powerpnt.exe") and
  process.name in ("cmd.exe","powershell.exe","wscript.exe","mshta.exe")
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
