# DET-009: Encoded PowerShell Command

**Category:** Execution  
**Severity:** High  
**MITRE ATT&CK:** T1059.001  
**Tags:** attack.execution, attack.t1059.001

## Description
PowerShell launched with -EncodedCommand, -enc, FromBase64String, or IEX patterns.

## Microsoft Sentinel / Defender XDR (KQL)
```kql
DeviceProcessEvents
| where Timestamp > ago(1h)
| where FileName in ("powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any ("-EncodedCommand","-enc ","-e ","FromBase64String","IEX","Invoke-Expression","DownloadString","DownloadFile")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
```

## Splunk (SPL)
```spl
index=sysmon Image="*\\powershell.exe" OR Image="*\\pwsh.exe"
| search CommandLine="*-EncodedCommand*" OR CommandLine="*-enc *" OR CommandLine="*FromBase64String*" OR CommandLine="*IEX*"
| table _time, host, user, CommandLine, ParentImage
```

### Elastic EQL / ES|QL
```eql
process where process.name in ("powershell.exe","pwsh.exe") and
  process.command_line : ("*-EncodedCommand*", "*-enc *", "*FromBase64String*", "*IEX*")
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
*Created for blank SIEM + EDR environments. Customize entity names, thresholds, and exclusions.*
