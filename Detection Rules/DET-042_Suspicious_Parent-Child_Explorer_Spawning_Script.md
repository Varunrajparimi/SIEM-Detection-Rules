# DET-042: Suspicious Parent-Child: Explorer Spawning Script

**Category:** Execution  
**Severity:** Medium  
**MITRE ATT&CK:** T1059  
**Tags:** attack.execution, attack.t1059

## Description
explorer.exe spawning powershell, cmd, or scripting engines with suspicious arguments.

## Microsoft Sentinel / Defender XDR (KQL)
```kql
DeviceProcessEvents
| where Timestamp > ago(1h)
| where InitiatingProcessFileName =~ "explorer.exe"
| where FileName in ("powershell.exe","cmd.exe","wscript.exe","mshta.exe")
| where ProcessCommandLine has_any ("-enc","-nop","-w hidden","http","IEX","DownloadString")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

## Splunk (SPL)
```spl
index=sysmon ParentImage="*\\explorer.exe" Image IN ("*\\powershell.exe","*\\cmd.exe","*\\wscript.exe")
| search CommandLine="*-enc*" OR CommandLine="*-nop*" OR CommandLine="*IEX*" OR CommandLine="*http*"
| table _time, host, user, Image, CommandLine
```

### Elastic EQL / ES|QL
```eql
process where process.parent.name == "explorer.exe" and process.name in ("powershell.exe","cmd.exe") and
  process.command_line : ("*-enc*", "*-nop*", "*IEX*", "*http*")
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
