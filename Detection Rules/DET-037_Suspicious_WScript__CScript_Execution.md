# DET-037: Suspicious WScript / CScript Execution

**Category:** Execution  
**Severity:** Medium  
**MITRE ATT&CK:** T1059.005, T1059.007  
**Tags:** attack.execution, attack.t1059.005

## Description
wscript or cscript executing files from Temp, Downloads, or with unusual arguments.

## Microsoft Sentinel / Defender XDR (KQL)
```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName in ("wscript.exe","cscript.exe")
| where ProcessCommandLine has_any (@"\Temp\",@"\Downloads\",@"\AppData\",".vbs",".js",".jse")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

## Splunk (SPL)
```spl
index=sysmon Image IN ("*\\wscript.exe","*\\cscript.exe")
| search CommandLine="*\\Temp\\*" OR CommandLine="*\\Downloads\\*" OR CommandLine="*.vbs*" OR CommandLine="*.js*"
| table _time, host, user, CommandLine
```

### Elastic EQL / ES|QL
```eql
process where process.name in ("wscript.exe","cscript.exe") and
  process.command_line : ("*\\Temp\\*", "*\\Downloads\\*", "*.vbs*", "*.js*")
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
