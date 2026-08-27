# DET-039: Rundll32 Suspicious Execution

**Category:** Defense Evasion  
**Severity:** High  
**MITRE ATT&CK:** T1218.011  
**Tags:** attack.defense_evasion, attack.t1218.011

## Description
rundll32 executing unusual DLLs, JavaScript, or network-related content.

## Microsoft Sentinel / Defender XDR (KQL)
```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "rundll32.exe"
| where ProcessCommandLine has_any ("javascript:","http://","https://","\\Temp\\","\\AppData\\","StartW","OpenURL")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

## Splunk (SPL)
```spl
index=sysmon Image="*\\rundll32.exe"
| search CommandLine="*javascript*" OR CommandLine="*http*" OR CommandLine="*\\Temp\\*" OR CommandLine="*StartW*"
| table _time, host, user, CommandLine
```

### Elastic EQL / ES|QL
```eql
process where process.name == "rundll32.exe" and process.command_line : ("*javascript*", "*http*", "*\\Temp\\*")
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
