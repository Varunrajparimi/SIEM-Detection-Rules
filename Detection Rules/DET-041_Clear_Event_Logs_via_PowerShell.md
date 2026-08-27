# DET-041: Clear Event Logs via PowerShell

**Category:** Defense Evasion  
**Severity:** High  
**MITRE ATT&CK:** T1070.001  
**Tags:** attack.defense_evasion, attack.t1070.001

## Description
PowerShell Clear-EventLog or wevtutil clear used to remove evidence.

## Microsoft Sentinel / Defender XDR (KQL)
```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where ProcessCommandLine has_any ("Clear-EventLog","wevtutil cl","wevtutil clear-log","Remove-EventLog")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

## Splunk (SPL)
```spl
index=sysmon
| search CommandLine="*Clear-EventLog*" OR CommandLine="*wevtutil cl*" OR CommandLine="*wevtutil clear-log*"
| table _time, host, user, CommandLine
```

### Elastic EQL / ES|QL
```eql
process where process.command_line : ("*Clear-EventLog*", "*wevtutil cl*", "*wevtutil clear-log*")
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
