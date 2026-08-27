# DET-026: Windows Event Log Clearing

**Category:** Defense Evasion  
**Severity:** High  
**MITRE ATT&CK:** T1070.001  
**Tags:** attack.defense_evasion, attack.t1070.001

## Description
Security or System logs cleared (Event ID 1102 / 104) or wevtutil used to clear logs.

## Microsoft Sentinel / Defender XDR (KQL)
```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID in (1102, 104)
| project TimeGenerated, Computer, Account, EventID
| union (
    DeviceProcessEvents
    | where Timestamp > ago(24h)
    | where FileName =~ "wevtutil.exe" and ProcessCommandLine has_any ("cl ","clear-log")
    | project TimeGenerated=Timestamp, Computer=DeviceName, Account=AccountName, EventID=0
)
```

## Splunk (SPL)
```spl
index=windows EventCode IN (1102,104)
| table _time, host, user, EventCode
| append [search index=sysmon Image="*\\wevtutil.exe" CommandLine="*cl *" OR CommandLine="*clear-log*"]
```

### Elastic EQL / ES|QL
```eql
process where process.name == "wevtutil.exe" and process.command_line : ("*cl *", "*clear-log*")
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
