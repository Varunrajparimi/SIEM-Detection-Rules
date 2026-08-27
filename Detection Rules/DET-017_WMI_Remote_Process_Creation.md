# DET-017: WMI Remote Process Creation

**Category:** Lateral Movement  
**Severity:** High  
**MITRE ATT&CK:** T1047  
**Tags:** attack.lateral_movement, attack.t1047

## Description
wmic or PowerShell used for remote process creation via WMI.

## Microsoft Sentinel / Defender XDR (KQL)
```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where (FileName == "wmic.exe" and ProcessCommandLine has "/node:" and ProcessCommandLine has "process call create")
   or (ProcessCommandLine has "Invoke-WmiMethod" and ProcessCommandLine has "-ComputerName")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

## Splunk (SPL)
```spl
index=sysmon (Image="*\\wmic.exe" CommandLine="*/node:*" CommandLine="*process call create*")
OR CommandLine="*Invoke-WmiMethod*" CommandLine="*-ComputerName*"
| table _time, host, user, CommandLine
```

### Elastic EQL / ES|QL
```eql
process where process.name == "wmic.exe" and process.command_line : ("*/node:*", "*process call create*")
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
