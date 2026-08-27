# DET-051: PowerShell Remoting / WinRM Lateral Movement

**Category:** Lateral Movement  
**Severity:** High  
**MITRE ATT&CK:** T1021.006  
**Tags:** attack.lateral_movement, attack.t1021.006

## Description
Use of Enter-PSSession, Invoke-Command, or winrs for remote execution.

## Microsoft Sentinel / Defender XDR (KQL)
```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where ProcessCommandLine has_any ("Enter-PSSession","Invoke-Command","-ComputerName","winrs ","New-PSSession")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

## Splunk (SPL)
```spl
index=sysmon
| search CommandLine="*Enter-PSSession*" OR CommandLine="*Invoke-Command*" OR CommandLine="*-ComputerName*" OR CommandLine="*winrs *"
| table _time, host, user, CommandLine
```

### Elastic EQL / ES|QL
```eql
process where process.command_line : ("*Enter-PSSession*", "*Invoke-Command*", "*winrs *")
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
