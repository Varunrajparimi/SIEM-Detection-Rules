# DET-015: New Windows Service Creation

**Category:** Persistence  
**Severity:** Medium  
**MITRE ATT&CK:** T1543.003  
**Tags:** attack.persistence, attack.t1543.003

## Description
Creation of a new Windows service – potential persistence or privilege escalation.

## Microsoft Sentinel / Defender XDR (KQL)
```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where (FileName == "sc.exe" and ProcessCommandLine has "create")
   or (FileName == "powershell.exe" and ProcessCommandLine has "New-Service")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

## Splunk (SPL)
```spl
index=sysmon (Image="*\\sc.exe" CommandLine="*create*") OR (CommandLine="*New-Service*")
| table _time, host, user, CommandLine
```

### Elastic EQL / ES|QL
```eql
process where (process.name == "sc.exe" and process.command_line : "*create*") or
  process.command_line : "*New-Service*"
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
