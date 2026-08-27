# DET-050: Suspicious Scheduled Task – System Privileges

**Category:** Persistence  
**Severity:** High  
**MITRE ATT&CK:** T1053.005  
**Tags:** attack.persistence, attack.t1053.005

## Description
Scheduled task created to run as SYSTEM or with highest privileges.

## Microsoft Sentinel / Defender XDR (KQL)
```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName == "schtasks.exe"
| where ProcessCommandLine has "/create" and ProcessCommandLine has_any ("/ru system","/rl highest","NT AUTHORITY\\SYSTEM")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

## Splunk (SPL)
```spl
index=sysmon Image="*\\schtasks.exe" CommandLine="*/create*"
| search CommandLine="*/ru system*" OR CommandLine="*/rl highest*" OR CommandLine="*NT AUTHORITY\\SYSTEM*"
| table _time, host, user, CommandLine
```

### Elastic EQL / ES|QL
```eql
process where process.name == "schtasks.exe" and process.command_line : "*/create*" and
  process.command_line : ("*/ru system*", "*/rl highest*")
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
