# DET-014: Suspicious Scheduled Task Creation

**Category:** Persistence  
**Severity:** High  
**MITRE ATT&CK:** T1053.005  
**Tags:** attack.persistence, attack.t1053.005

## Description
New scheduled task with suspicious command line (powershell, temp paths, encoded content).

## Microsoft Sentinel / Defender XDR (KQL)
```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName in ("schtasks.exe","powershell.exe")
| where ProcessCommandLine has_any ("/create","Register-ScheduledTask","New-ScheduledTask")
| where ProcessCommandLine has_any ("powershell","cmd","wscript","mshta","http","temp","appdata","programdata")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

## Splunk (SPL)
```spl
index=sysmon (Image="*\\schtasks.exe" OR Image="*\\powershell.exe")
| search CommandLine="*/create*" OR CommandLine="*Register-ScheduledTask*"
| search CommandLine="*powershell*" OR CommandLine="*temp*" OR CommandLine="*http*"
| table _time, host, user, CommandLine
```

### Elastic EQL / ES|QL
```eql
process where process.name in ("schtasks.exe","powershell.exe") and
  process.command_line : ("*/create*", "*Register-ScheduledTask*") and
  process.command_line : ("*powershell*", "*temp*", "*http*")
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
