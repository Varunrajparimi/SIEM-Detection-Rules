# DET-016: PsExec or Remote Service Execution

**Category:** Lateral Movement  
**Severity:** High  
**MITRE ATT&CK:** T1021.002, T1569.002  
**Tags:** attack.lateral_movement, attack.t1021.002

## Description
Use of PsExec, PaExec, or sc.exe to create remote services for lateral movement.

## Microsoft Sentinel / Defender XDR (KQL)
```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName in ("psexec.exe","psexec64.exe","paexec.exe")
   or (FileName == "sc.exe" and ProcessCommandLine has "\\" and ProcessCommandLine has "create")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

## Splunk (SPL)
```spl
index=sysmon Image IN ("*\\psexec.exe","*\\psexec64.exe","*\\paexec.exe")
OR (Image="*\\sc.exe" CommandLine="*create*" CommandLine="*\\\\*")
| table _time, host, user, Image, CommandLine
```

### Elastic EQL / ES|QL
```eql
process where process.name in ("psexec.exe","psexec64.exe","paexec.exe") or
  (process.name == "sc.exe" and process.command_line : "*create*" and process.command_line : "*\\\\*")
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
*Created for blank SIEM + EDR environments. Customize entity names, thresholds, and exclusions.*
