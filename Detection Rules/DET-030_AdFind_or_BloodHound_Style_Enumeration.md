# DET-030: AdFind or BloodHound Style Enumeration

**Category:** Discovery  
**Severity:** High  
**MITRE ATT&CK:** T1087, T1069, T1482  
**Tags:** attack.discovery, attack.t1087

## Description
Execution of AdFind, SharpHound, or common AD reconnaissance command lines.

## Microsoft Sentinel / Defender XDR (KQL)
```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName has_any ("AdFind","SharpHound","BloodHound")
   or ProcessCommandLine has_any ("-f objectcategory","--CollectionMethod","Get-ADComputer","Get-ADGroupMember")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

## Splunk (SPL)
```spl
index=sysmon
| search Image="*AdFind*" OR Image="*SharpHound*" OR CommandLine="*-f objectcategory*" OR CommandLine="*--CollectionMethod*"
| table _time, host, user, Image, CommandLine
```

### Elastic EQL / ES|QL
```eql
process where process.name : ("*AdFind*", "*SharpHound*") or process.command_line : ("*-f objectcategory*", "*--CollectionMethod*")
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
