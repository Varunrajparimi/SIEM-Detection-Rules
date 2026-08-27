# DET-023: Shadow Copy Deletion (Ransomware Prep)

**Category:** Impact  
**Severity:** Critical  
**MITRE ATT&CK:** T1490  
**Tags:** attack.impact, attack.t1490

## Description
vssadmin, wmic, or bcdedit used to delete shadow copies or disable recovery – strong ransomware precursor.

## Microsoft Sentinel / Defender XDR (KQL)
```kql
DeviceProcessEvents
| where Timestamp > ago(1h)
| where ProcessCommandLine has_any (
    "vssadmin delete shadows","vssadmin resize shadowstorage",
    "wmic shadowcopy delete","Get-WmiObject Win32_ShadowCopy",
    "bcdedit /set {default} recoveryenabled no","wbadmin delete catalog"
)
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

## Splunk (SPL)
```spl
index=sysmon OR index=windows
| search CommandLine="*vssadmin delete shadows*" OR CommandLine="*wmic shadowcopy delete*" OR CommandLine="*bcdedit*recoveryenabled*no*" OR CommandLine="*wbadmin delete*"
| table _time, host, user, CommandLine
```

### Elastic EQL / ES|QL
```eql
process where process.command_line : ("*vssadmin delete shadows*", "*wmic shadowcopy delete*", "*bcdedit*recoveryenabled*no*")
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
