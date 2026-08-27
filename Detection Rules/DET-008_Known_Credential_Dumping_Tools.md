# DET-008: Known Credential Dumping Tools

**Category:** Credential Access  
**Severity:** Critical  
**MITRE ATT&CK:** T1003.001  
**Tags:** attack.credential_access, attack.t1003.001

## Description
Execution of Mimikatz, ProcDump against LSASS, comsvcs MiniDump, NanoDump, etc.

## Microsoft Sentinel / Defender XDR (KQL)
```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where ProcessCommandLine has_any ("mimikatz","sekurlsa","procdump","comsvcs.dll","MiniDump","nanodump","lsass")
   or FileName has_any ("mimikatz","procdump","nanodump","pypykatz")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

## Splunk (SPL)
```spl
index=sysmon OR index=windows (CommandLine="*mimikatz*" OR CommandLine="*sekurlsa*" OR CommandLine="*procdump*" OR CommandLine="*MiniDump*")
| table _time, host, user, Image, CommandLine
```

### Elastic EQL / ES|QL
```eql
process where process.command_line : ("*mimikatz*", "*sekurlsa*", "*procdump*lsass*", "*MiniDump*")
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
