# DET-034: UAC Bypass Indicators

**Category:** Privilege Escalation  
**Severity:** High  
**MITRE ATT&CK:** T1548.002  
**Tags:** attack.privilege_escalation, attack.t1548.002

## Description
Common UAC bypass techniques via fodhelper, eventvwr, sdclt, or registry auto-elevate.

## Microsoft Sentinel / Defender XDR (KQL)
```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName in ("fodhelper.exe","eventvwr.exe","sdclt.exe","computerdefaults.exe")
   or ProcessCommandLine has "mscfile\\shell\\open\\command"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

## Splunk (SPL)
```spl
index=sysmon Image IN ("*\\fodhelper.exe","*\\eventvwr.exe","*\\sdclt.exe")
OR CommandLine="*mscfile\\shell\\open\\command*"
| table _time, host, user, Image, CommandLine
```

### Elastic EQL / ES|QL
```eql
process where process.name in ("fodhelper.exe","eventvwr.exe","sdclt.exe")
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
