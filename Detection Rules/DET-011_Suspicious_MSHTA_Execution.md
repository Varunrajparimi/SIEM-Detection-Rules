# DET-011: Suspicious MSHTA Execution

**Category:** Defense Evasion  
**Severity:** High  
**MITRE ATT&CK:** T1218.005  
**Tags:** attack.defense_evasion, attack.t1218.005

## Description
mshta.exe executing remote content or JavaScript/VBScript.

## Microsoft Sentinel / Defender XDR (KQL)
```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "mshta.exe"
| where ProcessCommandLine has_any ("http://","https://","javascript:","vbscript:","about:")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

## Splunk (SPL)
```spl
index=sysmon Image="*\\mshta.exe"
| search CommandLine="*http*" OR CommandLine="*javascript*" OR CommandLine="*vbscript*"
| table _time, host, user, CommandLine
```

### Elastic EQL / ES|QL
```eql
process where process.name == "mshta.exe" and process.command_line : ("*http*", "*javascript*", "*vbscript*")
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
