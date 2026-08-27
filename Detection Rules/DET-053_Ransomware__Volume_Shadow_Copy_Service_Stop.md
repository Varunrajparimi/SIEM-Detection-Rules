# DET-053: Ransomware – Volume Shadow Copy Service Stop

**Category:** Impact  
**Severity:** Critical  
**MITRE ATT&CK:** T1490  
**Tags:** attack.impact, attack.t1490

## Description
Stopping of VSS service often preceding ransomware encryption.

## Microsoft Sentinel / Defender XDR (KQL)
```kql
DeviceProcessEvents
| where Timestamp > ago(1h)
| where ProcessCommandLine has_any ("sc stop vss","net stop vss","Stop-Service vss","sc config vss")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

## Splunk (SPL)
```spl
index=sysmon OR index=windows
| search CommandLine="*sc stop vss*" OR CommandLine="*net stop vss*" OR CommandLine="*Stop-Service*vss*"
| table _time, host, user, CommandLine
```

### Elastic EQL / ES|QL
```eql
process where process.command_line : ("*sc stop vss*", "*net stop vss*", "*Stop-Service*vss*")
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
