# DET-038: Bitsadmin Download

**Category:** Command and Control  
**Severity:** High  
**MITRE ATT&CK:** T1197, T1105  
**Tags:** attack.command_and_control, attack.t1197

## Description
bitsadmin used to download files – classic LOLBin for ingress tool transfer.

## Microsoft Sentinel / Defender XDR (KQL)
```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "bitsadmin.exe"
| where ProcessCommandLine has_any ("/transfer","/download","http://","https://")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

## Splunk (SPL)
```spl
index=sysmon Image="*\\bitsadmin.exe"
| search CommandLine="*/transfer*" OR CommandLine="*/download*" OR CommandLine="*http*"
| table _time, host, user, CommandLine
```

### Elastic EQL / ES|QL
```eql
process where process.name == "bitsadmin.exe" and process.command_line : ("*/transfer*", "*/download*", "*http*")
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
