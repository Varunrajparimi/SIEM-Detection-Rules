# DET-012: Certutil Download or Decode

**Category:** Command and Control  
**Severity:** High  
**MITRE ATT&CK:** T1105, T1140  
**Tags:** attack.command_and_control, attack.t1105

## Description
certutil used to download files from URL or decode base64 content – common LOLBin abuse.

## Microsoft Sentinel / Defender XDR (KQL)
```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "certutil.exe"
| where ProcessCommandLine has_any ("-urlcache","-decode","-decodehex","http://","https://")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

## Splunk (SPL)
```spl
index=sysmon Image="*\\certutil.exe"
| search CommandLine="*-urlcache*" OR CommandLine="*-decode*" OR CommandLine="*http*"
| table _time, host, user, CommandLine
```

### Elastic EQL / ES|QL
```eql
process where process.name == "certutil.exe" and process.command_line : ("*-urlcache*", "*-decode*", "*http*")
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
