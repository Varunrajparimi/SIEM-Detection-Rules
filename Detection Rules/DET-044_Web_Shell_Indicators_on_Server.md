# DET-044: Web Shell Indicators on Server

**Category:** Persistence  
**Severity:** Critical  
**MITRE ATT&CK:** T1505.003  
**Tags:** attack.persistence, attack.t1505.003

## Description
Web server process (w3wp, httpd, nginx, tomcat) spawning shell processes.

## Microsoft Sentinel / Defender XDR (KQL)
```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName has_any ("w3wp.exe","httpd","nginx","tomcat","java")
| where FileName in ("cmd.exe","powershell.exe","bash","sh","whoami","net.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

## Splunk (SPL)
```spl
index=sysmon ParentImage IN ("*\\w3wp.exe","*httpd*","*nginx*","*tomcat*")
| search Image IN ("*\\cmd.exe","*\\powershell.exe","*\\bash*","*\\sh*")
| table _time, host, ParentImage, Image, CommandLine
```

### Elastic EQL / ES|QL
```eql
process where process.parent.name : ("w3wp.exe","httpd","nginx") and process.name in ("cmd.exe","powershell.exe","bash","sh")
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
