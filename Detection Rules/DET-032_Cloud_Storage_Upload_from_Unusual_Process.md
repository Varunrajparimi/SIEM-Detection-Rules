# DET-032: Cloud Storage Upload from Unusual Process

**Category:** Exfiltration  
**Severity:** Medium  
**MITRE ATT&CK:** T1567.002  
**Tags:** attack.exfiltration, attack.t1567.002

## Description
Non-browser processes connecting to common cloud storage domains.

## Microsoft Sentinel / Defender XDR (KQL)
```kql
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteUrl has_any ("dropbox.com","drive.google.com","onedrive.live.com","mega.nz","box.com","wetransfer.com")
| where InitiatingProcessFileName !in ("chrome.exe","msedge.exe","firefox.exe","outlook.exe","teams.exe")
| project Timestamp, DeviceName, RemoteUrl, InitiatingProcessFileName, InitiatingProcessAccountName
```

## Splunk (SPL)
```spl
index=proxy OR index=firewall
| search dest IN ("*dropbox.com*","*drive.google.com*","*onedrive*","*mega.nz*")
| search NOT process IN ("chrome.exe","msedge.exe","firefox.exe")
| table _time, src, process, dest
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
