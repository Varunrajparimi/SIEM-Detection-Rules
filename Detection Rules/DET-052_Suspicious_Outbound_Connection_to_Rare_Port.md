# DET-052: Suspicious Outbound Connection to Rare Port

**Category:** Command and Control  
**Severity:** Medium  
**MITRE ATT&CK:** T1071  
**Tags:** attack.command_and_control, attack.t1071

## Description
Outbound connections to uncommon high ports from workstations.

## Microsoft Sentinel / Defender XDR (KQL)
```kql
DeviceNetworkEvents
| where Timestamp > ago(1h)
| where RemoteIPType == "Public"
| where RemotePort > 1024 and RemotePort !in (80,443,8080,8443,53,123,22,21,25,587,993,995)
| where InitiatingProcessFileName !in ("chrome.exe","msedge.exe","firefox.exe","outlook.exe","teams.exe","onedrive.exe")
| summarize count() by DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName
| where count_ > 3
```

## Splunk (SPL)
```spl
index=firewall OR index=sysmon EventCode=3
| search dest_port>1024 NOT dest_port IN (80,443,8080,8443,53)
| search NOT process IN ("chrome.exe","msedge.exe","firefox.exe")
| stats count by src, dest_ip, dest_port, process
| where count > 3
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
