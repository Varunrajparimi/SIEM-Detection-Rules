# DET-019: SMB Administrative Share Access

**Category:** Lateral Movement  
**Severity:** Medium  
**MITRE ATT&CK:** T1021.002  
**Tags:** attack.lateral_movement, attack.t1021.002

## Description
Access to ADMIN$ or C$ shares from non-admin jump hosts.

## Microsoft Sentinel / Defender XDR (KQL)
```kql
DeviceNetworkEvents
| where Timestamp > ago(1h)
| where RemotePort == 445
| where InitiatingProcessFileName !in ("System","svchost.exe")
| project Timestamp, DeviceName, RemoteIP, InitiatingProcessFileName, InitiatingProcessAccountName
```

## Splunk (SPL)
```spl
index=windows OR index=sysmon (EventCode=5140 OR EventCode=5145) Share_Name IN ("ADMIN$","C$")
| table _time, host, src_ip, Share_Name, user
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
