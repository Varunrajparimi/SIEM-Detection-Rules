# DET-022: Periodic Beaconing Behavior

**Category:** Command and Control  
**Severity:** Medium  
**MITRE ATT&CK:** T1071  
**Tags:** attack.command_and_control, attack.t1071

## Description
Regular interval outbound connections suggestive of C2 beaconing.

## Microsoft Sentinel / Defender XDR (KQL)
```kql
DeviceNetworkEvents
| where Timestamp > ago(6h)
| where RemoteIPType == "Public"
| summarize ConnCount=count() by DeviceName, RemoteIP, RemotePort, bin(Timestamp, 5m)
| where ConnCount >= 3
| summarize BeaconIntervals=count() by DeviceName, RemoteIP
| where BeaconIntervals >= 5
```

## Splunk (SPL)
```spl
index=firewall OR index=sysmon EventCode=3
| stats count by src_ip, dest_ip, dest_port, _time span=5m
| where count >= 3
| stats dc(_time) as intervals by src_ip, dest_ip
| where intervals >= 5
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
