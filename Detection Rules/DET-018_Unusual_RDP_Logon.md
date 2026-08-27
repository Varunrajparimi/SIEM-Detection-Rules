# DET-018: Unusual RDP Logon

**Category:** Lateral Movement  
**Severity:** Medium  
**MITRE ATT&CK:** T1021.001  
**Tags:** attack.lateral_movement, attack.t1021.001

## Description
RDP successful logon from unexpected source or to high-value hosts.

## Microsoft Sentinel / Defender XDR (KQL)
```kql
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4624 and LogonType == 10
| project TimeGenerated, TargetUserName, IpAddress, Computer, LogonProcessName
```

## Splunk (SPL)
```spl
index=windows EventCode=4624 Logon_Type=10
| table _time, TargetUserName, src_ip, Computer
```

### Elastic EQL / ES|QL
```eql
authentication where event.action == "logged-in" and winlog.event_data.LogonType == "10"
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
