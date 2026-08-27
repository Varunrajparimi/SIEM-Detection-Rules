# DET-049: Local Account Creation

**Category:** Persistence  
**Severity:** Medium  
**MITRE ATT&CK:** T1136.001  
**Tags:** attack.persistence, attack.t1136.001

## Description
New local user account created on a workstation or server.

## Microsoft Sentinel / Defender XDR (KQL)
```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4720
| project TimeGenerated, Computer, TargetUserName, SubjectUserName
```

## Splunk (SPL)
```spl
index=windows EventCode=4720
| table _time, host, TargetUserName, SubjectUserName
```

### Elastic EQL / ES|QL
```eql
authentication where event.action == "added-user-account" or winlog.event_id == 4720
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
