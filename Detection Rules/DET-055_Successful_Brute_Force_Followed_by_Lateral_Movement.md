# DET-055: Successful Brute Force Followed by Lateral Movement

**Category:** Lateral Movement  
**Severity:** Critical  
**MITRE ATT&CK:** T1110, T1021  
**Tags:** attack.credential_access, attack.lateral_movement, attack.t1110

## Description
Correlation: successful logon after multiple failures, then remote activity from same host.

## Microsoft Sentinel / Defender XDR (KQL)
```kql
let brute = SecurityEvent
| where TimeGenerated > ago(2h)
| where EventID == 4625
| summarize Failures=count() by TargetUserName, IpAddress
| where Failures >= 10;
SecurityEvent
| where TimeGenerated > ago(2h)
| where EventID == 4624 and LogonType in (3,10)
| join kind=inner brute on $left.TargetUserName == $right.TargetUserName and $left.IpAddress == $right.IpAddress
| project TimeGenerated, TargetUserName, IpAddress, Computer, LogonType
```

## Splunk (SPL)
```spl
index=windows EventCode=4625
| stats count as fails by TargetUserName, src_ip
| where fails >= 10
| join type=inner [search index=windows EventCode=4624 Logon_Type IN (3,10) | fields TargetUserName, src_ip, Computer]
| table _time, TargetUserName, src_ip, Computer
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
