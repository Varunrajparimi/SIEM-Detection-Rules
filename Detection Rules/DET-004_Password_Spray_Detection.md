# DET-004: Password Spray Detection

**Category:** Credential Access  
**Severity:** High  
**MITRE ATT&CK:** T1110.003  
**Tags:** attack.credential_access, attack.t1110.003

## Description
Multiple failed authentications against many accounts from few source IPs within a short window.

## Microsoft Sentinel / Defender XDR (KQL)
```kql
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType in ("50126","50053","50055","50056","50144")
| summarize FailedAttempts=count(), DistinctUsers=dcount(UserPrincipalName), Users=make_set(UserPrincipalName,20)
  by IPAddress, bin(TimeGenerated, 15m)
| where DistinctUsers >= 15
| order by DistinctUsers desc
```

## Splunk (SPL)
```spl
index=azuread OR index=windows EventCode=4625
| stats dc(user) as users, count as failures by src_ip, _time span=15m
| where users >= 15
| sort -users
```

### Elastic EQL / ES|QL
```eql
sequence by source.ip with maxspan=15m
  [authentication where event.outcome == "failure"] with runs=10
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
