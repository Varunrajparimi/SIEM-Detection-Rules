# DET-005: Successful Login After Password Spray

**Category:** Credential Access  
**Severity:** Critical  
**MITRE ATT&CK:** T1110.003, T1078  
**Tags:** attack.credential_access, attack.t1110.003

## Description
Detects successful authentication from an IP previously involved in password spraying.

## Microsoft Sentinel / Defender XDR (KQL)
```kql
let sprayIPs = SigninLogs
| where TimeGenerated > ago(2h)
| where ResultType != "0"
| summarize dcount(UserPrincipalName) by IPAddress
| where dcount_UserPrincipalName >= 10
| project IPAddress;
SigninLogs
| where TimeGenerated > ago(2h)
| where ResultType == "0"
| where IPAddress in (sprayIPs)
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName
```

## Splunk (SPL)
```spl
index=azuread ResultType!=0
| stats dc(user) as users by src_ip
| where users>=10
| join type=inner [search index=azuread ResultType=0 | fields src_ip, user]
| table _time, user, src_ip
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
