# DET-003: New Inbox Rule After Suspicious Sign-in

**Category:** Collection  
**Severity:** High  
**MITRE ATT&CK:** T1114.003, T1078  
**Tags:** attack.collection, attack.t1114.003

## Description
Detects creation of mailbox rules (forwarding/hiding) shortly after anomalous login – common BEC post-exploitation.

## Microsoft Sentinel / Defender XDR (KQL)
```kql
OfficeActivity
| where TimeGenerated > ago(24h)
| where Operation in ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules")
| project TimeGenerated, UserId, ClientIP, Operation, Parameters
| join kind=inner (
    SigninLogs
    | where TimeGenerated > ago(48h)
    | where ResultType == "0"
    | where RiskLevelDuringSignIn in ("medium","high")
    | project UserPrincipalName, SignInTime=TimeGenerated, IPAddress
) on $left.UserId == $right.UserPrincipalName
```

## Splunk (SPL)
```spl
index=o365 Operation IN ("New-InboxRule","Set-InboxRule")
| join type=inner [search index=azuread ResultType=0 risk=high | fields user]
| table _time, user, client_ip, operation
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
