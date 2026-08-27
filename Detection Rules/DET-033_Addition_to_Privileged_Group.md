# DET-033: Addition to Privileged Group

**Category:** Privilege Escalation  
**Severity:** Critical  
**MITRE ATT&CK:** T1098, T1078  
**Tags:** attack.privilege_escalation, attack.t1098

## Description
Account added to Domain Admins, Enterprise Admins, Administrators, or Global Administrator.

## Microsoft Sentinel / Defender XDR (KQL)
```kql
AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName has_any ("Add member to role","Add member to group")
| extend Target = tostring(TargetResources[0].userPrincipalName)
| extend Group = tostring(TargetResources[0].displayName)
| where Group has_any ("Global Administrator","Domain Admins","Enterprise Admins","Administrators")
| project TimeGenerated, InitiatedBy=tostring(InitiatedBy.user.userPrincipalName), Target, Group
```

## Splunk (SPL)
```spl
index=windows EventCode=4732 OR EventCode=4728
| search Group_Name IN ("Domain Admins","Enterprise Admins","Administrators")
| table _time, user, Group_Name, Member_Name
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
