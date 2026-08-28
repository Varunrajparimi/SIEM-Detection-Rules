# DET-002: Successful Sign-in After Phishing Click

**Category:** Initial Access  
**Severity:** High  
**MITRE ATT&CK:** T1566, T1078  
**Tags:** attack.initial_access, attack.t1566, attack.t1078

## Description
Correlates potential phishing with subsequent successful authentication from new location/IP.

## Microsoft Sentinel / Defender XDR (KQL)
```kql
let phishUsers = EmailEvents
| where TimeGenerated > ago(24h)
| where EmailDirection == "Inbound"
| where Subject has_any ("urgent","verify","password") or UrlCount > 0
| distinct RecipientEmailAddress;
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == "0"
| where UserPrincipalName in (phishUsers)
| where RiskLevelDuringSignIn in ("medium","high") or LocationDetails.countryOrRegion != "YourCountry"
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName, RiskLevelDuringSignIn
```

## Splunk (SPL)
```spl
index=azuread OR index=o365
| search operation=Sign-in ResultType=0
| join type=inner [ search index=email subject IN ("*urgent*","*verify*") | fields recipient ]
| table _time, user, src_ip, location
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
