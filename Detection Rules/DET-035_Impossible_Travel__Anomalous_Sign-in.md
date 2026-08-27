# DET-035: Impossible Travel / Anomalous Sign-in

**Category:** Initial Access  
**Severity:** High  
**MITRE ATT&CK:** T1078  
**Tags:** attack.initial_access, attack.t1078

## Description
Successful sign-ins from geographically distant locations in a short time window.

## Microsoft Sentinel / Defender XDR (KQL)
```kql
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == "0"
| extend Country = tostring(LocationDetails.countryOrRegion)
| where isnotempty(Country)
| summarize Countries=make_set(Country), IPs=make_set(IPAddress), First=min(TimeGenerated), Last=max(TimeGenerated)
  by UserPrincipalName, bin(TimeGenerated, 1h)
| where array_length(Countries) > 1
| extend Minutes=datetime_diff('minute', Last, First)
| where Minutes < 180
```

## Splunk (SPL)
```spl
index=azuread ResultType=0
| stats values(country) as countries, earliest(_time) as first, latest(_time) as last by user
| where mvcount(countries) > 1
| eval duration=last-first
| where duration < 10800
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
