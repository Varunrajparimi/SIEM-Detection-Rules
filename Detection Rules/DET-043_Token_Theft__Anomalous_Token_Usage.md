# DET-043: Token Theft / Anomalous Token Usage

**Category:** Credential Access  
**Severity:** High  
**MITRE ATT&CK:** T1528, T1550  
**Tags:** attack.credential_access, attack.t1528

## Description
Sign-ins using tokens from unusual locations or with high risk scores related to token anomalies.

## Microsoft Sentinel / Defender XDR (KQL)
```kql
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == "0"
| where RiskLevelDuringSignIn in ("medium","high")
| extend Risk = tostring(RiskEventTypes_V2)
| where Risk has_any ("anomalousToken","tokenIssuerAnomaly","unfamiliarFeatures","maliciousIPAddress")
| project TimeGenerated, UserPrincipalName, IPAddress, Location, Risk, AppDisplayName
```

## Splunk (SPL)
```spl
index=azuread ResultType=0 risk_level IN ("medium","high")
| search risk_event="*token*" OR risk_event="*anomalous*"
| table _time, user, src_ip, risk_event
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
