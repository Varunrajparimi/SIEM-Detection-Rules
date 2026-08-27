# DET-036: MFA Fatigue / Repeated MFA Push Failures

**Category:** Credential Access  
**Severity:** High  
**MITRE ATT&CK:** T1621  
**Tags:** attack.credential_access, attack.t1621

## Description
Multiple MFA push denials or failures in short time – possible MFA fatigue attack.

## Microsoft Sentinel / Defender XDR (KQL)
```kql
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType in ("500121","50074","50158") or Status.errorCode in (500121,50074)
| summarize MFAFailures=count() by UserPrincipalName, IPAddress, bin(TimeGenerated, 15m)
| where MFAFailures >= 5
```

## Splunk (SPL)
```spl
index=azuread (ResultType=500121 OR ResultType=50074)
| stats count as mfa_fail by user, src_ip, _time span=15m
| where mfa_fail >= 5
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
