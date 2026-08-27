# DET-006: RDP Brute Force

**Category:** Credential Access  
**Severity:** High  
**MITRE ATT&CK:** T1110, T1021.001  
**Tags:** attack.credential_access, attack.t1110

## Description
High volume of failed RDP logons from a single source.

## Microsoft Sentinel / Defender XDR (KQL)
```kql
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4625
| where LogonType == 10 or LogonType == 3
| summarize FailedAttempts=count(), DistinctAccounts=dcount(TargetUserName) by IpAddress, bin(TimeGenerated, 10m)
| where FailedAttempts >= 20
```

## Splunk (SPL)
```spl
index=windows EventCode=4625 Logon_Type=10 OR Logon_Type=3
| stats count as failures, dc(TargetUserName) as accounts by src_ip, _time span=10m
| where failures >= 20
```

### Elastic EQL / ES|QL
```eql
sequence by source.ip with maxspan=10m
  [authentication where event.outcome=="failure" and winlog.event_data.LogonType in ("10","3")] with runs=15
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
