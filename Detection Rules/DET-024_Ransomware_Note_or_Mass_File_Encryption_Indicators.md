# DET-024: Ransomware Note or Mass File Encryption Indicators

**Category:** Impact  
**Severity:** Critical  
**MITRE ATT&CK:** T1486  
**Tags:** attack.impact, attack.t1486

## Description
Detection of common ransom note filenames or rapid creation of encrypted extensions.

## Microsoft Sentinel / Defender XDR (KQL)
```kql
DeviceFileEvents
| where Timestamp > ago(1h)
| where FileName has_any ("README","HOW_TO_DECRYPT","RECOVERY","DECRYPT","RANSOM",".encrypted",".locked",".crypt",".pay")
| summarize count() by DeviceName, FileName, bin(Timestamp, 5m)
| where count_ > 5
```

## Splunk (SPL)
```spl
index=sysmon EventCode=11
| search file_name IN ("*README*","*HOW_TO_DECRYPT*","*DECRYPT*","*.encrypted","*.locked")
| stats count by host, file_name, _time span=5m
| where count > 5
```

### Elastic EQL / ES|QL
```eql
file where file.name : ("*README*", "*HOW_TO_DECRYPT*", "*DECRYPT*", "*.encrypted", "*.locked")
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
