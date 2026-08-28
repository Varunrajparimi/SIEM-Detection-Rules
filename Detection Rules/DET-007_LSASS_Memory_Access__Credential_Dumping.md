# DET-007: LSASS Memory Access / Credential Dumping

**Category:** Credential Access  
**Severity:** Critical  
**MITRE ATT&CK:** T1003.001  
**Tags:** attack.credential_access, attack.t1003.001

## Description
Detects processes accessing LSASS memory with suspicious permissions or known dumping tools.

## Microsoft Sentinel / Defender XDR (KQL)
```kql
DeviceEvents
| where Timestamp > ago(1h)
| where ActionType has "ProcessAccessed" or ActionType has "OpenProcess"
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in ("csrss.exe","wininit.exe","services.exe","MsMpEng.exe","MsSense.exe","svchost.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
```

## Splunk (SPL)
```spl
index=sysmon EventCode=10 TargetImage="*\\lsass.exe"
| search NOT SourceImage IN ("*\\csrss.exe","*\\wininit.exe","*\\MsMpEng.exe")
| table _time, host, SourceImage, SourceCommandLine
```

### Elastic EQL / ES|QL
```eql
process where event.type == "access" and process.name == "lsass.exe" and
  not process.executable : ("C:\\Windows\\System32\\csrss.exe", "C:\\Windows\\System32\\wininit.exe")
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
