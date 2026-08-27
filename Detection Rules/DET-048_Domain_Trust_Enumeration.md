# DET-048: Domain Trust Enumeration

**Category:** Discovery  
**Severity:** Medium  
**MITRE ATT&CK:** T1482  
**Tags:** attack.discovery, attack.t1482

## Description
Commands used to discover domain trusts (nltest, Get-ADTrust, etc.).

## Microsoft Sentinel / Defender XDR (KQL)
```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where ProcessCommandLine has_any ("nltest /domain_trusts","nltest /trusted_domains","Get-ADTrust","dsquery trust")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

## Splunk (SPL)
```spl
index=sysmon
| search CommandLine="*nltest /domain_trusts*" OR CommandLine="*nltest /trusted_domains*" OR CommandLine="*Get-ADTrust*"
| table _time, host, user, CommandLine
```

### Elastic EQL / ES|QL
```eql
process where process.command_line : ("*nltest /domain_trusts*", "*nltest /trusted_domains*", "*Get-ADTrust*")
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
