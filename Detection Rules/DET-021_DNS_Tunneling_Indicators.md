# DET-021: DNS Tunneling Indicators

**Category:** Command and Control  
**Severity:** High  
**MITRE ATT&CK:** T1071.004  
**Tags:** attack.command_and_control, attack.t1071.004

## Description
High volume of DNS queries or high-entropy subdomains from a single host.

## Microsoft Sentinel / Defender XDR (KQL)
```kql
// Requires DNS logging
DnsEvents
| where TimeGenerated > ago(1h)
| summarize QueryCount=count(), DistinctDomains=dcount(Name) by ClientIP, bin(TimeGenerated, 5m)
| where QueryCount > 100 or DistinctDomains > 50
```

## Splunk (SPL)
```spl
index=dns
| stats count as queries, dc(query) as domains by src_ip, _time span=5m
| where queries > 100 OR domains > 50
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
