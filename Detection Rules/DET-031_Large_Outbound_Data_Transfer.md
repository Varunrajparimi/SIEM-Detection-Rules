# DET-031: Large Outbound Data Transfer

**Category:** Exfiltration  
**Severity:** High  
**MITRE ATT&CK:** T1041, T1048  
**Tags:** attack.exfiltration, attack.t1041

## Description
Unusual high volume of outbound traffic from a single host or process.

## Microsoft Sentinel / Defender XDR (KQL)
```kql
DeviceNetworkEvents
| where Timestamp > ago(1h)
| where RemoteIPType == "Public"
| summarize TotalBytes=sum(SentBytes) by DeviceName, InitiatingProcessFileName, RemoteIP, bin(Timestamp, 30m)
| where TotalBytes > 50000000
| order by TotalBytes desc
```

## Splunk (SPL)
```spl
index=firewall OR index=proxy
| stats sum(bytes_out) as total_bytes by src_ip, dest_ip, _time span=30m
| where total_bytes > 50000000
| sort -total_bytes
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
