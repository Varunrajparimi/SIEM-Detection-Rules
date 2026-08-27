# DET-029: Network / Port Scanning from Internal Host

**Category:** Discovery  
**Severity:** Medium  
**MITRE ATT&CK:** T1046  
**Tags:** attack.discovery, attack.t1046

## Description
Internal host making high volume of connection attempts to many ports or hosts.

## Microsoft Sentinel / Defender XDR (KQL)
```kql
DeviceNetworkEvents
| where Timestamp > ago(30m)
| where RemoteIPType == "Private" or RemoteIPType == "Public"
| summarize DistinctPorts=dcount(RemotePort), DistinctIPs=dcount(RemoteIP), ConnCount=count()
  by DeviceName, InitiatingProcessFileName, bin(Timestamp, 5m)
| where DistinctPorts > 50 or DistinctIPs > 30
```

## Splunk (SPL)
```spl
index=firewall OR index=sysmon EventCode=3
| stats dc(dest_port) as ports, dc(dest_ip) as hosts, count as conns by src_ip, _time span=5m
| where ports > 50 OR hosts > 30
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
