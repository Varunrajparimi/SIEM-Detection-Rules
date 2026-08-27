# DET-020: Suspicious Outbound from Scripting Processes

**Category:** Command and Control  
**Severity:** High  
**MITRE ATT&CK:** T1071, T1059  
**Tags:** attack.command_and_control, attack.t1071

## Description
PowerShell, wscript, cscript, mshta, or rundll32 making outbound network connections.

## Microsoft Sentinel / Defender XDR (KQL)
```kql
DeviceNetworkEvents
| where Timestamp > ago(1h)
| where InitiatingProcessFileName in ("powershell.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe")
| where RemoteIPType == "Public"
| project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine
```

## Splunk (SPL)
```spl
index=sysmon EventCode=3 Image IN ("*\\powershell.exe","*\\wscript.exe","*\\mshta.exe","*\\rundll32.exe")
| search DestinationIp!="10.*" DestinationIp!="192.168.*" DestinationIp!="172.16.*"
| table _time, host, Image, DestinationIp, DestinationPort, CommandLine
```

### Elastic EQL / ES|QL
```eql
network where process.name in ("powershell.exe","wscript.exe","mshta.exe","rundll32.exe") and
  not cidrMatch(destination.ip, "10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12")
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
