# DET-047: Suspicious Network Connection from LOLBin

**Category:** Command and Control  
**Severity:** High  
**MITRE ATT&CK:** T1218, T1105  
**Tags:** attack.command_and_control, attack.t1218

## Description
LOLBins (certutil, mshta, regsvr32, rundll32, bitsadmin) making external connections.

## Microsoft Sentinel / Defender XDR (KQL)
```kql
DeviceNetworkEvents
| where Timestamp > ago(1h)
| where InitiatingProcessFileName in ("certutil.exe","mshta.exe","regsvr32.exe","rundll32.exe","bitsadmin.exe")
| where RemoteIPType == "Public"
| project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine
```

## Splunk (SPL)
```spl
index=sysmon EventCode=3 Image IN ("*\\certutil.exe","*\\mshta.exe","*\\regsvr32.exe","*\\rundll32.exe","*\\bitsadmin.exe")
| search DestinationIp!="10.*" DestinationIp!="192.168.*"
| table _time, host, Image, DestinationIp, CommandLine
```

### Elastic EQL / ES|QL
```eql
network where process.name in ("certutil.exe","mshta.exe","regsvr32.exe","rundll32.exe","bitsadmin.exe") and
  not cidrMatch(destination.ip, "10.0.0.0/8", "192.168.0.0/16")
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
