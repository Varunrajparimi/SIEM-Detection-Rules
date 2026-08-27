# CORR-007: Office Macro Execution + Child Process Network Activity

**Severity:** High  
**MITRE ATT&CK:** T1204.002, T1059, T1071  
**Related Base Detections:** DET-010, DET-020

## Description
Office application spawns scripting engine, and that child (or grandchild) makes an external network connection.

## Correlation Logic
Office → script engine spawn, correlated with outbound network activity shortly after.

## False Positive Reduction Notes
Some legitimate add-ins or macros exist. Require external IP and/or known-bad command patterns for higher confidence.

## Microsoft Sentinel / Defender (KQL)
```kql
DeviceProcessEvents
| where Timestamp > ago(1h)
| where InitiatingProcessFileName in ("winword.exe","excel.exe","powerpnt.exe","outlook.exe")
| where FileName in ("cmd.exe","powershell.exe","wscript.exe","cscript.exe","mshta.exe")
| project SpawnTime=Timestamp, DeviceName, AccountName, OfficeApp=InitiatingProcessFileName, Child=FileName, ProcessCommandLine, ProcessId
| join kind=inner (
    DeviceNetworkEvents
    | where Timestamp > ago(1h)
    | where RemoteIPType == "Public"
    | project NetTime=Timestamp, DeviceName, RemoteIP, InitiatingProcessFileName, InitiatingProcessId
) on DeviceName
| where NetTime between (SpawnTime .. SpawnTime + 15m)
| project SpawnTime, DeviceName, AccountName, OfficeApp, Child, ProcessCommandLine, RemoteIP
```

## Splunk (SPL)
```spl
index=sysmon ParentImage IN ("*\\winword.exe","*\\excel.exe","*\\powerpnt.exe") earliest=-1h
| search Image IN ("*\\cmd.exe","*\\powershell.exe","*\\wscript.exe","*\\mshta.exe")
| join type=inner [
    search index=sysmon EventCode=3 earliest=-1h
    | search DestinationIp!="10.*" DestinationIp!="192.168.*"
]
| table _time, host, ParentImage, Image, CommandLine, DestinationIp
```

### Elastic EQL Sequence
```eql
sequence by host.name with maxspan=15m
  [process where process.parent.name in ("winword.exe","excel.exe","powerpnt.exe") and process.name in ("cmd.exe","powershell.exe","wscript.exe","mshta.exe")]
  [network where not cidrMatch(destination.ip, "10.0.0.0/8", "192.168.0.0/16")]
```

## Recommended Response
- High / Critical severity → auto-create incident and link to corresponding Automated IR Playbook (AIR-xxx)
- Enrich with EDR timeline and identity risk score
- For Critical: consider automatic host isolation (non-critical assets) after confirmation

## Tuning Guidance
- Start with higher thresholds; lower only after validating true positives
- Maintain allow-lists for scanners, backup accounts, and admin jump hosts
- Review weekly for the first month of production use

---
*Advanced correlation rule for real-environment deployment. Test thoroughly before enabling alerting.*
