# CORR-006: Encoded PowerShell + Outbound Network Connection

**Severity:** High  
**MITRE ATT&CK:** T1059.001, T1071, T1105  
**Related Base Detections:** DET-009, DET-020, DET-046

## Description
PowerShell with encoded or download cradle command line that also initiates an external network connection.

## Correlation Logic
Suspicious PowerShell execution correlated with near-simultaneous outbound connection from the same process tree.

## False Positive Reduction Notes
Allow-list known management scripts and software deployment tools that use encoded PowerShell.

## Microsoft Sentinel / Defender (KQL)
```kql
DeviceProcessEvents
| where Timestamp > ago(1h)
| where FileName in ("powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any ("-EncodedCommand","-enc ","FromBase64String","IEX","DownloadString","Net.WebClient","Invoke-WebRequest")
| project ProcTime=Timestamp, DeviceName, AccountName, ProcessCommandLine, ProcessId
| join kind=inner (
    DeviceNetworkEvents
    | where Timestamp > ago(1h)
    | where InitiatingProcessFileName in ("powershell.exe","pwsh.exe")
    | where RemoteIPType == "Public"
    | project NetTime=Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessId
) on DeviceName
| where NetTime between (ProcTime .. ProcTime + 10m)
| project ProcTime, DeviceName, AccountName, ProcessCommandLine, RemoteIP, RemotePort
```

## Splunk (SPL)
```spl
index=sysmon Image="*\\powershell.exe" earliest=-1h
| search CommandLine="*-EncodedCommand*" OR CommandLine="*FromBase64String*" OR CommandLine="*DownloadString*" OR CommandLine="*IEX*"
| join type=inner [
    search index=sysmon EventCode=3 Image="*\\powershell.exe" earliest=-1h
    | search DestinationIp!="10.*" DestinationIp!="192.168.*"
    | fields host, DestinationIp, DestinationPort, _time
]
| table _time, host, user, CommandLine, DestinationIp
```

### Elastic EQL Sequence
```eql
sequence by host.name, process.pid with maxspan=10m
  [process where process.name in ("powershell.exe","pwsh.exe") and process.command_line : ("*-EncodedCommand*", "*DownloadString*", "*IEX*")]
  [network where process.name in ("powershell.exe","pwsh.exe") and not cidrMatch(destination.ip, "10.0.0.0/8", "192.168.0.0/16")]
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
