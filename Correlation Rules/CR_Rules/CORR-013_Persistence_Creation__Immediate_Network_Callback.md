# CORR-013: Persistence Creation + Immediate Network Callback

**Severity:** High  
**MITRE ATT&CK:** T1547.001, T1053.005, T1543.003, T1071  
**Related Base Detections:** DET-013, DET-014, DET-015, DET-020

## Description
New Run key, Scheduled Task, or Service created, followed by outbound connection from related process.

## Correlation Logic
Persistence mechanism written, then near-term outbound connection from the host.

## False Positive Reduction Notes
Software installers often create persistence + check for updates. Focus on unusual paths and rare destinations.

## Microsoft Sentinel / Defender (KQL)
```kql
let persist = DeviceProcessEvents
| where Timestamp > ago(2h)
| where (FileName == "schtasks.exe" and ProcessCommandLine has "/create")
   or (FileName == "sc.exe" and ProcessCommandLine has "create")
   or (ProcessCommandLine has_any ("CurrentVersion\\Run","New-Service","Register-ScheduledTask"))
| project PersistTime=Timestamp, DeviceName, AccountName, PersistCmd=ProcessCommandLine;
DeviceNetworkEvents
| where Timestamp > ago(2h)
| where RemoteIPType == "Public"
| join kind=inner persist on DeviceName
| where Timestamp between (PersistTime .. PersistTime + 30m)
| project Timestamp, DeviceName, AccountName, PersistCmd, RemoteIP, RemotePort, InitiatingProcessFileName
```

## Splunk (SPL)
```spl
index=sysmon (CommandLine="*/create*" Image="*\\schtasks.exe") OR (CommandLine="*create*" Image="*\\sc.exe") earliest=-2h
| join type=inner [
    search index=sysmon EventCode=3 earliest=-2h
    | search DestinationIp!="10.*" DestinationIp!="192.168.*"
]
| table _time, host, CommandLine, DestinationIp
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
