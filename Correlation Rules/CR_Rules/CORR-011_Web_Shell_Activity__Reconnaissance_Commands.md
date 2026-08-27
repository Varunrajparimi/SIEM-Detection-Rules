# CORR-011: Web Shell Activity + Reconnaissance Commands

**Severity:** Critical  
**MITRE ATT&CK:** T1505.003, T1033, T1082  
**Related Base Detections:** DET-044

## Description
Web server process spawns a shell, and reconnaissance commands (whoami, net, ipconfig, etc.) are observed.

## Correlation Logic
Web server spawning shell + immediate recon commands = likely web shell usage.

## False Positive Reduction Notes
Very high confidence when both conditions are met on internet-facing servers.

## Microsoft Sentinel / Defender (KQL)
```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName has_any ("w3wp.exe","httpd","nginx","tomcat")
| where FileName in ("cmd.exe","powershell.exe","bash","sh")
| project ShellTime=Timestamp, DeviceName, WebProc=InitiatingProcessFileName, Shell=FileName, ProcessCommandLine
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > ago(24h)
    | where ProcessCommandLine has_any ("whoami","net user","net group","ipconfig","systeminfo","netstat","tasklist")
    | project ReconTime=Timestamp, DeviceName, ReconCmd=ProcessCommandLine
) on DeviceName
| where ReconTime between (ShellTime .. ShellTime + 30m)
| project ShellTime, DeviceName, WebProc, Shell, ProcessCommandLine, ReconCmd
```

## Splunk (SPL)
```spl
index=sysmon ParentImage IN ("*\\w3wp.exe","*httpd*","*nginx*") Image IN ("*\\cmd.exe","*\\powershell.exe") earliest=-24h
| join type=inner [
    search index=sysmon CommandLine IN ("*whoami*","*net user*","*ipconfig*","*systeminfo*") earliest=-24h
]
| table _time, host, ParentImage, Image, CommandLine
```

### Elastic EQL Sequence
```eql
sequence by host.name with maxspan=30m
  [process where process.parent.name : ("w3wp.exe","httpd","nginx") and process.name in ("cmd.exe","powershell.exe","bash")]
  [process where process.command_line : ("*whoami*", "*net user*", "*ipconfig*", "*systeminfo*")]
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
