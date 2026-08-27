# CORR-003: Shadow Copy Deletion + Mass File Encryption Behavior

**Severity:** Critical  
**MITRE ATT&CK:** T1490, T1486  
**Related Base Detections:** DET-023, DET-024, DET-025, DET-053

## Description
Classic ransomware kill-chain correlation: volume shadow copy deletion followed by high volume of file modifications/renames on the same host.

## Correlation Logic
First detect VSS/shadow copy destruction, then look for rapid file system activity on the same host.

## False Positive Reduction Notes
Almost never benign on production servers. Allow-list only known backup/VSS maintenance accounts during approved windows.

## Microsoft Sentinel / Defender (KQL)
```kql
let vssHosts = DeviceProcessEvents
| where Timestamp > ago(2h)
| where ProcessCommandLine has_any ("vssadmin delete shadows","wmic shadowcopy delete","bcdedit /set","wbadmin delete","sc stop vss")
| distinct DeviceName;
DeviceFileEvents
| where Timestamp > ago(2h)
| where DeviceName in (vssHosts)
| where ActionType in ("FileCreated","FileRenamed","FileModified")
| summarize FileOps = count() by DeviceName, InitiatingProcessFileName, bin(Timestamp, 5m)
| where FileOps > 80
| sort by FileOps desc
```

## Splunk (SPL)
```spl
index=sysmon earliest=-2h
| search CommandLine="*vssadmin delete shadows*" OR CommandLine="*wmic shadowcopy delete*" OR CommandLine="*sc stop vss*"
| stats values(host) as vss_hosts
| join type=inner [
    search index=sysmon EventCode IN (11,2) earliest=-2h
    | stats count as file_ops by host, Image, _time span=5m
    | where file_ops > 80
]
| table _time, host, Image, file_ops
```

### Elastic EQL Sequence
```eql
sequence by host.name with maxspan=2h
  [process where process.command_line : ("*vssadmin delete shadows*", "*wmic shadowcopy delete*", "*sc stop vss*")]
  [file where event.action in ("creation","rename","change")] with runs=50
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
