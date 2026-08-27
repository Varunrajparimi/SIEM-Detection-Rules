# CORR-020: Ransomware Full Kill Chain Correlation

**Severity:** Critical  
**MITRE ATT&CK:** T1486, T1490, T1003, T1078  
**Related Base Detections:** DET-023, DET-024, DET-025, DET-007, DET-053

## Description
Multi-stage correlation: initial access indicators + credential access + shadow copy deletion + mass file operations. Highest confidence ransomware alert.

## Correlation Logic
Requires evidence of at least two ransomware kill-chain stages on the same host for critical alert.

## False Positive Reduction Notes
Designed for maximum precision. Require at least two stages before alerting.

## Microsoft Sentinel / Defender (KQL)
```kql
let stage1 = DeviceProcessEvents
| where Timestamp > ago(6h)
| where ProcessCommandLine has_any ("vssadmin delete","wmic shadowcopy","bcdedit /set","sc stop vss","wbadmin delete")
| distinct DeviceName;
let stage2 = DeviceFileEvents
| where Timestamp > ago(6h)
| where ActionType in ("FileCreated","FileRenamed")
| summarize ops=count() by DeviceName, bin(Timestamp, 10m)
| where ops > 100
| distinct DeviceName;
let stage3 = DeviceEvents
| where Timestamp > ago(6h)
| where ActionType has "ProcessAccessed" and FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in ("csrss.exe","MsMpEng.exe","MsSense.exe")
| distinct DeviceName;
union (stage1 | extend Stage="VSS"), (stage2 | extend Stage="FileOps"), (stage3 | extend Stage="LSASS")
| summarize Stages=make_set(Stage), StageCount=dcount(Stage) by DeviceName
| where StageCount >= 2
| sort by StageCount desc
```

## Splunk (SPL)
```spl
index=sysmon earliest=-6h
| eval stage=case(
    match(CommandLine,"vssadmin delete|wmic shadowcopy|sc stop vss"), "VSS",
    EventCode IN (11,2), "FileOps",
    TargetImage="*\\lsass.exe" AND EventCode=10, "LSASS",
    true(), null())
| where isnotnull(stage)
| stats dc(stage) as stages, values(stage) as stage_list by host
| where stages >= 2
| table host, stages, stage_list
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
