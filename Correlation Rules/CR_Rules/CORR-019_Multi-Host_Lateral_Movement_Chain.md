# CORR-019: Multi-Host Lateral Movement Chain

**Severity:** High  
**MITRE ATT&CK:** T1021, T1078  
**Related Base Detections:** DET-018, DET-016, DET-051

## Description
Same account authenticates successfully to multiple hosts in a short period using remote logon types (potential lateral movement chain).

## Correlation Logic
One account successfully authenticating to many hosts in a short window via network/RDP logon types.

## False Positive Reduction Notes
Jump servers, software distribution, and admin accounts need careful allow-listing or separate baselining.

## Microsoft Sentinel / Defender (KQL)
```kql
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4624 and LogonType in (3,10)
| summarize DistinctHosts=dcount(Computer), Hosts=make_set(Computer,10), Logons=count() by TargetUserName, IpAddress, bin(TimeGenerated, 30m)
| where DistinctHosts >= 4
| sort by DistinctHosts desc
```

## Splunk (SPL)
```spl
index=windows EventCode=4624 Logon_Type IN (3,10) earliest=-1h
| stats dc(Computer) as hosts, values(Computer) as host_list, count as logons by TargetUserName, src_ip, _time span=30m
| where hosts >= 4
| sort -hosts
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
