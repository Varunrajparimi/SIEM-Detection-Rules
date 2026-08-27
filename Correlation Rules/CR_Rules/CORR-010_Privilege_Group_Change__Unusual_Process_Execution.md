# CORR-010: Privilege Group Change + Unusual Process Execution

**Severity:** Critical  
**MITRE ATT&CK:** T1098, T1078, T1059  
**Related Base Detections:** DET-033, DET-009

## Description
Account added to a privileged group, followed by suspicious process activity under that account.

## Correlation Logic
Privileged group membership change correlated with subsequent high-risk process execution by that account.

## False Positive Reduction Notes
Change control windows and known IAM automation should be excluded.

## Microsoft Sentinel / Defender (KQL)
```kql
let privAdds = AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName has_any ("Add member to role","Add member to group")
| extend Target = tostring(TargetResources[0].userPrincipalName)
| extend Group = tostring(TargetResources[0].displayName)
| where Group has_any ("Global Administrator","Domain Admins","Enterprise Admins","Administrators")
| project AddTime=TimeGenerated, Target, Group;
DeviceProcessEvents
| where Timestamp > ago(24h)
| where ProcessCommandLine has_any ("-EncodedCommand","mimikatz","procdump","IEX","DownloadString","vssadmin")
| join kind=inner privAdds on $left.AccountName == $right.Target
| where Timestamp > AddTime
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, Group, AddTime
```

## Splunk (SPL)
```spl
index=windows EventCode IN (4728,4732) OR index=azuread OperationName="*Add member*" earliest=-24h
| fields user, group, _time as add_time
| join type=inner [
    search index=sysmon (CommandLine="*-EncodedCommand*" OR CommandLine="*mimikatz*" OR CommandLine="*vssadmin*") earliest=-24h
    | fields user, host, CommandLine, _time
]
| where _time > add_time
| table _time, user, host, CommandLine, group
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
