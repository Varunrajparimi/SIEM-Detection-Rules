# CORR-001: Password Spray Followed by Successful Authentication

**Severity:** Critical  
**MITRE ATT&CK:** T1110.003, T1078  
**Related Base Detections:** DET-004, DET-005

## Description
High-fidelity correlation: multiple failed logons against many users from one IP, followed by a successful logon from the same IP. Strong indicator of successful password spray.

## Correlation Logic
Stage 1: Identify IPs with high distinct-user failures. Stage 2: Successful auth from those IPs within 1 hour.

## False Positive Reduction Notes
Exclude known vulnerability scanners, password audit tools, and service accounts. Tune DistinctUsers and time window to environment size.

## Microsoft Sentinel / Defender (KQL)
```kql
let lookback = 2h;
let sprayWindow = 30m;
let sprayIPs = SigninLogs
| where TimeGenerated > ago(lookback)
| where ResultType in ("50126","50053","50055","50056")
| summarize DistinctUsers = dcount(UserPrincipalName), Failures = count() by IPAddress, bin(TimeGenerated, sprayWindow)
| where DistinctUsers >= 12 and Failures >= 20
| project SprayIP = IPAddress, SprayTime = TimeGenerated;
SigninLogs
| where TimeGenerated > ago(lookback)
| where ResultType == "0"
| join kind=inner sprayIPs on $left.IPAddress == $right.SprayIP
| where TimeGenerated between (SprayTime .. SprayTime + 1h)
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName, SprayTime, ResultType
| sort by TimeGenerated desc
```

## Splunk (SPL)
```spl
index=azuread OR index=windows earliest=-2h
| eval is_fail=if(ResultType!=0 OR EventCode=4625,1,0)
| eval is_success=if(ResultType=0 OR EventCode=4624,1,0)
| stats dc(user) as users, sum(is_fail) as fails, sum(is_success) as successes by src_ip, _time span=30m
| where users>=12 AND fails>=20
| join type=inner [
    search index=azuread ResultType=0 OR index=windows EventCode=4624 earliest=-2h
    | fields src_ip, user, _time
] 
| where _time >= relative_time(_time,"-1h@h")
| table _time, user, src_ip, users, fails
```

### Elastic EQL Sequence
```eql
sequence by source.ip with maxspan=1h
  [authentication where event.outcome == "failure"] with runs=15
  [authentication where event.outcome == "success"]
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
