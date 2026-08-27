# CORR-005: Risky Sign-in + New Inbox Rule (BEC Pattern)

**Severity:** Critical  
**MITRE ATT&CK:** T1078, T1114.003  
**Related Base Detections:** DET-003, DET-035, DET-043

## Description
Anomalous or high-risk sign-in followed by creation of a new inbox rule (forwarding, deletion, or move). Classic Business Email Compromise post-exploitation.

## Correlation Logic
High-risk authentication → subsequent mailbox rule creation by the same user.

## False Positive Reduction Notes
Exclude legitimate admin activity and known migration tools. Focus on non-admin users and external ClientIP.

## Microsoft Sentinel / Defender (KQL)
```kql
let riskyUsers = SigninLogs
| where TimeGenerated > ago(48h)
| where ResultType == "0"
| where RiskLevelDuringSignIn in ("medium","high")
| project UserPrincipalName, SignInTime = TimeGenerated, IPAddress;
OfficeActivity
| where TimeGenerated > ago(48h)
| where Operation in ("New-InboxRule","Set-InboxRule","UpdateInboxRules")
| join kind=inner riskyUsers on $left.UserId == $right.UserPrincipalName
| where TimeGenerated > SignInTime and TimeGenerated < SignInTime + 12h
| project TimeGenerated, UserId, ClientIP, Operation, SignInTime, IPAddress
```

## Splunk (SPL)
```spl
index=azuread ResultType=0 risk_level IN ("medium","high") earliest=-48h
| fields user, _time as signin_time, src_ip
| join type=inner [
    search index=o365 Operation IN ("New-InboxRule","Set-InboxRule") earliest=-48h
    | fields user, client_ip, Operation, _time
]
| where _time > signin_time
| table _time, user, client_ip, Operation, signin_time
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
