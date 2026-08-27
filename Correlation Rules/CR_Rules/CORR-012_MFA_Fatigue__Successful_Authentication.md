# CORR-012: MFA Fatigue + Successful Authentication

**Severity:** High  
**MITRE ATT&CK:** T1621, T1078  
**Related Base Detections:** DET-036

## Description
Multiple MFA push failures/denials followed by a successful authentication for the same user.

## Correlation Logic
Repeated MFA denials followed by successful login – possible MFA fatigue success.

## False Positive Reduction Notes
Users occasionally deny legitimate pushes. Require ≥5 failures and success within short window.

## Microsoft Sentinel / Defender (KQL)
```kql
let mfaFatigue = SigninLogs
| where TimeGenerated > ago(2h)
| where ResultType in ("500121","50074","50158") or Status.errorCode in (500121,50074)
| summarize MFAFailures=count() by UserPrincipalName, bin(TimeGenerated, 20m)
| where MFAFailures >= 5
| project UserPrincipalName, FatigueTime=TimeGenerated;
SigninLogs
| where TimeGenerated > ago(2h)
| where ResultType == "0"
| join kind=inner mfaFatigue on UserPrincipalName
| where TimeGenerated between (FatigueTime .. FatigueTime + 30m)
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName, FatigueTime
```

## Splunk (SPL)
```spl
index=azuread (ResultType=500121 OR ResultType=50074) earliest=-2h
| stats count as mfa_fails by user, _time span=20m
| where mfa_fails >= 5
| join type=inner [search index=azuread ResultType=0 earliest=-2h | fields user, src_ip, _time]
| table _time, user, src_ip, mfa_fails
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
