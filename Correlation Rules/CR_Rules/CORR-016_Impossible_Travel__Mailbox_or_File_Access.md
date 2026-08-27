# CORR-016: Impossible Travel + Mailbox or File Access

**Severity:** High  
**MITRE ATT&CK:** T1078, T1114, T1005  
**Related Base Detections:** DET-035

## Description
Impossible travel / anomalous sign-in correlated with subsequent mailbox access or sensitive file operations.

## Correlation Logic
Impossible travel sign-in pattern + subsequent access to mail or files.

## False Positive Reduction Notes
VPN and cloud app usage can cause false travel alerts. Require additional activity for confidence.

## Microsoft Sentinel / Defender (KQL)
```kql
let travel = SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == "0"
| extend Country = tostring(LocationDetails.countryOrRegion)
| summarize Countries=make_set(Country), First=min(TimeGenerated), Last=max(TimeGenerated) by UserPrincipalName
| where array_length(Countries) > 1
| extend Minutes=datetime_diff('minute', Last, First)
| where Minutes < 180
| project UserPrincipalName, Countries, First, Last;
OfficeActivity
| where TimeGenerated > ago(24h)
| where Operation has_any ("MailItemsAccessed","FileSyncDownloadedFull","FileAccessed","FileDownloaded")
| join kind=inner travel on $left.UserId == $right.UserPrincipalName
| where TimeGenerated between (First .. Last + 2h)
| project TimeGenerated, UserId, Operation, Countries
```

## Splunk (SPL)
```spl
index=azuread ResultType=0 earliest=-24h
| stats values(country) as countries, earliest(_time) as first, latest(_time) as last by user
| where mvcount(countries) > 1
| join type=inner [search index=o365 Operation IN ("MailItemsAccessed","FileAccessed","FileDownloaded") earliest=-24h | fields user, Operation, _time]
| table _time, user, Operation, countries
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
