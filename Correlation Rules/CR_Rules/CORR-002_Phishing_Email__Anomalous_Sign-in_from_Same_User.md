# CORR-002: Phishing Email + Anomalous Sign-in from Same User

**Severity:** High  
**MITRE ATT&CK:** T1566, T1078  
**Related Base Detections:** DET-001, DET-002, DET-035

## Description
User received a suspicious phishing-style email and shortly after has a successful sign-in with elevated risk or from a new location.

## Correlation Logic
Identify recipients of suspicious emails, then look for risky or anomalous successful authentications by those users.

## False Positive Reduction Notes
Exclude internal security awareness campaigns. Require risk level medium/high or country change for higher confidence.

## Microsoft Sentinel / Defender (KQL)
```kql
let phishWindow = 24h;
let phishUsers = EmailEvents
| where TimeGenerated > ago(phishWindow)
| where EmailDirection == "Inbound"
| where Subject has_any ("urgent","verify","password","invoice","action required","account")
    or UrlCount > 2
| distinct RecipientEmailAddress;
SigninLogs
| where TimeGenerated > ago(phishWindow)
| where ResultType == "0"
| where UserPrincipalName in (phishUsers)
| where RiskLevelDuringSignIn in ("medium","high")
    or isnotempty(LocationDetails.countryOrRegion)
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName, RiskLevelDuringSignIn, RiskEventTypes
```

## Splunk (SPL)
```spl
index=email OR sourcetype=o365:email earliest=-24h
| search direction=inbound (subject="*urgent*" OR subject="*verify*" OR subject="*invoice*" OR url_count>2)
| fields recipient
| join type=inner [
    search index=azuread ResultType=0 risk_level IN ("medium","high") earliest=-24h
    | fields user, src_ip, location, _time
]
| table _time, user, src_ip, location
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
