# CORR-018: Clear Event Logs + Prior Suspicious Activity

**Severity:** High  
**MITRE ATT&CK:** T1070.001, T1003, T1059  
**Related Base Detections:** DET-026, DET-041, DET-007, DET-009

## Description
Event log clearing occurs on a host that recently exhibited credential access, lateral movement, or encoded PowerShell.

## Correlation Logic
Prior attack-stage activity on a host, followed by log clearing (anti-forensics).

## False Positive Reduction Notes
Log clearing alone can be admin activity. Correlation with prior attack techniques greatly increases confidence.

## Microsoft Sentinel / Defender (KQL)
```kql
let suspicious = DeviceProcessEvents
| where Timestamp > ago(6h)
| where ProcessCommandLine has_any ("-EncodedCommand","mimikatz","procdump","vssadmin","psexec","Invoke-WmiMethod")
    or FileName in ("mimikatz.exe","procdump.exe","psexec.exe")
| distinct DeviceName;
SecurityEvent
| where TimeGenerated > ago(6h)
| where EventID in (1102, 104)
| where Computer in (suspicious)
| project TimeGenerated, Computer, Account, EventID
| union (
    DeviceProcessEvents
    | where Timestamp > ago(6h)
    | where FileName =~ "wevtutil.exe" and ProcessCommandLine has_any ("cl ","clear-log")
    | where DeviceName in (suspicious)
    | project TimeGenerated=Timestamp, Computer=DeviceName, Account=AccountName, EventID=0
)
```

## Splunk (SPL)
```spl
index=sysmon (CommandLine="*-EncodedCommand*" OR CommandLine="*mimikatz*" OR CommandLine="*psexec*") earliest=-6h
| stats values(host) as susp_hosts
| join type=inner [
    search index=windows EventCode IN (1102,104) OR (index=sysmon Image="*\\wevtutil.exe" CommandLine="*cl *") earliest=-6h
]
| table _time, host, EventCode, CommandLine
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
