# CORR-004: LSASS Access + Subsequent Lateral Movement

**Severity:** Critical  
**MITRE ATT&CK:** T1003.001, T1021  
**Related Base Detections:** DET-007, DET-008, DET-016, DET-017

## Description
Credential dumping activity (LSASS access or known tools) followed by remote logon or PsExec/WMI activity from the same host or account.

## Correlation Logic
Detect credential access, then look for lateral movement tools or remote execution from the same context.

## False Positive Reduction Notes
Exclude EDR/AV processes and known security tools. Focus on non-system accounts.

## Microsoft Sentinel / Defender (KQL)
```kql
let dumpHosts = DeviceEvents
| where Timestamp > ago(2h)
| where (ActionType has "ProcessAccessed" and FileName =~ "lsass.exe")
    or (ProcessCommandLine has_any ("mimikatz","sekurlsa","procdump","MiniDump","nanodump"))
| where InitiatingProcessFileName !in ("csrss.exe","wininit.exe","MsMpEng.exe","MsSense.exe")
| distinct DeviceName, AccountName = InitiatingProcessAccountName;
DeviceProcessEvents
| where Timestamp > ago(2h)
| where FileName in ("psexec.exe","psexec64.exe","wmic.exe","sc.exe")
    or ProcessCommandLine has_any ("/node:","Invoke-WmiMethod","-ComputerName","Enter-PSSession")
| where DeviceName in (dumpHosts) or AccountName in (dumpHosts)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

## Splunk (SPL)
```spl
index=sysmon earliest=-2h
| search (TargetImage="*\\lsass.exe" EventCode=10) OR CommandLine="*mimikatz*" OR CommandLine="*procdump*lsass*"
| stats values(host) as dump_hosts, values(user) as dump_users
| join [
    search index=sysmon (Image="*\\psexec.exe" OR CommandLine="*/node:*" OR CommandLine="*Invoke-WmiMethod*") earliest=-2h
]
| table _time, host, user, Image, CommandLine
```

### Elastic EQL Sequence
```eql
sequence by host.name with maxspan=2h
  [process where process.name == "lsass.exe" or process.command_line : ("*mimikatz*", "*procdump*")]
  [process where process.name in ("psexec.exe","wmic.exe") or process.command_line : ("*/node:*", "*Invoke-WmiMethod*")]
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
