# CORR-015: Disabled Security Tool + Ransomware Precursor

**Severity:** Critical  
**MITRE ATT&CK:** T1562.001, T1490, T1486  
**Related Base Detections:** DET-027, DET-023, DET-024

## Description
Attempts to disable Defender or security services followed by shadow copy deletion or encryption indicators.

## Correlation Logic
Security tool disablement immediately followed by ransomware preparation commands.

## False Positive Reduction Notes
Extremely high confidence. Almost never legitimate outside of controlled maintenance.

## Microsoft Sentinel / Defender (KQL)
```kql
let disable = DeviceProcessEvents
| where Timestamp > ago(2h)
| where ProcessCommandLine has_any ("Set-MpPreference","DisableRealtimeMonitoring","sc stop WinDefend","sc stop Sense","tamper protection")
| distinct DeviceName;
DeviceProcessEvents
| where Timestamp > ago(2h)
| where DeviceName in (disable)
| where ProcessCommandLine has_any ("vssadmin delete","wmic shadowcopy","bcdedit","wbadmin delete","sc stop vss")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

## Splunk (SPL)
```spl
index=sysmon CommandLine="*Set-MpPreference*" OR CommandLine="*DisableRealtimeMonitoring*" OR CommandLine="*sc stop WinDefend*" earliest=-2h
| stats values(host) as disabled_hosts
| join type=inner [
    search index=sysmon CommandLine="*vssadmin delete*" OR CommandLine="*wmic shadowcopy*" OR CommandLine="*sc stop vss*" earliest=-2h
]
| table _time, host, CommandLine
```

### Elastic EQL Sequence
```eql
sequence by host.name with maxspan=2h
  [process where process.command_line : ("*Set-MpPreference*", "*DisableRealtimeMonitoring*", "*sc stop WinDefend*")]
  [process where process.command_line : ("*vssadmin delete*", "*wmic shadowcopy*", "*sc stop vss*")]
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
