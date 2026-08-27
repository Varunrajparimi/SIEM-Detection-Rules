# DET-027: Disable Windows Defender / Security Tools

**Category:** Defense Evasion  
**Severity:** High  
**MITRE ATT&CK:** T1562.001  
**Tags:** attack.defense_evasion, attack.t1562.001

## Description
Attempts to disable real-time protection, exclude paths, or stop security services.

## Microsoft Sentinel / Defender XDR (KQL)
```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where ProcessCommandLine has_any (
    "Set-MpPreference","DisableRealtimeMonitoring","ExclusionPath",
    "sc stop WinDefend","sc config WinDefend","tamper protection"
)
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

## Splunk (SPL)
```spl
index=sysmon
| search CommandLine="*Set-MpPreference*" OR CommandLine="*DisableRealtimeMonitoring*" OR CommandLine="*sc stop WinDefend*"
| table _time, host, user, CommandLine
```

### Elastic EQL / ES|QL
```eql
process where process.command_line : ("*Set-MpPreference*", "*DisableRealtimeMonitoring*", "*sc stop WinDefend*")
```

## Implementation Notes
- Tune thresholds (counts, time windows) to your environment baseline.
- Add allow-lists for known admin tools, scanners, and service accounts.
- Correlate with EDR alerts for higher fidelity.
- Test in detection-only mode before enabling alerting.
- Map to your Automated IR Playbooks (AIR-xxx) for response.

## Data Sources Required
- Microsoft: SigninLogs, SecurityEvent, DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, EmailEvents, AuditLogs, DeviceRegistryEvents
- Splunk: windows, sysmon, azuread, o365, firewall, proxy, email indexes
- Elastic: process, network, authentication, file, registry events (Endpoint / Winlogbeat / Sysmon)

---
*Generated for blank SIEM + EDR environments. Customize entity names, thresholds, and exclusions.*
