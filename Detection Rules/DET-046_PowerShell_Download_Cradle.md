# DET-046: PowerShell Download Cradle

**Category:** Execution  
**Severity:** High  
**MITRE ATT&CK:** T1059.001, T1105  
**Tags:** attack.execution, attack.t1059.001

## Description
PowerShell using Net.WebClient, Invoke-WebRequest, or curl to download remote content.

## Microsoft Sentinel / Defender XDR (KQL)
```kql
DeviceProcessEvents
| where Timestamp > ago(1h)
| where FileName in ("powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any ("Net.WebClient","DownloadString","DownloadFile","Invoke-WebRequest","IWR","curl ","wget ")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

## Splunk (SPL)
```spl
index=sysmon Image="*\\powershell.exe"
| search CommandLine="*Net.WebClient*" OR CommandLine="*DownloadString*" OR CommandLine="*Invoke-WebRequest*" OR CommandLine="*IWR*"
| table _time, host, user, CommandLine
```

### Elastic EQL / ES|QL
```eql
process where process.name in ("powershell.exe","pwsh.exe") and
  process.command_line : ("*Net.WebClient*", "*DownloadString*", "*Invoke-WebRequest*", "*IWR*")
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
