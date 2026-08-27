# CORR-017: LOLBin Download + Immediate Execution of Dropped File

**Severity:** High  
**MITRE ATT&CK:** T1105, T1204, T1218  
**Related Base Detections:** DET-012, DET-038, DET-019

## Description
certutil/bitsadmin/mshta downloads a file, followed by execution of a new binary from Temp/Downloads/AppData.

## Correlation Logic
LOLBin used for download, followed by execution of newly dropped content.

## False Positive Reduction Notes
Some software updaters use these patterns. Focus on unsigned or rare hashes when possible.

## Microsoft Sentinel / Defender (KQL)
```kql
let downloads = DeviceProcessEvents
| where Timestamp > ago(2h)
| where FileName in ("certutil.exe","bitsadmin.exe","mshta.exe")
| where ProcessCommandLine has_any ("http://","https://","-urlcache","/transfer","/download")
| project DLTime=Timestamp, DeviceName, AccountName, DLCmd=ProcessCommandLine;
DeviceProcessEvents
| where Timestamp > ago(2h)
| where FolderPath has_any (@"\Temp\",@"\Downloads\",@"\AppData\Local\Temp\")
| where FileName endswith ".exe" or FileName endswith ".dll" or FileName endswith ".js"
| join kind=inner downloads on DeviceName
| where Timestamp between (DLTime .. DLTime + 20m)
| project Timestamp, DeviceName, AccountName, DLCmd, FileName, FolderPath, ProcessCommandLine
```

## Splunk (SPL)
```spl
index=sysmon Image IN ("*\\certutil.exe","*\\bitsadmin.exe","*\\mshta.exe") CommandLine="*http*" earliest=-2h
| join type=inner [
    search index=sysmon EventCode=1 (Image="*\\Temp\\*" OR Image="*\\Downloads\\*") earliest=-2h
]
| table _time, host, CommandLine, Image
```

### Elastic EQL Sequence
```eql
sequence by host.name with maxspan=20m
  [process where process.name in ("certutil.exe","bitsadmin.exe","mshta.exe") and process.command_line : "*http*"]
  [process where process.executable : ("*\\Temp\\*", "*\\Downloads\\*") and process.name : ("*.exe","*.dll")]
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
