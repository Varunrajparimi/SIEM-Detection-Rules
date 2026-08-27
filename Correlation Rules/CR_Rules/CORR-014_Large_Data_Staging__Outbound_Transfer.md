# CORR-014: Large Data Staging + Outbound Transfer

**Severity:** High  
**MITRE ATT&CK:** T1074, T1041, T1560  
**Related Base Detections:** DET-031, DET-032

## Description
High volume of archive file creation (zip/rar/7z) followed by large outbound network transfer from the same host.

## Correlation Logic
Archive/staging activity correlated with subsequent large outbound data volume.

## False Positive Reduction Notes
Backup jobs and legitimate data transfers. Correlate with unusual hours or non-backup accounts.

## Microsoft Sentinel / Defender (KQL)
```kql
let staging = DeviceFileEvents
| where Timestamp > ago(6h)
| where FileName endswith ".zip" or FileName endswith ".rar" or FileName endswith ".7z" or FileName endswith ".tar"
| summarize ArchiveCount=count() by DeviceName, InitiatingProcessAccountName, bin(Timestamp, 1h)
| where ArchiveCount >= 5
| project DeviceName, Account=InitiatingProcessAccountName, StageTime=Timestamp;
DeviceNetworkEvents
| where Timestamp > ago(6h)
| where RemoteIPType == "Public"
| summarize TotalBytes=sum(SentBytes) by DeviceName, bin(Timestamp, 1h)
| where TotalBytes > 30000000
| join kind=inner staging on DeviceName
| project Timestamp, DeviceName, TotalBytes, Account, StageTime
```

## Splunk (SPL)
```spl
index=sysmon EventCode=11 (TargetFilename="*.zip" OR TargetFilename="*.rar" OR TargetFilename="*.7z") earliest=-6h
| stats count as archives by host, user, _time span=1h
| where archives >= 5
| join type=inner [
    search index=firewall OR index=proxy earliest=-6h
    | stats sum(bytes_out) as total_bytes by src_ip, _time span=1h
    | where total_bytes > 30000000
]
| table _time, host, user, archives, total_bytes
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
