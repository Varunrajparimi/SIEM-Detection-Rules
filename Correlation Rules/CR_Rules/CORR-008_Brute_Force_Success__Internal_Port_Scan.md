# CORR-008: Brute Force Success + Internal Port Scan

**Severity:** Critical  
**MITRE ATT&CK:** T1110, T1046, T1021  
**Related Base Detections:** DET-006, DET-029, DET-055

## Description
Successful authentication after failures, followed by the same host performing internal network scanning.

## Correlation Logic
Failed then successful logon, followed by high-port/host scanning from the compromised host.

## False Positive Reduction Notes
Exclude vulnerability management scanners and known admin jump hosts.

## Microsoft Sentinel / Defender (KQL)
```kql
let successAfterFail = SecurityEvent
| where TimeGenerated > ago(2h)
| where EventID == 4625
| summarize Failures=count() by TargetUserName, IpAddress
| where Failures >= 8
| join kind=inner (
    SecurityEvent
    | where TimeGenerated > ago(2h)
    | where EventID == 4624 and LogonType in (3,10)
    | project SuccessTime=TimeGenerated, TargetUserName, IpAddress, Computer
) on TargetUserName, IpAddress;
DeviceNetworkEvents
| where Timestamp > ago(2h)
| where RemoteIPType == "Private"
| summarize DistinctPorts=dcount(RemotePort), DistinctIPs=dcount(RemoteIP) by DeviceName, bin(Timestamp, 10m)
| where DistinctPorts > 40 or DistinctIPs > 20
| join kind=inner successAfterFail on $left.DeviceName == $right.Computer
```

## Splunk (SPL)
```spl
index=windows EventCode=4625 earliest=-2h
| stats count as fails by TargetUserName, src_ip
| where fails >= 8
| join type=inner [search index=windows EventCode=4624 Logon_Type IN (3,10) earliest=-2h | fields TargetUserName, src_ip, Computer, _time]
| join type=inner [
    search index=firewall OR index=sysmon EventCode=3 earliest=-2h
    | stats dc(dest_port) as ports, dc(dest_ip) as hosts by src_ip, _time span=10m
    | where ports>40 OR hosts>20
]
| table _time, TargetUserName, src_ip, Computer, ports, hosts
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
