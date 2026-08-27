# CORR-009: C2 Beaconing + Known Bad Process or LOLBin

**Severity:** High  
**MITRE ATT&CK:** T1071, T1218, T1059  
**Related Base Detections:** DET-020, DET-022, DET-047

## Description
Periodic outbound connections correlated with LOLBin or scripting process as the initiator.

## Correlation Logic
Repeated outbound connections from LOLBins/script hosts over time, indicating possible C2.

## False Positive Reduction Notes
Baseline normal beaconing intervals of legitimate software. Focus on rare destinations + LOLBin combination.

## Microsoft Sentinel / Defender (KQL)
```kql
DeviceNetworkEvents
| where Timestamp > ago(6h)
| where RemoteIPType == "Public"
| where InitiatingProcessFileName in ("powershell.exe","wscript.exe","mshta.exe","rundll32.exe","certutil.exe","bitsadmin.exe")
| summarize ConnCount=count(), Ports=make_set(RemotePort) by DeviceName, RemoteIP, InitiatingProcessFileName, bin(Timestamp, 5m)
| where ConnCount >= 3
| summarize BeaconCount=count(), TotalConns=sum(ConnCount) by DeviceName, RemoteIP, InitiatingProcessFileName
| where BeaconCount >= 4
```

## Splunk (SPL)
```spl
index=sysmon EventCode=3 Image IN ("*\\powershell.exe","*\\mshta.exe","*\\rundll32.exe","*\\certutil.exe") earliest=-6h
| search DestinationIp!="10.*" DestinationIp!="192.168.*"
| stats count as conns by host, DestinationIp, Image, _time span=5m
| where conns >= 3
| stats dc(_time) as intervals, sum(conns) as total by host, DestinationIp, Image
| where intervals >= 4
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
