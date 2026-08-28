# DET-001: Phishing Email with Suspicious URL or Attachment

**Category:** Initial Access  
**Severity:** Medium  
**MITRE ATT&CK:** T1566, T1566.001, T1566.002  
**Tags:** attack.initial_access, attack.t1566

## Description
Detects inbound emails containing suspicious URLs, known phishing keywords, or high-risk attachments.

## Microsoft Sentinel / Defender XDR (KQL)
```kql
EmailEvents
| where TimeGenerated > ago(1h)
| where EmailDirection == "Inbound"
| where Subject has_any ("urgent", "verify", "password", "invoice", "action required", "account suspended")
   or UrlCount > 0
   or AttachmentCount > 0
| where SenderFromDomain !endswith ".yourdomain.com"
| project TimeGenerated, SenderFromAddress, RecipientEmailAddress, Subject, UrlCount, AttachmentCount, ThreatTypes
```

## Splunk (SPL)
```spl
index=email OR sourcetype=o365:email
| search direction=inbound
| search subject IN ("*urgent*", "*verify*", "*password*", "*invoice*", "*action required*") OR url_count>0 OR attachment_count>0
| table _time, sender, recipient, subject, url_count, attachment_count
```

### Elastic EQL / ES|QL
```eql
// Elastic - Email events (adjust index)
any where event.dataset == "email" and email.direction == "inbound" and
  (email.subject : ("*urgent*" or "*verify*" or "*invoice*") or email.url_count > 0)
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
*Created for blank SIEM + EDR environments. Customize entity names, thresholds, and exclusions.*
