# Detection Rule Index

| ID | Title | Severity | Category | MITRE |
|----|-------|----------|----------|-------|
| DET-001 | Phishing Email with Suspicious URL or Attachment | Medium | Initial Access | T1566, T1566.001, T1566.002 |
| DET-002 | Successful Sign-in After Phishing Click | High | Initial Access | T1566, T1078 |
| DET-003 | New Inbox Rule After Suspicious Sign-in | High | Collection | T1114.003, T1078 |
| DET-004 | Password Spray Detection | High | Credential Access | T1110.003 |
| DET-005 | Successful Login After Password Spray | Critical | Credential Access | T1110.003, T1078 |
| DET-006 | RDP Brute Force | High | Credential Access | T1110, T1021.001 |
| DET-007 | LSASS Memory Access / Credential Dumping | Critical | Credential Access | T1003.001 |
| DET-008 | Known Credential Dumping Tools | Critical | Credential Access | T1003.001 |
| DET-009 | Encoded PowerShell Command | High | Execution | T1059.001 |
| DET-010 | Office Application Spawning Scripting Engine | High | Execution | T1204.002, T1059 |
| DET-011 | Suspicious MSHTA Execution | High | Defense Evasion | T1218.005 |
| DET-012 | Certutil Download or Decode | High | Command and Control | T1105, T1140 |
| DET-013 | Registry Run Key Persistence | Medium | Persistence | T1547.001 |
| DET-014 | Suspicious Scheduled Task Creation | High | Persistence | T1053.005 |
| DET-015 | New Windows Service Creation | Medium | Persistence | T1543.003 |
| DET-016 | PsExec or Remote Service Execution | High | Lateral Movement | T1021.002, T1569.002 |
| DET-017 | WMI Remote Process Creation | High | Lateral Movement | T1047 |
| DET-018 | Unusual RDP Logon | Medium | Lateral Movement | T1021.001 |
| DET-019 | SMB Administrative Share Access | Medium | Lateral Movement | T1021.002 |
| DET-020 | Suspicious Outbound from Scripting Processes | High | Command and Control | T1071, T1059 |
| DET-021 | DNS Tunneling Indicators | High | Command and Control | T1071.004 |
| DET-022 | Periodic Beaconing Behavior | Medium | Command and Control | T1071 |
| DET-023 | Shadow Copy Deletion (Ransomware Prep) | Critical | Impact | T1490 |
| DET-024 | Ransomware Note or Mass File Encryption Indicators | Critical | Impact | T1486 |
| DET-025 | Mass File Modification / Encryption Behavior | Critical | Impact | T1486 |
| DET-026 | Windows Event Log Clearing | High | Defense Evasion | T1070.001 |
| DET-027 | Disable Windows Defender / Security Tools | High | Defense Evasion | T1562.001 |
| DET-028 | Process Injection Indicators | High | Defense Evasion | T1055 |
| DET-029 | Network / Port Scanning from Internal Host | Medium | Discovery | T1046 |
| DET-030 | AdFind or BloodHound Style Enumeration | High | Discovery | T1087, T1069, T1482 |
| DET-031 | Large Outbound Data Transfer | High | Exfiltration | T1041, T1048 |
| DET-032 | Cloud Storage Upload from Unusual Process | Medium | Exfiltration | T1567.002 |
| DET-033 | Addition to Privileged Group | Critical | Privilege Escalation | T1098, T1078 |
| DET-034 | UAC Bypass Indicators | High | Privilege Escalation | T1548.002 |
| DET-035 | Impossible Travel / Anomalous Sign-in | High | Initial Access | T1078 |
| DET-036 | MFA Fatigue / Repeated MFA Push Failures | High | Credential Access | T1621 |
| DET-037 | Suspicious WScript / CScript Execution | Medium | Execution | T1059.005, T1059.007 |
| DET-038 | Bitsadmin Download | High | Command and Control | T1197, T1105 |
| DET-039 | Rundll32 Suspicious Execution | High | Defense Evasion | T1218.011 |
| DET-040 | Suspicious Service Binary Path | High | Persistence | T1543.003 |
| DET-041 | Clear Event Logs via PowerShell | High | Defense Evasion | T1070.001 |
| DET-042 | Suspicious Parent-Child: Explorer Spawning Script | Medium | Execution | T1059 |
| DET-043 | Token Theft / Anomalous Token Usage | High | Credential Access | T1528, T1550 |
| DET-044 | Web Shell Indicators on Server | Critical | Persistence | T1505.003 |
| DET-045 | Suspicious File Creation in Startup Folders | Medium | Persistence | T1547.001 |
| DET-046 | PowerShell Download Cradle | High | Execution | T1059.001, T1105 |
| DET-047 | Suspicious Network Connection from LOLBin | High | Command and Control | T1218, T1105 |
| DET-048 | Domain Trust Enumeration | Medium | Discovery | T1482 |
| DET-049 | Local Account Creation | Medium | Persistence | T1136.001 |
| DET-050 | Suspicious Scheduled Task – System Privileges | High | Persistence | T1053.005 |
| DET-051 | PowerShell Remoting / WinRM Lateral Movement | High | Lateral Movement | T1021.006 |
| DET-052 | Suspicious Outbound Connection to Rare Port | Medium | Command and Control | T1071 |
| DET-053 | Ransomware – Volume Shadow Copy Service Stop | Critical | Impact | T1490 |
| DET-054 | Suspicious DLL Side-Loading Pattern | High | Defense Evasion | T1574.002 |
| DET-055 | Successful Brute Force Followed by Lateral Movement | Critical | Lateral Movement | T1110, T1021 |
