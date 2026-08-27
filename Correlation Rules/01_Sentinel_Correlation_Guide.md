# Step-by-Step: Creating Correlation Rules in Microsoft Sentinel

## Prerequisites
- Log Analytics workspace with required tables (SigninLogs, SecurityEvent, DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, EmailEvents, OfficeActivity, AuditLogs, etc.)
- Microsoft Sentinel enabled
- Appropriate RBAC (Security Reader + Logic App contributor if automating)

## Method 1: Scheduled Analytics Rule (Recommended for most CORR rules)

1. In Sentinel → **Analytics** → **+ Create** → **Scheduled query rule**
2. **General** tab:
   - Name: use the CORR-ID + short title (e.g., CORR-001 Password Spray + Success)
   - Description: paste the rule description
   - Tactics & Techniques: select the MITRE tactics listed in the rule
   - Severity: High or Critical as specified
3. **Set rule logic** tab:
   - Rule query: paste the full KQL from the rule file
   - Run query every: 5–15 minutes (match the tightest window in the query)
   - Lookup data from the last: equal or slightly larger than the lookback in the query (e.g., 2h–6h)
   - Event grouping: usually “Trigger an alert for each event” or group by DeviceName / UserPrincipalName
4. **Incident settings**:
   - Create incidents: Enabled
   - Alert grouping: group by entities (Account, Host, IP) when appropriate
5. **Automated response** (optional):
   - Attach an Automation rule or Playbook (link to your AIR-xxx Automated IR Playbooks)
6. **Review + Create**

### Tips for Correlation Queries in Sentinel
- Always use `let` statements for intermediate result sets
- Keep time windows as tight as possible for performance
- Test the query in **Logs** blade first with a shorter lookback
- Use **Watchlists** for allow-lists (scanners, admin hosts, service accounts)
- Entity mapping: map Account, Host, IPAddress so incidents are rich

## Method 2: NRT (Near-Real-Time) Rule
Use only for very high-volume, simple correlations that must fire in < 1 minute. Most multi-stage correlations are better as Scheduled rules.

## Method 3: Fusion / Advanced Multistage
Sentinel Fusion automatically correlates some built-in detections. For custom logic, Scheduled rules with joins are more transparent and controllable.

## Validation Checklist
- [ ] Query returns expected results in Logs
- [ ] No excessive false positives on 7-day historical run
- [ ] Entities are properly mapped
- [ ] Automation playbook (if any) is tested in soft mode
- [ ] Severity and tactics are correct
