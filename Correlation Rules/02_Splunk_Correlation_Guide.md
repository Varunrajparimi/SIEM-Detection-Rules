# Step-by-Step: Creating Correlation Rules in Splunk

## Prerequisites
- Splunk Enterprise or Splunk Cloud with required indexes (windows, sysmon, azuread, o365, firewall, etc.)
- ES (Enterprise Security) recommended for notable events and risk framework
- Appropriate capabilities (edit_search, schedule_search, etc.)

## Method 1: Correlation Search (Splunk Enterprise Security)

1. Go to **Enterprise Security** → **Configure** → **Content** → **Correlation Searches**
2. Click **+ Add New**
3. Fill in:
   - Search Name: CORR-001 – Password Spray + Success
   - Description + App
   - Search: paste the SPL from the rule (adjust index names and field names to your CIM mappings)
4. Schedule:
   - Cron or continuous
   - Earliest / Latest matching the rule window
5. Throttle (important for correlation):
   - Throttle fields: src_ip, user, host (as appropriate)
   - Window: 30m–2h so the same chain does not flood notables
6. Notable Event settings:
   - Severity / Urgency: High or Critical
   - Security Domain, Nested category
   - Drill-down searches if desired
7. Adaptive Response (optional): link to SOAR or custom scripts
8. Save and Enable

## Method 2: Regular Scheduled Search + Alert (non-ES)

1. Search → paste SPL → **Save As** → **Alert**
2. Alert type: Scheduled
3. Trigger conditions: Number of Results > 0
4. Throttle by key fields
5. Actions: Add to Triggered Alerts, send to SOAR, create ticket, webhook, etc.

## Field Mapping Tips
- Normalize to CIM: Authentication, Network_Traffic, Endpoint, etc.
- Common fields used: src_ip, user, host, dest_ip, CommandLine, Image, EventCode, ResultType
- Use `tstats` where possible for performance on large datasets

## Validation Checklist
- [ ] SPL runs successfully over historical data
- [ ] Throttling prevents alert storms
- [ ] Notable / Alert contains useful fields for analysts
- [ ] Linked to response playbook or SOAR
