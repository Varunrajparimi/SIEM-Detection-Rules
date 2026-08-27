# Step-by-Step: Creating Correlation Rules in Elastic (ELK / Elastic Security)

## Prerequisites
- Elastic Stack 7.x / 8.x with Elastic Security (or SIEM app)
- Endpoint / Winlogbeat / Sysmon / Packetbeat data shipped and mapped to ECS
- Appropriate privileges to create detection rules

## Method 1: EQL Sequence Rule (Best for ordered correlations)

1. Go to **Security** → **Detect** → **Rules** → **Create new rule**
2. Select **Custom query** or **EQL rule**
3. Rule type: **Event Correlation** (EQL)
4. EQL query: paste the sequence from the rule file
5. Required fields / index patterns: adjust to your data (logs-*, winlogbeat-*, etc.)
6. Schedule: every 5–15 minutes, lookback matching the maxspan
7. Severity, Risk score, MITRE mappings: fill according to the rule
8. Actions: create investigation timeline, Webhook, Slack, SOAR, etc.
9. Enable and test

## Method 2: Threshold / Aggregation Rule
Useful when pure sequence is not needed (e.g., count of distinct hosts).

1. Create rule → Custom query
2. Use KQL or Lucene + Threshold setting (group by host.name / source.ip, count >= N)
3. Same scheduling and action options

## Method 3: Indicator Match + Building Block Rules
- Create lower-level “building block” rules that are silent
- Higher-level rule matches when multiple building blocks fire for the same entity

## ECS Field Tips
- host.name, user.name, source.ip, destination.ip, process.name, process.command_line, event.outcome, event.code
- Always verify field names with your actual data view

## Validation Checklist
- [ ] EQL sequence returns hits in Timeline / Discover
- [ ] maxspan and runs values are appropriate
- [ ] False positive rate checked over 7–14 days
- [ ] Rule is assigned to correct severity and MITRE tags
- [ ] Response actions tested
