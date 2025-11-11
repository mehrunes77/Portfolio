# Splunk-Alerts.md

## Purpose

This document provides a comprehensive guide to configuring, deploying, and managing alerts in Splunk for security monitoring. It covers alert creation workflows, best practices for avoiding false positives, alert action configuration, and practical examples for common security use cases.

Use this guide for:
- Setting up reliable alerts in a Security Operations Center (SOC)
- Reducing alert fatigue through proper tuning and baselining
- Automating incident response workflows via alert actions
- Creating reproducible alert configurations for portfolio demonstration

## Prerequisites

- Splunk Enterprise or Splunk Cloud with search capability
- User permissions: at minimum, "Power User" role to create and modify alerts
- Basic familiarity with Splunk Query Language (SPL)
- Optional: access to a test/sandbox Splunk instance for non-production testing

## Alert Anatomy: Core Components

Every Splunk alert consists of:

1. **Search query (SPL)** — the detection logic that runs on a schedule
2. **Trigger condition** — when to fire the alert (e.g., results > 5)
3. **Schedule** — how often the search runs (e.g., every 5 minutes)
4. **Alert actions** — what happens when triggered (email, webhook, etc.)
5. **Throttling** — prevents duplicate alerts within a time window
6. **Suppressions** — exclude known false positives by field values

## Quick Start: Create a Simple Alert

### Step 1: Build the detection query

Start with a search that identifies the suspicious activity. Example: detect failed login attempts.

```spl
index=main sourcetype=auth "Failed password"
| stats count by user, host
| where count > 5
```

Run this search interactively first to understand your data and refine it.

### Step 2: Save as an Alert

1. In the Splunk UI: **Searches & Visualizations** → **Searches** (or click your saved search)
2. Click **Save As** → **Alert**
3. Give it a name (e.g., `High Failed Logins`)
4. Choose a **Search Owner** (typically a shared workspace or service account)
5. Click **Save Alert**

### Step 3: Configure the Alert

1. Click your saved alert to open it
2. Go to **Edit Alert**
3. Set the following:
   - **Search**: review and confirm your SPL
   - **Trigger Condition**: `if number of events is greater than 5`
   - **Schedule**: `Every 5 minutes`
   - **Throttle**: `suppress alert for 1 hour` (prevents duplicate alerts for the same user)
   - **Alert Actions**: select `Send email` (or other action)
4. Click **Save**

### Step 4: Configure the Alert Action

For **email action**:
1. Set **Email To**: your SOC distribution list
2. Set **Subject**: `High Failed Logins Detected: $result.user$`
3. Set **Message**: include context (user, count, host)
4. Click **Save Alert**

Test by running the alert manually: click the alert and select **Run Alert Now**.

## Best Practices for Alert Configuration

### 1. Reduce False Positives

**Baseline your data first:**
- Run the search for several days to understand normal activity
- Identify thresholds (e.g., "more than 5 failed logins in 5 minutes is unusual")
- Adjust trigger conditions based on your environment

**Example: tune a brute-force detection alert**

```spl
index=main sourcetype=auth "Failed password"
| stats count by user, src_ip
| where count > 10
| lookup my_whitelist.csv user OUTPUTNEW is_authorized
| search is_authorized=false
```

This adds a whitelist lookup to exclude known-good accounts.

### 2. Use Throttling Effectively

Throttle alerts to avoid duplicate notifications for the same incident:

```
Throttle: suppress alert for 1 hour if user field is the same
```

This prevents the alert from firing more than once per hour for the same user, reducing email noise.

### 3. Add Context to Alert Messages

Include relevant field values and summary information:

```
Alert Title: Suspicious PowerShell Execution Detected
Subject: Alert: PowerShell Activity on $result.dest$
Message:
Host: $result.dest$
User: $result.user$
CommandLine: $result.command_line$
Count: $result.count$
Time: $result._time$
Recommended Action: Review process tree in endpoint security tool.
```

### 4. Use Tags and Metadata

Tag your alerts with CIS frameworks, attack tactics (MITRE ATT&CK), or severity levels:

- `cis_control: CIS 13.5`
- `mitre_attack_tactic: privilege_escalation`
- `severity: high`

This helps with:
- Mapping controls to compliance requirements
- Correlating alerts to attack frameworks
- Prioritizing SOC response

### 5. Monitor Alert Performance

Regularly check:
- **Number of alerts fired** — should be stable (spike indicates new threat or false positive surge)
- **Search run time** — avoid heavy queries that slow Splunk
- **Alert action failures** — check logs if emails aren't sending

## Common Security Alert Examples

### Example 1: Brute Force Login Detection

**Scenario:** Detect potential brute force attacks by monitoring failed login attempts.

```spl
index=main sourcetype=auth "Failed password" OR "Invalid user"
| stats count by src_ip, user
| where count > 20
| lookup geoip src_ip OUTPUT Country
| stats values(Country) as Countries, sum(count) as failed_attempts by src_ip, user
| where failed_attempts > 20
```

**Trigger:** `if number of events is greater than 0`

**Throttle:** `1 hour by src_ip`

**Alert Action:** Send email to SOC team with src_ip, user, and country info.

---

### Example 2: Lateral Movement Detection (SMB/PSEXEC)

**Scenario:** Detect lateral movement via SMB or PSEXEC activity.

```spl
index=main sourcetype=WinEventLog EventCode=4688 CommandLine="*psexec*" OR "*\\\\*\\admin$*"
| stats count by ComputerName, User, CommandLine
| where count > 1
```

**Trigger:** `if number of events is greater than 0`

**Throttle:** `30 minutes by ComputerName`

**Alert Action:** Send to ticketing system (e.g., Jira) with ComputerName, User, and CommandLine.

---

### Example 3: Data Exfiltration Detection (Large File Transfer)

**Scenario:** Detect suspicious large file transfers over network protocols.

```spl
index=main sourcetype=network_traffic dest_port IN (21, 22, 80, 443)
| search bytes_out > 1000000
| stats sum(bytes_out) as total_bytes_out, values(dest_ip) as dest_ips by src_ip, user
| where total_bytes_out > 10000000
```

**Trigger:** `if number of events is greater than 0`

**Throttle:** `2 hours by src_ip`

**Alert Action:** Send to SOC with src_ip, total_bytes_out, and dest_ips for investigation.

---

### Example 4: Privilege Escalation (Sudo/Runas)

**Scenario:** Monitor for suspicious privilege escalation attempts.

```spl
index=main (sourcetype=linux_audit AUDIT_RULE="sudo" OR sourcetype=WinEventLog EventCode=4688 CommandLine="*runas*")
| stats count by host, user, _time
| where count > 3
```

**Trigger:** `if number of events is greater than 0`

**Throttle:** `1 hour by host, user`

**Alert Action:** Send to Slack with host, user, and timestamp for immediate SOC review.

---

### Example 5: DNS Exfiltration Detection (Unusual DNS Queries)

**Scenario:** Detect potential DNS tunneling or data exfiltration.

```spl
index=main sourcetype=dns query_type=A
| stats count as num_queries, sum(answer_count) as num_answers by src_ip, query
| where num_queries > 100 AND num_answers == 0
| lookup known_domains.csv query OUTPUTNEW is_known
| search is_known=false
```

**Trigger:** `if number of events is greater than 0`

**Throttle:** `30 minutes by src_ip`

**Alert Action:** Send to SOC with src_ip, num_queries, and suspicious queries.

## Alert Actions and Integrations

Splunk supports multiple alert actions:

### 1. Email

```
To: soc@company.com
Subject: $alert_name$ - $result.src_ip$
Message: Failed login from $result.src_ip$ (Country: $result.Country$)
```

### 2. Webhook (HTTP POST)

Forward alert data to external systems (e.g., SOAR, ticketing):

```json
{
  "alert_name": "$alert_name$",
  "severity": "high",
  "src_ip": "$result.src_ip$",
  "user": "$result.user$",
  "count": "$result.count$"
}
```

### 3. Slack Integration

Configure a webhook URL in Splunk and send alerts directly to a Slack channel:

```
Slack channel: #soc-alerts
Message: 🚨 $alert_name$: $result.user$ from $result.src_ip$ (Count: $result.count$)
```

### 4. Ticketing System (Jira, ServiceNow)

Create tickets automatically when alerts fire:

```
Project: SEC
Issue Type: Security Incident
Summary: $alert_name$ - $result.host$
Description: Triggered at $result._time$. Details: $result$
```

### 5. Webhook to Custom SOAR (e.g., Phantom, Tines)

Send to an automation platform for orchestrated response:

```json
{
  "action": "isolate_host",
  "target": "$result.dest$",
  "reason": "High failed login attempts detected"
}
```

## Alert Tuning and Refinement

### Monitor Alert Volume

Check the **Alert Manager** in Splunk to see:
- How many times each alert fired in the last 7 days
- Failure rates
- Average time to fire

Adjust thresholds if:
- **Too many alerts:** increase threshold or add whitelist
- **Too few alerts:** decrease threshold or broaden search criteria

### A/B Test Alert Changes

When refining an alert:

1. Save the old alert as `Alert_Name_v1_baseline`
2. Create a new version with changes: `Alert_Name_v2_test`
3. Run both in parallel for 1 week
4. Compare accuracy and volume
5. Retire the worse-performing version

### Investigate False Positives

When an alert fires incorrectly:

1. Open the alert in Splunk
2. Review the **search results** to understand what triggered it
3. Add **exclusions** (e.g., whitelist, filter by source)
4. Save the refined alert
5. Document the change in your alert runbook

## Alert Deployment and Version Control

### Structure for Portfolio

Store alert configurations in a repository for reproducibility:

```
alerts/
  ├── brute_force_login.spl
  ├── lateral_movement.spl
  ├── data_exfiltration.spl
  ├── dns_exfiltration.spl
  └── privilege_escalation.spl

docs/
  ├── alert_runbook.md
  ├── false_positives.md
  └── thresholds.md
```

### Export Alerts from Splunk

Use the Splunk API to export an alert:

```bash
curl -k -u admin:password \
  https://your-splunk-instance:8089/servicesNS/admin/search/saved/searches/Alert_Name \
  -H 'X-Requested-With: XMLHttpRequest' \
  -o alert_export.json
```

### Import/Restore Alerts

Use a custom dashboard or REST API to quickly restore alerts in a new Splunk instance.

## Reproducible Alert Testing

### Test Alert in Sandbox

1. Create a test index with sample data
2. Modify the alert to target the test index
3. Run the alert manually and verify it fires correctly
4. Document expected behavior and threshold

### Example: Reproducible Brute Force Alert

**Test data:** Create a sample sourcetype with fake failed login events

```spl
| makeresults count=30
| eval _time=now()-[5, 10, 15, 20, 25, 30, 35, 40, 45, 50]
| eval src_ip="192.0.2.100"
| eval user="testuser"
| eval event="Failed password"
| fields _time, src_ip, user, event
```

**Alert search:**

```spl
index=main sourcetype=test_auth "Failed password"
| stats count by src_ip, user
| where count > 5
```

**Expected result:** Alert fires because count (30) > threshold (5).

## Common Pitfalls and How to Avoid Them

| Pitfall | Cause | Solution |
|---------|-------|----------|
| Alert fatigue | Too many alerts, low thresholds | Tune thresholds, use whitelists, correlate events |
| Missed incidents | Search logic too narrow | Expand search criteria, test with diverse data |
| Slow alerts | Complex queries on large datasets | Use data models, summarize, limit time ranges |
| No context | Alert message lacks detail | Add field values ($result.field$) and summaries |
| No throttle | Duplicate notifications | Set throttle based on field (e.g., by user, host) |
| Untracked changes | Alert logic drifts over time | Version control, document thresholds, use baselines |

## References and Resources

- **Splunk Documentation:** https://docs.splunk.com/Documentation/Splunk/latest/Alert/Aboutalerts
- **SPL Quick Reference:** https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/SearchCommandsIndex
- **MITRE ATT&CK Framework:** https://attack.mitre.org/ (for tagging alerts)
- **CIS Controls:** https://www.cisecurity.org/cis-controls (for mapping alerts to compliance)

## Appendix: Alert Deployment Checklist

- [ ] Alert search query tested and baseline established
- [ ] Trigger condition tuned to minimize false positives
- [ ] Throttle period set appropriately
- [ ] Alert actions configured (email, webhook, etc.)
- [ ] Alert name and description are clear
- [ ] Alert documentation added to runbook
- [ ] Alert tested in sandbox or test environment
- [ ] Owner and escalation contacts assigned
- [ ] Severity/priority level assigned
- [ ] Alert versioned and tracked in repository

---

**Document version:** 1.0  
**Last updated:** 2025-11-11  
**Status:** Ready for portfolio use
