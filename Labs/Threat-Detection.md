# Threat-Detection.md

## Purpose

This document provides a comprehensive guide to threat detection methodologies, tools, and workflows in a Security Operations Center (SOC). It covers detection engineering, threat hunting, indicator-of-compromise (IOC) analysis, and practical strategies for identifying advanced threats using network, host, and application logs.

Use this guide for:
- Building robust threat detection programs from scratch
- Implementing detection strategies aligned with MITRE ATT&CK framework
- Performing threat hunting campaigns to proactively identify threats
- Creating reproducible detection workflows for portfolio demonstration
- Correlating multiple data sources to improve detection accuracy

## Prerequisites

- Access to a SIEM (e.g., Splunk, ELK, Datadog) or log aggregation platform
- Understanding of basic network and host artifacts (IPs, domains, process names, registry keys)
- Familiarity with query languages (SPL, KQL, PromQL) or regex patterns
- Basic knowledge of attack frameworks (MITRE ATT&CK, Lockheed Martin Cyber Kill Chain)
- Optional: sandbox environment (e.g., Cuckoo, Falcon Sandbox) for malware analysis

## Threat Detection Framework

### The Detection Pyramid (from General to Specific)

```
        ▲
        │      Threats (Advanced, Sophisticated)
        │    /─────────────────────────────────\
        │   / Malware, C2, APT Campaigns      \
        │  /  (requires behavioral + IOC)      \
        │ /─────────────────────────────────────\
        │/ Suspicious Activity (Unusual Patterns) \
        │ (lateral movement, privilege escalation)\
        │────────────────────────────────────────
        │  Baseline Activity (Known-Good Baseline)
        │────────────────────────────────────────
        └─────────────────────────────────────────
```

**Detection strategy levels:**

1. **Level 1: Baseline awareness** — understand normal behavior (baseline traffic, process execution, login patterns)
2. **Level 2: Anomaly detection** — identify deviations from baseline (unusual process, large data transfer)
3. **Level 3: Behavioral detection** — recognize attack patterns (command and control beaconing, lateral movement)
4. **Level 4: Threat intelligence** — use known IOCs and threat feeds (malicious IPs, domain names, file hashes)

## Core Detection Data Sources

### Network-based Detection

**Flow data (NetFlow, sFlow, Zeek):**
- Source/destination IPs and ports
- Protocol (TCP, UDP, DNS)
- Bytes in/out
- Connection duration

**Example use case:** Detect C2 beaconing via regular outbound connections to suspicious IPs.

```spl
index=network dest_ip=external src_ip=internal
| stats count, avg(duration), sum(bytes_out) by src_ip, dest_ip, dest_port
| where count > 100 AND avg(duration) < 10
```

**DNS logs:**
- Query names (domains requested)
- Query types (A, AAAA, MX, TXT)
- Response codes (NXDOMAIN, NOERROR)

**Example use case:** Detect DNS tunneling or beaconing.

```spl
index=dns query_type=A
| stats count as num_queries by client_ip, query_name
| where num_queries > 500
```

**HTTP/HTTPS traffic (proxy, firewall):**
- User agent
- URL paths
- HTTP status codes
- Referer headers

**Example use case:** Detect webshell access or suspicious downloads.

```spl
index=http uri_path="/admin/*" status=200 uri_path="*shell*"
| stats count by src_ip, uri_path, status
```

### Host-based Detection

**Process execution logs (Sysmon on Windows, auditd on Linux):**
- Process name and path
- Parent process
- Command-line arguments
- User context
- Timestamp

**Example use case:** Detect suspicious process spawning (e.g., PowerShell running from Office).

```spl
index=endpoint source=sysmon EventCode=1 Image="*powershell.exe" ParentImage="*winword.exe"
| stats count by ComputerName, User, CommandLine
```

**File system events (Sysmon, auditd):**
- File path, size, modification time
- Hash (MD5, SHA-1, SHA-256)
- User who accessed it

**Example use case:** Detect suspicious DLL injection or file writes.

```spl
index=endpoint source=sysmon EventCode=11 TargetFilename="*AppData*" TargetFilename="*.dll"
| stats count by ComputerName, TargetFilename, Hashes
```

**Windows Event Logs:**
- EventCode 4688 (process creation)
- EventCode 4720 (user account created)
- EventCode 4722 (user account enabled)
- EventCode 5140 (network share access)

**Example use case:** Detect suspicious account creation or enablement.

```spl
index=windows EventCode IN (4720, 4722) TargetUserName!="*$"
| stats count by TargetUserName, NewAccountName, EventCode
```

### Application-based Detection

**Web application logs:**
- HTTP requests/responses
- SQL queries
- Authentication attempts
- Error messages

**Example use case:** Detect SQL injection attempts.

```spl
index=webapp sourcetype=apache_error "union" OR "select" OR "insert" OR "delete"
| stats count by src_ip, uri_path
```

**Email logs:**
- Sender, recipient, subject
- Attachments (type, size, hash)
- External recipient count

**Example use case:** Detect phishing or spam campaigns.

```spl
index=email attachment_type IN ("exe", "zip", "doc", "xls") recipient_domain!=company.com
| stats count by sender, subject, attachment_hash
```

## Threat Detection Techniques

### 1. Signature-based Detection

**What:** Match known indicators (file hashes, domain names, IP addresses) against observed activity.

**Advantages:** Fast, high confidence, low false positive rate.

**Disadvantages:** Only catches known threats; ineffective against new variants.

**Example:** Detect known malware by hash.

```spl
index=endpoint source=sysmon EventCode=1
| lookup malware_hashes.csv Hashes OUTPUTNEW is_malware
| search is_malware=true
| stats count by ComputerName, Image, Hashes
```

### 2. Anomaly-based Detection

**What:** Identify deviations from established baseline (volume, timing, direction, payload).

**Advantages:** Catches new/unknown threats; adaptive to environment changes.

**Disadvantages:** Higher false positive rate; requires good baselines.

**Example:** Detect unusual outbound data transfer.

```spl
index=network src_ip=internal
| stats sum(bytes_out) as total_bytes_out by src_ip
| where total_bytes_out > avg * 10
```

### 3. Behavioral Detection

**What:** Recognize attack patterns and tactics (lateral movement, privilege escalation, command and control).

**Advantages:** Catches sophisticated attacks; aligns with threat actor TTPs.

**Disadvantages:** Complex logic; requires understanding of attack lifecycle.

**Example:** Detect lateral movement via SMB/PSEXEC.

```spl
index=network src_ip=internal dest_ip=internal dest_port IN (445, 139)
| stats count by src_ip, dest_ip
| where count > 1
| lookup known_servers.csv dest_ip OUTPUTNEW is_server
| search is_server=false
```

### 4. Threat Intelligence Integration

**What:** Use external feeds of known malicious IPs, domains, and file hashes.

**Advantages:** Leverages collective threat intelligence; reduces analysis time.

**Disadvantages:** Requires up-to-date feeds; possible false positives from feed errors.

**Example:** Check observed IPs against threat feed.

```spl
index=network dest_ip=external
| lookup threat_intel.csv dest_ip OUTPUTNEW threat_score, threat_type
| where threat_score > 50
| stats count by dest_ip, threat_type
```

## Practical Threat Detection Scenarios

### Scenario 1: Ransomware Detection

**Attack chain:**
1. Initial access (phishing, RDP compromise)
2. Privilege escalation
3. Lateral movement
4. File encryption

**Detection points:**

```spl
# Detect mass file modification (potential encryption)
index=endpoint source=sysmon EventCode=11 TargetFilename="*" 
| bucket _time span=1h
| stats dc(TargetFilename) as file_count by _time, ComputerName
| where file_count > 100

# Detect suspicious process execution (RunAs, psexec)
index=endpoint source=sysmon EventCode=1 (CommandLine="*runas*" OR CommandLine="*psexec*")
| stats count by ComputerName, User

# Detect network activity to known ransomware C2
index=network dest_ip=external
| lookup ransomware_c2_ips.csv dest_ip OUTPUTNEW is_c2
| search is_c2=true
```

### Scenario 2: APT Campaign (Multi-Stage)

**Attack chain:**
1. Reconnaissance (OSINT, scanning)
2. Initial compromise (phishing, watering hole)
3. Persistence (scheduled task, registry run key)
4. Lateral movement
5. Exfiltration (DNS tunneling, HTTPS to C2)

**Detection points:**

```spl
# Detect scheduled task creation (persistence)
index=windows EventCode=4698 OR EventCode=4699
| stats count by Computer, TaskName, TaskContent

# Detect registry modification for persistence
index=endpoint source=sysmon EventCode=13 TargetObject="HKLM\\Software\\Microsoft\\Windows\\Run*"
| stats count by ComputerName, TargetObject, Details

# Detect DNS queries to known APT infrastructure
index=dns
| lookup apt_domains.csv query_name OUTPUTNEW apt_group, confidence
| where confidence > 0.7
| stats count by client_ip, query_name, apt_group

# Detect data exfiltration via HTTPS to C2
index=network dest_port=443 bytes_out > 1000000
| lookup c2_ips.csv dest_ip OUTPUTNEW is_c2
| search is_c2=true
```

### Scenario 3: Insider Threat Detection

**Indicators:**
- After-hours access to sensitive systems
- Large volume of file copies/moves
- Access to systems outside normal role
- Email forwarding rules
- Unusual outbound traffic

**Detection points:**

```spl
# After-hours access to sensitive systems
index=windows EventCode=4624 ComputerName IN (fileserver, database)
| eval hour=strftime(_time, "%H")
| where hour < 7 OR hour > 18
| stats count by User, ComputerName, hour

# Large volume of sensitive file access
index=endpoint source=sysmon EventCode=23 TargetFilename IN ("*financial*", "*confidential*")
| stats count by User, ComputerName
| where count > 50

# Unusual outbound data transfer
index=network src_ip=internal bytes_out > 5000000
| stats sum(bytes_out) by src_ip, user
| where sum(bytes_out) > 100000000
```

### Scenario 4: Web Application Exploitation

**Attack chain:**
1. Reconnaissance (scanning, enumeration)
2. Vulnerability discovery
3. Exploitation (SQLi, RCE, LFI)
4. Webshell upload or reverse shell
5. Post-exploitation (privilege escalation, lateral movement)

**Detection points:**

```spl
# Detect SQLi attempts
index=webapp (uri_path="*union*" OR uri_path="*select*" OR uri_path="*drop*" OR uri_path="*exec*")
| stats count by src_ip, uri_path, status

# Detect suspicious file uploads
index=webapp (uri_path="*upload*" OR uri_path="*file*") status=200
| stats count by src_ip, uri_path, filename

# Detect webshell access
index=webapp uri_path IN ("*shell.php", "*cmd.asp", "*backdoor.jsp")
| stats count by src_ip, uri_path

# Detect post-exploitation reverse shell
index=network src_ip=external dest_ip=webserver dest_port IN (4444, 5555, 6666, 8888)
| stats count by dest_ip, dest_port
```

## Threat Hunting Workflow

Threat hunting is proactive threat detection — manually searching for evidence of compromise.

### Step 1: Define Hunting Hypothesis

Start with a question based on threat intelligence or known gaps in detection:

- "Are we compromised by APT-29?"
- "Do we have any indicators of lateral movement?"
- "Are there signs of data exfiltration via DNS tunneling?"

### Step 2: Gather Intelligence

Research:
- Known IOCs (IPs, domains, file hashes)
- MITRE ATT&CK tactics used by the threat
- Common attack patterns

**Resources:**
- MITRE ATT&CK: https://attack.mitre.org/
- VirusTotal: https://www.virustotal.com/
- AlienVault OTX: https://otx.alienvault.com/
- Shodan: https://www.shodan.io/

### Step 3: Develop Hunt Queries

Build searches to identify the threat pattern:

```spl
# Hunt: APT-29 lateral movement via WinRM
index=network dest_port=5985 OR dest_port=5986 src_ip=internal dest_ip=internal
| stats count by src_ip, dest_ip

# Hunt: Suspicious PowerShell execution from Office
index=endpoint source=sysmon EventCode=1 ParentImage IN ("*winword*", "*excel*") Image="*powershell*"
| stats count by ComputerName, CommandLine

# Hunt: Registry persistence mechanisms
index=endpoint source=sysmon EventCode=13 TargetObject IN ("HKLM\\SOFTWARE\\Microsoft\\Windows\\Run*", "HKCU\\SOFTWARE\\Microsoft\\Windows\\Run*")
| stats count by ComputerName, Details
```

### Step 4: Analyze Results

Review search results and investigate suspicious entries:

- **High confidence findings:** Immediately escalate to incident response
- **Medium confidence:** Correlate with other data sources; request additional context
- **Low confidence:** Document and add to whitelist

### Step 5: Develop Detections

Convert successful hunt queries into automated alerts:

```spl
# Converted to Alert: Daily check for suspicious PowerShell from Office
index=endpoint source=sysmon EventCode=1 ParentImage IN ("*winword*", "*excel*") Image="*powershell*"
| stats count by ComputerName, CommandLine
| where count > 0
```

### Step 6: Document Findings

Create a hunt report documenting:
- Hypothesis and methodology
- Queries used
- Results and findings
- Recommendations
- Follow-up actions

## Detection Engineering Best Practices

### 1. Start with High-Confidence Detection Rules

Build detections in priority order:

1. **Known bad** (file hashes, IPs, domains) — high confidence, low false positive
2. **Behavioral patterns** (lateral movement, privilege escalation) — medium confidence
3. **Anomalies** (unusual volume, direction) — lower confidence, higher false positive

### 2. Baseline Your Data

Understand normal behavior before alerting on abnormal:

```spl
# Baseline: average bytes_out per src_ip over past 30 days
index=network
| stats sum(bytes_out) as total_bytes_out by src_ip
| stats avg(total_bytes_out) as avg_bytes_out, stdev(total_bytes_out) as stdev_bytes_out
```

### 3. Use Correlation Rules

Combine multiple indicators for higher confidence:

```spl
# Detection: Lateral movement (multiple indicators)
index=network src_ip=internal dest_ip=internal dest_port IN (445, 3389)
| stats count by src_ip, dest_ip
| search count > 5
| join type=inner src_ip
  [search index=endpoint EventCode=4688 (CommandLine="*psexec*" OR CommandLine="*runas*")]
| stats count by src_ip
```

### 4. Avoid Alert Fatigue

- Use throttling to suppress duplicate alerts
- Add context to alert messages
- Whitelisting known-good activity
- Tune thresholds based on baseline

### 5. Continuous Improvement

- Monitor alert accuracy (true positives vs. false positives)
- Update detection logic based on new threats
- Incorporate feedback from incident response team
- Test detections regularly

## Tools for Threat Detection

| Tool | Use Case | Strengths |
|------|----------|-----------|
| Splunk | SIEM, log aggregation | Powerful query language, alerting, dashboards |
| ELK (Elasticsearch, Logstash, Kibana) | Log aggregation, detection | Open-source, scalable, cost-effective |
| Zeek | Network IDS | Protocol analysis, flow data, TLS certificate extraction |
| Suricata | Network IDS/IPS | Open-source, signature and behavioral detection |
| Wazuh | Host-based monitoring | Endpoint detection, file integrity monitoring |
| CrowdStrike Falcon | Endpoint detection & response (EDR) | Real-time threat detection, threat hunting |
| Microsoft Defender for Cloud | Cloud security | Azure/Microsoft workload monitoring |
| Datadog | Observability | Real-time monitoring, threat detection |

## Detection Maturity Model

| Maturity Level | Characteristics | Example Detections |
|---|---|---|
| **Level 1: Initial** | Manual investigation only; no automated alerts | Analyst reviews firewall logs on demand |
| **Level 2: Managed** | Basic alert rules in place; reactive alerts | Email alert for failed login threshold |
| **Level 3: Defined** | Documented detection strategy; correlation rules | Multi-stage APT detections combining IOC + behavior |
| **Level 4: Quantitatively Managed** | Metrics on detection performance; continuous tuning | Tracked false positive rates, detection coverage |
| **Level 5: Optimizing** | AI/ML-driven detections; predictive threat hunting | Anomaly detection, behavioral modeling |

## Common Detection Gaps and Solutions

| Gap | Cause | Solution |
|-----|-------|----------|
| Encrypted traffic invisible | HTTPS/TLS blocks payload inspection | Implement TLS decryption, monitor metadata (IPs, ports, SNI) |
| False positives from business applications | Legitimate tools trigger detection | Whitelist, adjust threshold, correlate with other indicators |
| No visibility into encrypted DNS | DoH/DoT bypasses DNS monitoring | Deploy DNS sinkhole, monitor network egress to known DoH providers |
| Missing endpoint data | Agents not installed on all systems | Prioritize critical assets, auto-deploy agents |
| Delayed alerts | Heavy queries slow SIEM | Optimize queries, use data models, summarize pre-computed data |
| No correlation across data sources | Siloed security tools | Implement SOAR/automation, centralize logs in SIEM |

## References and Resources

- **MITRE ATT&CK Framework:** https://attack.mitre.org/ — comprehensive catalog of tactics and techniques
- **Lockheed Martin Cyber Kill Chain:** https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html
- **NIST Cybersecurity Framework:** https://www.nist.gov/cyberframework
- **Splunk Threat Research:** https://www.splunk.com/en_us/blog/security.html
- **Detection Engineering on GitHub:** https://github.com/SigmaHQ/sigma — open-source detection rule repository
- **YARA Rules:** https://virustotal.github.io/yara/ — malware detection rule format
- **AlienVault OTX:** https://otx.alienvault.com/ — open threat intelligence exchange

## Appendix: Threat Detection Maturity Checklist

- [ ] Inventory all data sources (network, host, application logs)
- [ ] Define baseline behavior for key assets
- [ ] Create signature-based detections for known threats
- [ ] Implement behavioral detection rules (lateral movement, privilege escalation)
- [ ] Set up alerting and escalation workflows
- [ ] Conduct threat hunting campaigns monthly
- [ ] Document all detections and false positive rates
- [ ] Train SOC team on detection rules and threat landscape
- [ ] Integrate threat intelligence feeds
- [ ] Establish metrics for detection accuracy (TPR, FPR, precision, recall)
- [ ] Schedule quarterly reviews and updates to detection rules
- [ ] Plan for advanced detections (ML anomaly detection, behavioral baselining)

## Appendix B: Sample Hunt Report Template

**Hypothesis:** [State the hunting question]

**Time Period:** [Start date - End date]

**Data Sources:** [Log types searched: network flow, DNS, endpoint, etc.]

**Queries Run:**
```
[List all SPL/KQL queries used]
```

**Key Findings:**
- Finding 1: [Description, severity, IOCs]
- Finding 2: [Description, severity, IOCs]

**Recommendations:**
1. [Immediate action if suspicious activity found]
2. [Detection rule to deploy]
3. [Additional hunting direction]

**Follow-up:** [Escalation, incident creation, remediation steps]

---

**Document version:** 1.0  
**Last updated:** 2025-11-11  
**Status:** Ready for portfolio use
