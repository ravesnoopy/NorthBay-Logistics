# 05 · IOC List & MITRE ATT&CK Mapping — TKT-2026-04340

**Case:** TKT-2026-04340
**Analyst:** Leonardo Romero
**Purpose:** Consolidated indicator reference for blocking, detection-rule review, and threat-intelligence enrichment. Each IOC is sourced directly from confirmed log evidence. Each MITRE technique is mapped to the specific event that supports it — not applied categorically.

---

## Confidence Model (IOCs)

| Label | Meaning |
|---|---|
| **CONFIRMED** | Indicator directly evidenced by a log entry in the available sources |
| **INFERRED** | Derived from correlated evidence; not confirmed by a standalone log entry |
| **UNKNOWN** | Indicator referenced in the investigation but not independently verified |

---

## 1. Indicators of Compromise (IOCs)

### Network Indicators

| Indicator | Type | First Seen | Last Seen | Confidence | Source | Notes |
|---|---|---|---|---|---|---|
| `203.0.113.45` | External IP | Fri 22:14 | Sat 07:45 | **CONFIRMED** | Proxy/DNS, Firewall | Exfiltration destination; no prior organizational history; three confirmed outbound transfer windows |
| `cdn-us-east-19.streamcloud.io` | Domain | Fri 22:14 | Fri 22:14 | **CONFIRMED** | Proxy/DNS | Resolved to `203.0.113.45`; no prior DNS resolution history in the organization; newly observed immediately before exfiltration began |
| `203.0.113.45:443` | IP:Port | Fri 22:15:08 | Sat 07:45 | **CONFIRMED** | Firewall | HTTPS/443 used for all three exfiltration windows; also the port opened by the unauthorized firewall rule |

### Host Indicators

| Indicator | Type | First Seen | Last Seen | Confidence | Source | Notes |
|---|---|---|---|---|---|---|
| `powershell.exe -EncodedCommand` | Process execution | Fri 22:12 | Sat 05:58 | **CONFIRMED** | EDR | Observed twice; parent processes `rsync.exe` (Fri 22:12) and `scheduled_task_runner.exe` (Sat 02:28); payload not recovered — decoding is a priority gap |
| `rsync.exe → powershell.exe` | Process lineage | Fri 22:12 | Fri 22:12 | **CONFIRMED** | EDR | Anomalous parent-child relationship; a backup sync process spawning encoded PowerShell is not expected behavior |
| `scheduled_task_runner.exe → powershell.exe` | Process lineage | Sat 02:28 | Sat 02:28 | **CONFIRMED** | EDR | Scheduled task used as execution vehicle for encoded PowerShell immediately before firewall modification |
| `net.exe localgroup "Domain Admins" admin_backup /ADD` | Command | Sat 05:58 | Sat 05:58 | **CONFIRMED** | EDR | Executed by `powershell.exe`; resulted in confirmed AD group modification and replication |
| `FW_RULE_ADD dst=any:443 action=allow` | Firewall rule | Sat 02:30 | — | **CONFIRMED** | Firewall | Added by `admin_backup` from `srv-backup-01`; no change ticket; status (active/reverted) pending containment confirmation |

### Account & Identity Indicators

| Indicator | Type | First Seen | Last Seen | Confidence | Source | Notes |
|---|---|---|---|---|---|---|
| `admin_backup` | Account | Fri 14:25:11 | Sat 06:00:42 | **CONFIRMED** | AD, Firewall, EDR | Common thread across all five alerts; service account — no mailbox; added to `Domain_Admins` at Sat 06:00 |
| `10.50.8.45` | Internal IP | Fri 14:48:03 | Fri 14:48:03 | **CONFIRMED** (as login source) / **UNKNOWN** (device owner) | AD | Source of the Friday post-unlock login; internal address; not confirmed against asset inventory — owner and device type unresolved |

### Infrastructure Indicators

| Indicator | Type | Confidence | Source | Notes |
|---|---|---|---|---|
| `srv-backup-01` | Compromised host | **CONFIRMED** | AD, Firewall, EDR | Source of all post-login activity across all five tickets; forensic imaging required before remediation |
| `\\srv-backup-01\Backup_Config\` | Accessed resource | **INFERRED** | TKT-04118 alert context | AD hash data read during session; no discrete log entry confirms the exact access event |
| `dc01.internal`, `dc02.internal` | Domain controllers | **CONFIRMED** | AD | `Domain_Admins` group change replicated to both; elevated privileges confirmed as propagated |

---

## 2. MITRE ATT&CK Mapping

**Framework version:** ATT&CK v14 (Enterprise)
**Mapping principle:** Each technique is supported by at least one confirmed or inferred event from the available evidence. Techniques are not applied speculatively — where the evidence supports a technique only partially, this is noted.

---

### Initial Access

| Technique | ID | Confidence | Evidence |
|---|---|---|---|
| Valid Accounts — Local Accounts | T1078.003 | **PROBABLE** | `admin_backup` authenticated successfully at Fri 14:48:03 using valid credentials. The mechanism by which those credentials were obtained is unknown, but their use constitutes valid-account access regardless of how they were acquired. |

> **Note — T1078 sub-technique selection:** `admin_backup` is a local service account on `srv-backup-01`, not a domain account used for lateral movement at this stage. If investigation reveals the credentials were obtained via a prior domain-level compromise, T1078.002 (Domain Accounts) may apply in addition.

---

### Execution

| Technique | ID | Confidence | Evidence |
|---|---|---|---|
| Command and Scripting Interpreter — PowerShell | T1059.001 | **CONFIRMED** | `powershell.exe -EncodedCommand` executed at Fri 22:12 (parent: `rsync.exe`) and Sat 02:28 (parent: `scheduled_task_runner.exe`). PowerShell used as the execution mechanism for exfiltration, firewall modification, and privilege escalation. |
| Scheduled Task / Job — Scheduled Task | T1053.005 | **CONFIRMED** | `scheduled_task_runner.exe` used as the parent process to launch `powershell.exe -EncodedCommand` at Sat 02:28, immediately before the firewall rule modification. Indicates the use of a scheduled task as an execution vehicle. |

---

### Persistence

| Technique | ID | Confidence | Evidence |
|---|---|---|---|
| Modify Authentication Process | — | — | *(Not applicable — no evidence of authentication mechanism modification)* |
| Impair Defenses — Disable or Modify System Firewall | T1562.004 | **CONFIRMED** | `FW_RULE_ADD by=admin_backup src=srv-backup-01 dst=any:443 action=allow` at Sat 02:30. Rule persists after the session — creates a standing outbound channel on port 443 regardless of subsequent account containment, unless explicitly reverted. |
| Account Manipulation — Additional Cloud Credentials | — | — | *(Not applicable)* |
| Account Manipulation — Additional Local or Domain Groups | T1098.007 | **CONFIRMED** | `admin_backup` added to `Domain_Admins` at Sat 06:00 via `net.exe`. Change replicated across DCs. Provides persistent elevated access to the domain even if the original compromise vector is closed. |

---

### Credential Access

| Technique | ID | Confidence | Evidence |
|---|---|---|---|
| OS Credential Dumping — NTDS | T1003.003 | **INFERRED** | Access to `\\srv-backup-01\Backup_Config\` reportedly included AD hash data (TKT-04118). A backup server holding AD hashes in its configuration share is a known credential-access risk. No discrete log entry confirms a dump operation — this remains inferred from alert context. |

> **Note:** If the PowerShell payload is recovered and decoded, this technique may be confirmed or refined. Pass-the-Hash (T1550.002) should also be considered if the hash access is confirmed.

---

### Discovery

| Technique | ID | Confidence | Evidence |
|---|---|---|---|
| File and Directory Discovery | T1083 | **INFERRED** | Access to `Backup_Config` share implies active enumeration of backup content and configuration resources. Not confirmed by a discrete discovery-phase log entry; inferred from the sequence of access to configuration data prior to exfiltration. |

---

### Exfiltration

| Technique | ID | Confidence | Evidence |
|---|---|---|---|
| Exfiltration Over C2 Channel | T1041 | **CONFIRMED** | ~50 GB (SIEM) / ~72.6 GB (Firewall, pending clock-conflict resolution) transferred from `srv-backup-01` to `203.0.113.45:443` via HTTPS. Transfer initiated by `powershell.exe -EncodedCommand` (Fri 22:12). Three firewall-logged windows: Fri 22:15–22:45, Sat 03:00–03:45, Sat 07:30–07:45. |

---

### Defense Evasion

| Technique | ID | Confidence | Evidence |
|---|---|---|---|
| Obfuscated Files or Information — Command Obfuscation | T1027.010 | **CONFIRMED** | `powershell.exe -EncodedCommand` used for both execution events. Base64-encoded command-line arguments prevent static analysis of intent from log data alone. Payload not recovered in available evidence — decoding is a priority investigative action. |
| Indirect Command Execution | T1202 | **CONFIRMED** | PowerShell commands were launched via intermediate parent processes (`rsync.exe`, `scheduled_task_runner.exe`) rather than directly from a shell or interactive session. This lineage pattern is consistent with evading parent-process-based detection rules. |

---

### Privilege Escalation

| Technique | ID | Confidence | Evidence |
|---|---|---|---|
| Account Manipulation — Additional Local or Domain Groups | T1098.007 | **CONFIRMED** | (Also mapped under Persistence.) `admin_backup` added to `Domain_Admins` at Sat 06:00 — a direct privilege escalation from a service account to domain administrator level. |
| Valid Accounts | T1078 | **PROBABLE** | Pre-existing administrative privileges on `srv-backup-01` were used to execute firewall changes and AD group modifications. The account had sufficient local permissions to perform these actions — privilege escalation at the host level may not have been required; domain-level escalation via `Domain_Admins` is the primary escalation event. |

---

## 3. ATT&CK Technique Summary

| Tactic | Technique | ID | Confidence |
|---|---|---|---|
| Initial Access | Valid Accounts — Local Accounts | T1078.003 | PROBABLE |
| Execution | Command and Scripting Interpreter — PowerShell | T1059.001 | CONFIRMED |
| Execution | Scheduled Task / Job — Scheduled Task | T1053.005 | CONFIRMED |
| Persistence | Impair Defenses — Disable or Modify System Firewall | T1562.004 | CONFIRMED |
| Persistence / Privilege Escalation | Account Manipulation — Additional Local or Domain Groups | T1098.007 | CONFIRMED |
| Credential Access | OS Credential Dumping — NTDS | T1003.003 | INFERRED |
| Discovery | File and Directory Discovery | T1083 | INFERRED |
| Defense Evasion | Obfuscated Files or Information — Command Obfuscation | T1027.010 | CONFIRMED |
| Defense Evasion | Indirect Command Execution | T1202 | CONFIRMED |
| Exfiltration | Exfiltration Over C2 Channel | T1041 | CONFIRMED |

---

## 4. Detection Engineering Gaps (Post-Incident Recommendations)

The following gaps are identified based on this investigation and are separate from the analytical findings. They represent opportunities to improve detection coverage before the next similar incident.

| Gap | Observation | Recommendation |
|---|---|---|
| TKT-04287 severity was LOW | A service account adding itself to `Domain_Admins` triggered a low-severity alert. This should be a critical-severity rule with immediate escalation. | Review and recalibrate the AD group modification rule for privileged groups (`Domain_Admins`, `Enterprise Admins`, `Schema Admins`). Severity should be CRITICAL for any service account performing such changes. |
| No alert on anomalous parent-process lineage | `rsync.exe → powershell.exe` and `scheduled_task_runner.exe → powershell.exe -EncodedCommand` were detected via EDR but did not independently trigger correlation rules in the SIEM. | Implement parent-process-lineage rules for `powershell.exe -EncodedCommand` spawned by non-shell parent processes, particularly backup utilities and task schedulers. |
| No alert on unauthorized firewall rule creation | The firewall modification (TKT-04203) was closed as a false positive in part because the account had administrative privileges. Privilege ≠ authorization. | Implement a SIEM correlation rule that cross-references firewall rule changes against the active change-management calendar. Any firewall change without a same-day approved change ticket should escalate automatically. |
| SIEM/Firewall timestamp discrepancy undetected | The clock conflict between sources was not flagged automatically — it was discovered manually during correlation. | Implement automated NTP health monitoring and log-source timestamp-drift alerting across all SIEM-feeding devices. Discrepancies above a defined threshold should trigger a data-quality alert. |
