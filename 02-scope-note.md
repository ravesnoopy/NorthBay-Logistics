# 02 · Scope Note — Initial Supervisor Briefing

**Case:** TKT-2026-04340
**Analyst:** Leonardo Romero
**Delivered to:** Roberto Silva, SOC Manager
**Time constraint:** 25-minute reporting deadline from ticket assignment
**Purpose:** Enable a go/no-go containment decision in under 2 minutes of reading

---

> **Context:** This note was produced under operational time pressure at the start of the investigation. Its function is not to reach a final conclusion — it is to give the supervisor enough structured information to make an immediate operational decision while the deeper analysis continues. Scope cuts are explicit and intentional.

---

## 1. Opening Hypothesis

The five alerts share a single account (`admin_backup`) and a single host (`srv-backup-01`) across a 15-hour window spanning Friday evening through Saturday morning. Treated individually, each closure was defensible. Treated as a sequence, the alerts are consistent with a single incident: initial account access, backup-infrastructure reconnaissance, data exfiltration, firewall persistence, and privilege escalation. This is not five false positives — it is one missed campaign.

---

## 2. Scope

### 2a. Assets Involved
| Asset | Role in Incident |
|---|---|
| `srv-backup-01` | Primary compromised host; source of all post-login activity |
| `admin_backup` | Account used across all five alerts; service account, no mailbox |
| Active Directory / Domain Controllers (`dc01`, `dc02`) | Modified — `admin_backup` added to `Domain_Admins`; change replicated |
| Perimeter Firewall | Modified — unauthorized rule added permitting `dst=any:443` |
| `10.50.8.45` | Source IP of the Friday login; internal address, device owner unconfirmed |

### 2b. Data at Risk
The following data categories were accessible from `srv-backup-01` and are considered potentially compromised pending forensic confirmation:

- Production database snapshots
- Backup configuration files, including `credentials_map.enc`
- Active Directory account hashes (accessed via `Backup_Config` share — INFERRED, not confirmed by a discrete log entry)
- Full infrastructure configuration backups

### 2c. Incident Window
**Fri 14:48:03 → Sat 06:01:12** (approx. 15 hours, 13 minutes)

First observed event: successful login post-lockout.
Last confirmed event: AD replication complete after `Domain_Admins` group modification.

---

## 3. Source Consultation Order

Recommended query priority based on what each source can resolve at this stage:

| Priority | Source | What it resolves |
|---|---|---|
| 1 | **EDR** | Decode `powershell.exe -EncodedCommand` payload; confirm full process tree for both execution events |
| 2 | **Active Directory** | Confirm whether current elevated privileges (`Domain_Admins`) are still active; check for additional group changes not yet surfaced |
| 3 | **Firewall** | Confirm whether the port 443 rule is still active; identify any additional connections to `203.0.113.45` beyond the logged windows |
| 4 | **CMDB / Asset Inventory** | Identify owner and standard use of `10.50.8.45`; confirm `admin_backup` expected operational scope |
| 5 | **ITSM / Change Calendar** | Verify CHG-2026-1842 (password rotation) and confirm absence of authorized change ticket for firewall rule and group modification |
| 6 | **Proxy / DNS** | Determine if `203.0.113.45` or `cdn-us-east-19.streamcloud.io` were contacted from any other host in the environment |
| 7 | **Email Gateway** | Already reviewed for `admin_backup` — no activity found; revisit for other accounts if lateral movement is confirmed |

---

## 4. Data Conflict Detected

**SIEM vs. Firewall — exfiltration window discrepancy:**

The SIEM reports the exfiltration as a single event under 30 minutes. The firewall logs show three distinct transfer windows:

| Window | Destination | Volume |
|---|---|---|
| Fri 22:15–22:45 | `203.0.113.45:443` | ~50.0 GB |
| Sat 03:00–03:45 | `203.0.113.45:443` | 18.4 GB |
| Sat 07:30–07:45 | `203.0.113.45:443` | 4.2 GB |

**Total if firewall data is accurate: ~72.6 GB — not ~50 GB.**

This conflict has not been resolved. It does not change the containment decision but does affect the total data-exposure estimate. Possible causes: NTP desync between SIEM and firewall, timezone or UTC offset misconfiguration, SIEM log aggregation delay, or log collection latency. **Requires infrastructure verification before the final incident report.**

---

## 5. Recommended Decision: CONTAIN

**Rationale:** The combination of a confirmed 50 GB+ transfer to an unknown external IP, an unauthorized firewall rule opening port 443 to any destination, and a service account now holding `Domain_Admins` membership constitutes an active risk posture. Waiting for full forensic confirmation before acting would leave the persistence mechanism and the elevated account in place.

**Immediate actions:**
- Disable or reset `admin_backup` credentials
- Revert the unauthorized firewall rule (`FW_RULE_ADD dst=any:443 action=allow`, Sat 02:30)
- Remove `admin_backup` from `Domain_Admins` and verify replication
- Preserve memory and disk state of `srv-backup-01` before any remediation — do not power down without forensic imaging

**Do not do today (scope cut):**
- Full forensic imaging and analysis of `srv-backup-01`
- Attacker attribution
- Confirmation of initial access vector
- Lateral movement investigation beyond the current five tickets

---

## 6. What Would Change This Assessment

| Evidence | Impact |
|---|---|
| Confirmation of an authorized maintenance window covering Fri 22:00 – Sat 06:00 | Would require re-evaluation of all off-hours activity before concluding unauthorized access |
| Confirmation from the `admin_backup` account owner that they performed all observed actions | Would shift hypothesis from compromise to insider/privilege-abuse investigation |
| Evidence the 50 GB transfer was a legitimate, documented backup job to a known CDN | Would require re-evaluation of TKT-04156 in isolation, but would not explain firewall rule and group modification |
| Evidence of a second compromised account or persistence on additional hosts | Would escalate scope significantly beyond current five tickets |
