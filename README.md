# CIRRUS
### Cloud Incident Response & Reconnaissance Utility Suite

[![Build](https://github.com/ctrlaltdean/cirrus/actions/workflows/build.yml/badge.svg)](https://github.com/ctrlaltdean/cirrus/actions/workflows/build.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

CIRRUS is a command-line tool for investigating security incidents and auditing compliance in Microsoft 365 and Entra ID (Azure AD) tenants. Designed for MSSP environments — it runs on analyst machines without complex setup, supports multiple tenants, and produces clean output for investigations, reporting, and evidence preservation.

---

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [Installation](#installation)
  - [Pre-built Executable (Recommended)](#pre-built-executable-recommended)
  - [From Source](#from-source)
- [Required Roles](#required-roles)
- [Commands](#commands)
  - [Authentication](#authentication)
  - [Quick Triage](#quick-triage)
  - [Investigation Workflows](#investigation-workflows)
    - [BEC — Business Email Compromise](#bec--business-email-compromise)
    - [ATO — Account Takeover](#ato--account-takeover)
    - [BEC+ATO — Combined Full Attack Chain](#becato--combined-full-attack-chain)
    - [Full Tenant Collection](#full-tenant-collection)
    - [Workflow Comparison](#workflow-comparison)
  - [Post-Collection Analysis](#post-collection-analysis)
  - [Compliance Audit](#compliance-audit)
  - [Case Management](#case-management)
  - [Updating CIRRUS](#updating-cirrus)
  - [Dependency Management](#dependency-management)
- [Output Structure](#output-structure)
- [IOC Flags](#ioc-flags)
- [Cross-Collector Correlation](#cross-collector-correlation)
- [Chain of Custody](#chain-of-custody)
- [CIS Compliance Checks](#cis-compliance-checks)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## Features

| Feature | Description |
|---|---|
| **Quick Triage** | 8 parallel checks on a suspected compromised account — results in seconds, no case folder needed |
| **BEC Workflow** | Targeted 10-step collection for Business Email Compromise investigations |
| **ATO Workflow** | 11-step Account Takeover investigation — authentication layer, persistence, and exfiltration |
| **BEC+ATO Workflow** | Combined 13-step full attack chain — most BEC incidents begin with an ATO event |
| **Full Tenant Sweep** | Complete collection across all supported data sources |
| **Cross-Collector Correlation** | Post-collection engine links events across collectors to surface multi-source attack patterns |
| **HTML Investigation Report** | Single self-contained HTML report with correlation findings, IOC timeline, and per-collector tables |
| **CIS Compliance Audit** | 34 checks against CIS M365 & Entra ID Benchmarks with wizard UI |
| **License-Aware Collection** | Detects tenant license tier (P1/P2/E5) and gracefully skips unsupported endpoints |
| **Multi-Tenant** | Authenticate to and collect from multiple client tenants independently |
| **Flexible Targeting** | Single user, multiple users, file list, or entire tenant |
| **Chain of Custody** | Tamper-evident SHA-256 hash chain audit log per case |
| **Triple Output** | Every collector writes JSON + CSV + NDJSON (SOF-ELK ready) |
| **IOC Flagging** | Collectors auto-annotate records with `_iocFlags` for quick triage |
| **Auto-Update** | Checks for new releases in the background; update in one command |
| **Standalone Executable** | Single file download — no Python required on analyst machines |
| **Cross-Platform** | Windows, macOS, and Linux |

---

## Quick Start

**Step 1 — Fast triage on a suspected account (seconds, no files written):**
```bash
cirrus triage --tenant contoso.com --user john@contoso.com
```

**Step 2 — Full investigation if triage shows something suspicious:**
```bash
cirrus run ato --tenant contoso.com --user john@contoso.com --days 30
```

**Interactive wizard (no flags needed — CIRRUS prompts for everything):**
```bash
cirrus triage
cirrus run bec
```

After a workflow run, CIRRUS automatically runs the cross-collector correlation engine and generates `investigation_report.html` — a self-contained report you can open in any browser or share with a client.

---

## Installation

### Pre-built Executable (Recommended)

Download the latest release for your platform from the [Releases](../../releases) page.

| Platform | File |
|----------|------|
| Windows  | `cirrus-windows-x64.exe` |
| macOS    | `cirrus-macos-x64` |
| Linux    | `cirrus-linux-x64` |

**Windows:**
```powershell
Rename-Item cirrus-windows-x64.exe cirrus.exe
.\cirrus.exe --help
```

**macOS / Linux:**
```bash
chmod +x cirrus-macos-x64
mv cirrus-macos-x64 cirrus
./cirrus --help
```

> **Tip:** Move the executable to a folder on your PATH (e.g. `C:\Tools` on Windows, `/usr/local/bin` on macOS/Linux) so you can run `cirrus` from any directory.

Each release includes `.sha256` files — verify the download before running:
```bash
# Windows (PowerShell)
Get-FileHash cirrus.exe -Algorithm SHA256

# macOS / Linux
shasum -a 256 cirrus
```

---

### From Source

Requires **Python 3.11+** and **pip**.

```bash
git clone https://github.com/ctrlaltdean/cirrus.git
cd cirrus
pip install -e .
cirrus --help
```

---

## Required Roles

CIRRUS uses delegated (interactive login) permissions. The account used to authenticate must hold at least one of these Entra ID roles:

| Role | What It Covers |
|------|----------------|
| **Global Reader** | All data sources — simplest option for investigations |
| Security Reader | Sign-in logs, audit logs, Identity Protection, CA policies |
| Exchange Administrator | Mailbox rules, forwarding settings |
| Cloud App Security Administrator | OAuth app grants |

> **MSSP Recommendation:** Create a dedicated read-only investigation account per client tenant with Global Reader. Do not use a Global Administrator account for routine collection.

---

## Commands

### Authentication

CIRRUS caches tokens per tenant in `~/.cirrus/token_cache.json`. You only need to log in once per tenant per session.

Authentication opens a **private/incognito browser window** automatically (Edge InPrivate → Chrome Incognito → Firefox Private → system default). This prevents Microsoft SSO session bleed between tenants when working multi-tenant engagements — each prompt starts with a clean session.

```bash
# Authenticate to a tenant (opens browser)
cirrus auth login --tenant contoso.com

# See all tenants with cached credentials
cirrus auth status

# Remove cached credentials for a tenant
cirrus auth logout --tenant contoso.com
```

---

### Quick Triage

Runs 8 targeted checks on a suspected compromised account **in parallel**. No case folder is created — results display directly in the terminal in seconds. Use this for rapid first-look assessment before deciding whether to run a full workflow.

**Checks (all run simultaneously):**

| Check | What it looks for |
|---|---|
| Sign-in activity | Unusual countries, impossible travel, device code/ROPC, legacy auth, risk signals |
| MFA methods | Recently added methods, FIDO2 keys, external email OTP, multiple authenticator apps |
| Inbox rules | Forwarding rules, permanent delete, hidden-folder rules, finance keywords |
| Mail forwarding | External SMTP forward, no-local-copy configuration |
| OAuth grants | High-risk scopes (Mail.Read, Files.ReadWrite.All, full_access_as_user, etc.) |
| Registered devices | Recently registered, personal/BYOD devices |
| Directory audit | MFA changes, admin password resets, role assignments in the window |
| Identity Protection | Risk state and risk level (skipped gracefully if no Entra ID P2) |

```bash
# Single user, last 7 days (default)
cirrus triage --tenant contoso.com --user john@contoso.com

# Wider window
cirrus triage --tenant contoso.com --user john@contoso.com --days 14

# Multiple users
cirrus triage --tenant contoso.com --users john@contoso.com --users jane@contoso.com

# From a file (one UPN per line, # comments ignored)
cirrus triage --tenant contoso.com --users-file suspects.txt

# Interactive wizard
cirrus triage
```

**Sample output:**
```
  ✗  Sign-in activity    HIGH    8 sign-ins · 2 countries · 1 suspicious
       → IMPOSSIBLE_TRAVEL:US->RU:1.2h
       → SUSPICIOUS_AUTH_PROTOCOL:deviceCode
  ✗  MFA methods         HIGH    3 methods — NEW: fido2_key added 2026-03-15
       → HIGH_PERSISTENCE_METHOD:fido2_key
  ✗  Inbox rules         HIGH    2 rules — forwards to attacker@gmail.com
       → FORWARDS_TO:attacker@gmail.com
  ✓  Mail forwarding     CLEAN   No forwarding configured
  ⚠  OAuth grants        WARN    Mail.Read · offline_access
  ✓  Registered devices  CLEAN   2 devices · no recent additions
  ⚠  Directory audit     WARN    MFA_METHOD_ADDED, ADMIN_PASSWORD_RESET
  –  Identity Protection SKIP    Requires Entra ID P2

╭─ HIGH RISK — 4/7 checks flagged ──────────────────────────────────────────╮
│  Recommended: cirrus run ato --tenant contoso.com --user john@contoso.com  │
╰────────────────────────────────────────────────────────────────────────────╯
```

---

### Investigation Workflows

All workflow runs produce a timestamped case folder with JSON, CSV, and NDJSON output per collector, a chain-of-custody audit log, cross-collector correlation findings, and a self-contained HTML investigation report.

**License-aware collection:** Before running, CIRRUS checks the tenant's license tier and shows which collectors will run. Collectors for unlicensed features are gracefully skipped with a clear explanation rather than failing with an API error.

```
Tenant license profile:  Entra ID P1 ✓   Entra ID P2 ✗   M365 Advanced Auditing (UAL) ✗
  ↳ Entra ID P2 not found — risky_users, risky_signins will be skipped
  ↳ UAL will run — MailItemsAccessed requires E5/Audit Premium (Send and other events available on all plans)
```

#### BEC — Business Email Compromise

Targeted collection for a known or suspected compromised mailbox. Collects in the order that best supports timeline reconstruction.

**What it collects:**
1. Target user details
2. Sign-in logs — *requires Entra ID P1*
3. Entra directory audit logs (password resets, MFA changes, role assignments) — *requires Entra ID P1*
4. Risky user scores (Identity Protection) — *requires Entra ID P2*
5. Risky sign-in events — *requires Entra ID P2*
6. MFA / authentication methods
7. Mailbox inbox rules (hide/forward/delete rules)
8. Mailbox forwarding settings (SMTP forwarding to external address)
9. OAuth app grants (malicious app consent)
10. Unified Audit Log — `MailItemsAccessed` requires E5/Audit Premium; `Send` and most other events available on all plans

```bash
# Interactive wizard
cirrus run bec

# Single user, last 30 days
cirrus run bec --tenant contoso.com --user john@contoso.com --days 30

# Multiple users, explicit date range
cirrus run bec --tenant contoso.com \
  --users john@contoso.com --users jane@contoso.com \
  --start-date 2026-03-01 --end-date 2026-03-18

# Load targets from a file
cirrus run bec --tenant contoso.com --users-file targets.txt --days 14

# All users in the tenant
cirrus run bec --tenant contoso.com --all-users --start-date 2026-03-01 --end-date 2026-03-18

# Custom case name and output directory
cirrus run bec --tenant contoso.com --user john@contoso.com \
  --case-name INC-2026-042 --output-dir D:\Cases
```

---

#### ATO — Account Takeover

Focuses on the authentication layer — how the attacker got in, what persistence mechanisms they left behind, and what they accessed. Use when you want to assess the full blast radius of a suspected compromise.

**What it collects:**
1. Target user details (flags recently created accounts, guest accounts)
2. Sign-in logs — authentication timeline with IOC flags for legacy auth, device code phishing, impossible travel
3. Entra directory audit logs — MFA changes, password resets, role assignments, CA policy changes
4. MFA / authentication methods — attacker-added FIDO2 keys, authenticator apps, phone numbers
5. Risky user scores (Identity Protection) — *requires Entra ID P2*
6. Risky sign-in events — *requires Entra ID P2*
7. Conditional Access policies — what enforcement was in place; explains how entry was possible
8. Registered devices — PRT-bearing devices added during the window survive password resets
9. OAuth app grants — malicious app consent that persists after credential reset
10. App registrations — new apps created in the tenant; common attacker persistence mechanism
11. Unified Audit Log — MailItemsAccessed, file downloads, sharing events

```bash
# Interactive wizard
cirrus run ato

# Single user, last 30 days
cirrus run ato --tenant contoso.com --user john@contoso.com --days 30

# Explicit date range
cirrus run ato --tenant contoso.com --user john@contoso.com \
  --start-date 2026-03-01 --end-date 2026-03-18

# All users (broad incident, compromised account not yet identified)
cirrus run ato --tenant contoso.com --all-users --days 14
```

---

#### BEC+ATO — Combined Full Attack Chain

Most BEC incidents begin with an ATO event. This workflow combines both investigations into a single run — shared collectors (sign-in logs, audit logs, UAL) run exactly once with no duplication.

**Covers:**
- **ATO phase** — initial access, persistence (devices, MFA, OAuth, app registrations)
- **BEC phase** — mailbox manipulation (rules, forwarding, wire fraud enablement)
- **Overlap** — sign-in logs, audit events, and UAL cover both phases

```bash
cirrus run bec-ato --tenant contoso.com --user john@contoso.com --days 30

cirrus run bec-ato --tenant contoso.com \
  --users john@contoso.com --users jane@contoso.com \
  --start-date 2026-03-01 --end-date 2026-03-18
```

---

#### Full Tenant Collection

Sweeps the entire tenant for all supported artifact types. Use when the compromised account is not yet identified, or for proactive threat hunting.

**Collects everything in BEC+ATO, plus:** Service Principals.

```bash
# Full sweep, all users, 90-day window
cirrus run full --tenant contoso.com --all-users --days 90

# Targeted to specific users, all artifact types
cirrus run full --tenant contoso.com --users-file vip_users.txt
```

> **Note:** Full tenant sweeps on large tenants (1000+ users) can take 15–30 minutes and generate large output files. Use triage or a targeted workflow first if a compromised account is known.

---

#### Workflow Comparison

| | Triage | BEC | ATO | BEC+ATO | Full |
|--|:------:|-----|-----|---------|------|
| Users | ✓ | ✓ | ✓ | ✓ | ✓ |
| Sign-in logs | ✓ | ✓ | ✓ | ✓ | ✓ |
| Entra audit logs | ✓ | ✓ | ✓ | ✓ | ✓ |
| MFA methods | ✓ | ✓ | ✓ | ✓ | ✓ |
| Risky users / sign-ins | | ✓ | ✓ | ✓ | ✓ |
| Conditional Access | | | ✓ | ✓ | ✓ |
| Registered devices | ✓ | | ✓ | ✓ | |
| OAuth grants | ✓ | ✓ | ✓ | ✓ | ✓ |
| App registrations | | | ✓ | ✓ | |
| Mailbox rules | ✓ | ✓ | | ✓ | ✓ |
| Mail forwarding | ✓ | ✓ | | ✓ | ✓ |
| UAL | | ✓ | ✓ | ✓ | ✓ |
| Service principals | | | | | ✓ |
| Case folder / files | | ✓ | ✓ | ✓ | ✓ |
| Correlation + HTML report | | ✓ | ✓ | ✓ | ✓ |

---

### Post-Collection Analysis

After every workflow run, CIRRUS automatically runs the cross-collector correlation engine and generates an HTML investigation report. You can also re-run both against any existing case folder:

```bash
# Re-run correlation and regenerate HTML report for an existing case
cirrus analyze investigations/CONTOSO_20260317_143022
```

This is useful when you add new collectors to an existing case, pull in data from another tool, or want to regenerate the report after manually editing output files.

`cirrus analyze` prints a findings table to the terminal with a detail panel per finding, and writes:
- `ioc_correlation.json` — machine-readable findings (SIEM-ingestible)
- `ioc_correlation.txt` — formatted text report for case notes
- `investigation_report.html` — full self-contained HTML investigation report

See [Cross-Collector Correlation](#cross-collector-correlation) for the full list of detection rules.

---

### Compliance Audit

Checks your tenant configuration against **CIS Microsoft 365 Foundations Benchmark** and **CIS Entra ID Benchmark** controls. Each check reports `PASS`, `FAIL`, `WARN`, or `MANUAL` (with step-by-step verification instructions for checks that require PowerShell or the admin portal).

#### Interactive Wizard (Default)

```bash
cirrus run audit
```

```
╭─ CIS Compliance Audit Wizard ─────────────────────────────╮
│  Answer a few questions to configure your audit run.      │
╰───────────────────────────────────────────────────────────╯

Tenant domain or GUID: contoso.com

Which benchmark would you like to run?
  1  CIS Microsoft 365 Foundations Benchmark
  2  CIS Entra ID Benchmark
  3  Both  (recommended — maximum coverage)
Choice [3]:

Which CIS levels should be included?
  1  Level 1 only  (broadly applicable, lower disruption risk)
  2  Level 2 only  (stricter, higher security impact)
  3  Both levels   (recommended — full coverage)
Choice [3]:

Save output files? [Y/n]:
Case name (leave blank for auto-generated):

╭─ Audit Configuration ─────────────────────────────────────╮
│  Tenant      contoso.com                                  │
│  Benchmark   CIS M365 + CIS Entra (both)                 │
│  Levels      Level 1 & 2 (all)                           │
│  Checks      31 total                                     │
│  Output      investigations/                              │
╰───────────────────────────────────────────────────────────╯
```

> Before running checks, CIRRUS displays the tenant's license tier and optional PowerShell module status. Missing licenses cause certain checks to show contextual notes rather than unexplained FAILs. Missing modules fall back to step-by-step manual instructions.

#### Scripted

```bash
# Full audit, all benchmarks and levels
cirrus run audit --tenant contoso.com --benchmark all --level all

# CIS M365 Level 1 only
cirrus run audit --tenant contoso.com --benchmark cis-m365 --level 1

# Print to screen only, no output files
cirrus run audit --tenant contoso.com --benchmark all --level 1 --no-save
```

#### Sample Output

```
  Control        L  Title                              Expected           Actual              Status
  ─────────────────────────────────────────────────────────────────────────────────────────────────
  M365-1.1.1     1  Security Defaults vs. CA           SD disabled, ...   SD DISABLED, 4 CA   ✓ PASS
  M365-1.2.1     1  MFA required for all users         CA policy requi... Policy found: Req.. ✓ PASS
  M365-1.2.2     1  MFA required for admins            CA policy requi... No enabled CA pol.. ✗ FAIL
  M365-1.3.1     1  Users cannot consent to apps       Restricted cons... Users can consent.. ✗ FAIL
  M365-1.4.1     1  Legacy auth blocked                CA policy block... Policy found: Blo.. ✓ PASS
  M365-3.1.1     1  DKIM enabled                       DKIM enabled ...   Manual verificati.. ☐ MANUAL

  Summary:  14 PASS  7 FAIL  3 WARN  14 MANUAL  0 ERROR
```

---

### Case Management

```bash
# List all cases in the output directory
cirrus case list

# List cases in a custom directory
cirrus case list --output-dir D:\Cases

# Verify the chain-of-custody integrity of a case
cirrus case verify investigations/CONTOSO_20260317_143022
```

---

### Updating CIRRUS

CIRRUS automatically checks for new releases in the background on every run (at most once per 24 hours, 3-second timeout). If a newer version is available, a notification appears below the banner:

```
  ↑ Update available: v0.4.17  Run cirrus update to install.
```

```bash
# Check if a new version is available (no download)
cirrus update --check

# Check and install if a new version is available
cirrus update
```

On **Windows**, the binary is swapped automatically after the current window closes. On **macOS/Linux**, the binary is replaced in-place immediately. When running from source, `cirrus update` will tell you to use `git pull` instead.

---

### Dependency Management

CIRRUS checks PowerShell module availability automatically before each compliance audit. You can also check and install dependencies manually:

```bash
cirrus deps check
cirrus deps install
```

| Dependency | Purpose | Required? |
|------------|---------|-----------|
| `ExchangeOnlineManagement` | Automates Exchange, DKIM, UAL, and logging checks | Optional |
| `MicrosoftTeams` | Automates Teams external access, guest, and meeting checks | Optional |
| `Microsoft.Online.SharePoint.PowerShell` | Automates SharePoint sharing and legacy auth checks | Optional |
| `dnspython` | DNS-based DMARC / SPF checks | Optional |

---

## Output Structure

Every workflow run creates a timestamped case folder:

```
investigations/
└── CONTOSO_20260317_143022/
    ├── case_audit.jsonl                ← tamper-evident chain-of-custody log
    ├── case_audit.txt                  ← human-readable audit log
    │
    ├── users.json / .csv / .ndjson
    ├── signin_logs.json / .csv / .ndjson
    ├── entra_audit_logs.json / .csv / .ndjson
    ├── risky_users.json / .csv / .ndjson
    ├── risky_signins.json / .csv / .ndjson
    ├── mfa_methods.json / .csv / .ndjson
    ├── registered_devices.json / .csv / .ndjson   ← ATO / BEC+ATO workflows
    ├── app_registrations.json / .csv / .ndjson    ← ATO / BEC+ATO workflows
    ├── mailbox_rules.json / .csv / .ndjson
    ├── mail_forwarding.json / .csv / .ndjson
    ├── oauth_grants.json / .csv / .ndjson
    ├── conditional_access_policies.json / .csv / .ndjson
    ├── service_principals.json / .csv / .ndjson   ← full workflow only
    ├── unified_audit_log.json / .csv / .ndjson    ← UAL NDJSON is SOF-ELK normalized
    │
    ├── ioc_correlation.json                        ← cross-collector findings (machine-readable)
    ├── ioc_correlation.txt                         ← formatted correlation report
    ├── investigation_report.html                   ← self-contained HTML investigation report
    │
    └── compliance_audit.json / .csv / .txt        ← audit workflow only
```

Each collector produces three output files:
- **`.json`** — Pretty-printed JSON array. Human-readable, easy to open in any editor or `jq`.
- **`.csv`** — Flattened CSV. Import directly into Excel or SIEM ingestion pipelines.
- **`.ndjson`** — JSON Lines (one object per line). Ready for SOF-ELK, Elastic, or any Logstash pipeline.

### SOF-ELK Ingestion

[SOF-ELK](https://github.com/philhagen/sof-elk) automatically ingests files placed in specific directories on the VM:

| Collector | SOF-ELK target directory |
|-----------|--------------------------|
| `unified_audit_log.ndjson` | `/logstash/microsoft365/` |
| `signin_logs.ndjson` | `/logstash/azure/` |
| `entra_audit_logs.ndjson` | `/logstash/azure/` |

```bash
scp investigations/CONTOSO_20260317_143022/unified_audit_log.ndjson \
    analyst@sofelk:/logstash/microsoft365/

scp investigations/CONTOSO_20260317_143022/signin_logs.ndjson \
    analyst@sofelk:/logstash/azure/
```

UAL records are normalized to match native `Search-UnifiedAuditLog` field names (`CreationTime`, `Operation`, `UserId`, `Workload`, `ClientIP`, etc.) and the `auditData` payload is promoted to the top level — exactly the shape SOF-ELK's microsoft365 pipeline expects.

---

## IOC Flags

Collectors annotate each record with a `_iocFlags` list. Records with flags should be reviewed first. The `_iocFlags` field appears in JSON, CSV, and NDJSON output.

### Sign-In Logs

| Flag | Meaning |
|------|---------|
| `LEGACY_AUTH:<protocol>` | Sign-in used a legacy protocol (IMAP, POP3, SMTP, EAS, MAPI, BasicAuth) — cannot enforce MFA or Conditional Access |
| `SUSPICIOUS_AUTH_PROTOCOL:deviceCode` | Device code flow — primary technique in token-theft phishing |
| `SUSPICIOUS_AUTH_PROTOCOL:ropc` | Resource Owner Password Credentials — password submitted directly to the token endpoint, bypasses MFA entirely |
| `SINGLE_FACTOR_SUCCESS` | Sign-in succeeded with only one authentication factor |
| `CA_POLICY_FAILURE` | Conditional Access policy blocked or failed |
| `RISK_LEVEL:<high\|medium>` | Microsoft Identity Protection aggregate risk score |
| `RISK_STATE:<state>` | `atRisk` or `confirmedCompromised` per Identity Protection |
| `GEO_RISK:<detail>` | Geolocation risk signal: `anonymizedIPAddress` (Tor/VPN/proxy), `maliciousIPAddress`, `impossibleTravel`, `newCountry`, `unfamiliarFeatures` |
| `IDENTITY_RISK:<detail>` | Identity risk signal: `leakedCredentials`, `anomalousToken`, `suspiciousBrowser`, `suspiciousInboxForwarding`, etc. |
| `FAILED_SIGNIN:<reason>` | Sign-in failed — includes the failure reason string |
| `FLAGGED_FOR_REVIEW` | Microsoft flagged this sign-in for analyst review |
| `PUBLIC_IP:<ip>` | Non-RFC1918 source IP — paste directly into VirusTotal, Shodan, or AbuseIPDB |
| `COUNTRY:<country>` | Sign-in country — always tagged for geographic pivot and filtering |
| `CITY:<city>` | Sign-in city — always tagged |
| `IMPOSSIBLE_TRAVEL:<A->B:Xh>` | **Cross-record** — same user signed in from two different countries within 2 hours (no Identity Protection license required) |

### Entra Directory Audit Logs

| Flag | Meaning |
|------|---------|
| `MFA_METHOD_ADDED` | User registered a new MFA / security info method |
| `MFA_METHOD_REMOVED` | MFA method deleted — attacker removing victim's recovery options |
| `MFA_REGISTRATION_COMPLETE` | User completed full MFA registration |
| `MFA_SETTINGS_CHANGED` | `StrongAuthentication` property modified |
| `ADMIN_PASSWORD_RESET` | An admin reset a user's password — could be attacker locking victim out or legitimate IR |
| `USER_PASSWORD_CHANGE` | User changed their own password |
| `USER_CREATED` | New user account added to the directory |
| `USER_DELETED` | User account deleted |
| `USER_DISABLED` | User sign-in blocked |
| `USER_ENABLED` | User sign-in unblocked |
| `ROLE_ASSIGNMENT:<role>` | A role was assigned to a user or principal |
| `HIGH_PRIV_ROLE_ASSIGNED:<role>` | Assignment of a high-privilege role (Global Admin, Exchange Admin, Security Admin, etc.) |
| `ROLE_REMOVAL:<role>` | A role was removed |
| `APP_CONSENT_GRANTED` | User or admin consented to an application — OAuth phishing indicator |
| `OAUTH_PERMISSION_CHANGED` | OAuth delegated permission grant added or updated |
| `CA_POLICY_ADDED` | New Conditional Access policy created |
| `CA_POLICY_UPDATED` | Existing CA policy modified |
| `CA_POLICY_DELETED` | CA policy removed |
| `APP_REGISTRATION_CREATED` | New app registration added to the tenant |
| `APP_REGISTRATION_UPDATED` | App registration modified (secrets, certificates) |
| `SERVICE_PRINCIPAL_ADDED` | New service principal added |
| `APP_OWNER_ADDED` | Owner added to an application registration |
| `OPERATION_FAILED:<activity>` | Audit event recorded a `failure` or `timeout` result |
| `PUBLIC_IP:<ip>` | Initiating IP extracted from `additionalDetails` |

### Users

| Flag | Meaning |
|------|---------|
| `RECENTLY_CREATED:<date>` | Account created within the collection window — attacker backdoor account indicator |
| `GUEST_ACCOUNT` | B2B guest account — commonly over-permissioned; attacker may have invited an external account they control |
| `ACCOUNT_DISABLED` | Account is blocked from sign-in |
| `NO_ASSIGNED_LICENSES` | No license assigned — service accounts and orphaned accounts commonly targeted or created by attackers |
| `EXTERNAL_IDENTITY:<provider>` | Account federated to an external IdP (Google, Facebook, external Azure AD, email OTP) — may bypass Conditional Access |

### MFA / Authentication Methods

| Flag | Meaning |
|------|---------|
| `HIGH_PERSISTENCE_METHOD:<type>` | FIDO2 key or certificate — survives password resets, hard to detect |
| `RECENTLY_ADDED:<date>` | Method added within the collection window — classic attacker persistence |
| `EXTERNAL_EMAIL_OTP:<domain>` | Email OTP on a different domain from the user's UPN — likely attacker-controlled recovery address |
| `USABLE_TEMP_ACCESS_PASS` | Active Temporary Access Pass — usable right now without a password or MFA |
| `MULTIPLE_AUTHENTICATOR_APPS:<n>` | **Cross-record** — N authenticator apps registered; legitimate users rarely need more than one |
| `MULTIPLE_PHONE_NUMBERS:<n>` | **Cross-record** — N phone numbers registered |

### Registered Devices

| Flag | Meaning |
|------|---------|
| `RECENTLY_REGISTERED:<date>` | Device registered within the collection window — PRT-bearing devices survive password resets |
| `PERSONAL_DEVICE` | Workplace-joined personal/BYOD device |
| `UNMANAGED_DEVICE` | Device not enrolled in Intune MDM |
| `NON_COMPLIANT` | Enrolled device marked non-compliant with Intune compliance policies |

### App Registrations

| Flag | Meaning |
|------|---------|
| `RECENTLY_CREATED:<date>` | App registration created within the collection window |
| `NO_VERIFIED_PUBLISHER` | App has no verified publisher |
| `MULTI_TENANT` | App is configured for multi-tenant access — accepts tokens from any Azure AD tenant |
| `HAS_APP_PERMISSIONS` | App holds application (Role) permissions — can act without a signed-in user |
| `HAS_CLIENT_SECRETS:<n>` | App has N client secrets |
| `HAS_CERTIFICATES:<n>` | App has N certificate credentials |
| `LOCALHOST_REDIRECT` | App has a localhost redirect URI — unusual in production |

### Mailbox Rules

| Flag | Meaning |
|------|---------|
| `FORWARDS_TO:<addr>` | Rule forwards matching mail to an address |
| `PERMANENT_DELETE` | Rule permanently deletes matching mail |
| `MARKS_AS_READ` | Rule silently marks mail as read — victim sees no unread badge |
| `MOVES_TO_HIDDEN_FOLDER:<folder>` | Rule moves mail to Deleted Items, Junk, or RSS folders |
| `SUSPICIOUS_KEYWORD:<kw>` | Rule condition matches a finance or phishing keyword (invoice, wire, payment, etc.) |

### Mail Forwarding

| Flag | Meaning |
|------|---------|
| `EXTERNAL_SMTP_FORWARD:<addr>` | Mailbox SMTP forwarding points to an external address |
| `INTERNAL_SMTP_FORWARD:<addr>` | Mailbox SMTP forwarding points to an internal address |
| `FORWARDING_ADDRESS:<addr>` | Forwarding address object configured on the mailbox |
| `NO_LOCAL_COPY:victim_receives_nothing` | `DeliverToMailboxAndForward = false` — victim never sees the mail |

### OAuth Grants

| Flag | Meaning |
|------|---------|
| `HIGH_RISK_SCOPE:<scope>` | App holds a high-risk delegated permission: `Mail.Read`, `Mail.ReadWrite`, `Files.ReadWrite.All`, `Directory.ReadWrite.All`, `full_access_as_user`, `offline_access`, etc. |

### Conditional Access Policies

| Flag | Meaning |
|------|---------|
| `POLICY_DISABLED` | CA policy exists but is in disabled state |
| `POLICY_REPORT_ONLY` | CA policy is in report-only mode — not enforced |
| `NO_MFA_REQUIREMENT` | Policy has grant controls but does not require MFA |
| `EXCLUDES_USERS:<n>` | Policy excludes N specific users from scope |
| `EXCLUDES_GROUPS:<n>` | Policy excludes N groups from scope |

### Service Principals

| Flag | Meaning |
|------|---------|
| `NO_VERIFIED_PUBLISHER` | App has no verified publisher |
| `MANY_CREDENTIALS:<n>` | App has an unusually high number of client secrets or certificates |
| `LOCALHOST_REPLY_URL:<url>` | App has a localhost redirect URI |
| `DISABLED_WITH_CREDENTIALS` | Disabled service principal still has active credentials |

---

## Cross-Collector Correlation

After every workflow run, CIRRUS automatically runs a correlation engine that reads all collector output files, links events across data sources, and produces findings that are only visible when multiple collectors are viewed together.

Re-run manually on any existing case with:

```bash
cirrus analyze investigations/CONTOSO_20260317_143022
```

### Correlation Rules

| Rule | Severity | Pattern |
|------|----------|---------|
| `suspicious_signin_then_persistence` | **HIGH** | Sign-in with device code / impossible travel / geo-risk + new MFA method or device registered in same window |
| `password_reset_then_mfa_registered` | **HIGH** | Admin password reset + new MFA method for the same user — attacker locks out victim, registers own authenticator |
| `privilege_escalation_after_signin` | **HIGH** | Suspicious sign-in activity + high-privilege role assigned to the same user in the same window |
| `oauth_phishing_pattern` | **HIGH** | Device code / ROPC authentication + high-risk OAuth grant (mail read, file access) for the same user |
| `bec_attack_pattern` | **HIGH** | Any sign-in activity + inbox rule with forwarding / deletion / hiding or external SMTP forwarding |
| `device_code_then_device_registered` | **HIGH** | Device code phishing sign-in + new device registered — attacker obtains a PRT that survives password resets |
| `new_account_with_signin` | **MEDIUM** | Recently-created user account with active sign-in events — potential attacker backdoor account |
| `cross_ip_correlation` | **MEDIUM** | Same public IP in both sign-in logs and directory audit logs — same session performed auth and directory changes |

Three output files are written to the case folder:
- `ioc_correlation.json` — machine-readable findings (suitable for SIEM ingestion)
- `ioc_correlation.txt` — formatted report for analyst review and case documentation
- `investigation_report.html` — self-contained HTML report with correlation findings, IOC timeline, per-user summary, and per-collector flagged record tables

---

## Chain of Custody

Every case folder contains `case_audit.jsonl` — an append-only log of every action CIRRUS took. Each entry records:

- UTC timestamp, analyst username, and hostname
- OS platform
- Action taken (auth, collection start/complete, error, workflow events, correlation)
- Record count and SHA-256 hash of each output artifact
- SHA-256 hash of the previous log entry (tamper-evident chain)

```bash
cirrus case verify investigations/CONTOSO_20260317_143022
# ✓ Audit chain integrity verified
```

If any entry has been modified after the fact, the hash chain will fail and CIRRUS will report exactly which entries are suspect.

---

## CIS Compliance Checks

All 34 checks attempt automation first. Checks marked **Hybrid** use PowerShell modules when available and fall back to step-by-step manual instructions.

| Section | Graph API | Hybrid (PS/DNS) | Total |
|---------|-----------|-----------------|-------|
| 1 — Identity & Access Management | 10 | 1 | 11 |
| 2 — M365 Administration | 5 | 0 | 5 |
| 3 — Exchange Online | 0 | 8 | 8 |
| 4 — Microsoft Teams | 0 | 3 | 3 |
| 5 — SharePoint & OneDrive | 0 | 3 | 3 |
| 6 — Logging & Monitoring | 0 | 4 | 4 |
| **Total** | **15** | **19** | **34** |

---

## Roadmap

- [ ] App registration / service principal auth (`--client-id` / `--client-secret`) for unattended/automated collection
- [ ] Additional correlation rules (password spray detection, mass mail access / exfiltration indicators)
- [ ] SIEM push integrations (Splunk HEC, Microsoft Sentinel)
- [x] Quick triage command (`cirrus triage`) — 8 parallel checks, results in seconds
- [x] HTML investigation report (`investigation_report.html`) — self-contained, print-friendly, offline-capable
- [x] Cross-collector correlation engine (8 rules, auto-runs after every workflow)
- [x] Account Takeover (ATO) investigation workflow
- [x] BEC+ATO combined full attack chain workflow
- [x] Registered devices and app registrations collectors
- [x] IOC flagging across all collectors (sign-in, audit, MFA, users, devices, app registrations)
- [x] Exchange Online automated checks (PS batch via `ExchangeOnlineManagement`)
- [x] Teams automated checks (PS batch via `MicrosoftTeams`)
- [x] SharePoint automated checks (PS batch via `Microsoft.Online.SharePoint.PowerShell`)
- [x] Audit log retention automation (IPPS policy query + license-tier inference)

---

## Contributing

Contributions are welcome. To add a new collector:

1. Create `cirrus/collectors/your_collector.py` inheriting from `GraphCollector`
2. Implement `collect(**kwargs) -> list[dict]`
3. Add it to the appropriate workflow in `cirrus/workflows/`

To add a CIS compliance check:

1. Add a class inheriting from `BaseCheck` (automated) or `ManualCheck` (manual) in the appropriate `cirrus/compliance/checks/` file
2. Add it to the `*_CHECKS` list at the bottom of that file

Please open an issue before starting large changes.

---

## License

MIT — see [LICENSE](LICENSE) for details.
