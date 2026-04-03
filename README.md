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
- [Authentication & Consent](#authentication--consent)
  - [What appears during login](#what-appears-during-login)
  - [Permissions requested and why](#permissions-requested-and-why)
  - [Admin consent](#admin-consent)
  - [Token cache and security](#token-cache-and-security)
  - [Using a custom app registration](#using-a-custom-app-registration)
- [Required Roles](#required-roles)
  - [Minimum roles by workflow](#minimum-roles-by-workflow)
  - [Provisioning a dedicated investigation account](#provisioning-a-dedicated-investigation-account)
- [Commands](#commands)
  - [Authentication](#authentication)
  - [Quick Triage](#quick-triage)
  - [IP Enrichment](#ip-enrichment)
  - [Domain Enrichment](#domain-enrichment)
  - [Blast Radius](#blast-radius)
  - [Threat Hunt](#threat-hunt)
  - [Compliance Audit](#compliance-audit)
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
| **Quick Triage + Handoff Package** | 8 parallel checks on a suspected compromised account — creates a case folder with SIEM-ready evidence and a structured `triage_report.json`. Add `--workflow` to run the full BEC+ATO collection in the same pass. Cyber team receives one ready-to-analyze package. |
| **IP Enrichment** | Enrich all IPs in a case with geolocation, ASN, and threat intel (datacenter/proxy/Tor/VPN). Free via ip-api.com; optional AbuseIPDB abuse scoring |
| **Blast Radius** | Map a compromised account's full access footprint — directory roles, groups, app roles, owned objects, OAuth grants, and recent sign-in apps — in parallel |
| **BEC Workflow** | Targeted 10-step collection for Business Email Compromise investigations |
| **ATO Workflow** | 11-step Account Takeover investigation — authentication layer, persistence, and exfiltration |
| **BEC+ATO Workflow** | Combined 13-step full attack chain — most BEC incidents begin with an ATO event |
| **Full Tenant Sweep** | Complete collection across all supported data sources |
| **Cross-Collector Correlation** | Post-collection engine links events across collectors to surface multi-source attack patterns including hosting-provider sign-ins |
| **HTML Investigation Report** | Single self-contained HTML report with correlation findings, IOC timeline, IP enrichment tab, and per-collector tables |
| **CIS Compliance Audit** | 34 checks against CIS M365 & Entra ID Benchmarks with wizard UI |
| **License-Aware Collection** | Detects tenant license tier (P1/P2/E5) and gracefully skips unsupported endpoints |
| **Multi-Tenant** | Authenticate to and collect from multiple client tenants independently |
| **Flexible Targeting** | Single user, multiple users, file list, or entire tenant |
| **Chain of Custody** | Tamper-evident SHA-256 hash chain audit log per case |
| **Excel Master Workbook** | All triage and collection CSVs combined into `analysis.xlsx` — open directly in Excel for analyst review |
| **Triple Output** | Every collector writes JSON + CSV + NDJSON (SOF-ELK ready); JSON/NDJSON organized into a `json/` subfolder to keep analyst-facing CSVs at the top level |
| **IOC Flagging** | Collectors auto-annotate records with `_iocFlags` for quick triage |
| **Auto-Update** | Checks for new releases in the background; update in one command |
| **Standalone Executable** | Single file download — no Python required on analyst machines |
| **Cross-Platform** | Windows, macOS, and Linux |

---

## Quick Start

**Helpdesk triage — fast first-look, creates a handoff package:**
```bash
cirrus triage --tenant contoso.com --user john@contoso.com
```
Runs 8 checks in ~30 seconds and creates a case folder with `triage_report.json`, SIEM-ready NDJSON, and `analysis.xlsx` for immediate review in Excel. Hand the folder to your cyber team.

**Include full BEC+ATO collection in the same pass:**
```bash
cirrus triage --tenant contoso.com --user john@contoso.com --workflow
```
Triage + full collection in one command. One case folder, complete evidence package ready for analysis.

**Cyber team picks up the case:**
```bash
cirrus analyze investigations/CONTOSO_20260317_143022   # correlation + HTML report
cirrus enrich  investigations/CONTOSO_20260317_143022   # IP enrichment

# Or extend a triage-only case with full BEC+ATO collection:
cirrus run bec-ato --tenant contoso.com --existing-case investigations/CONTOSO_20260317_143022
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

## Authentication & Consent

### What appears during login

When you run any CIRRUS command that accesses a tenant for the first time, a browser window opens to the Microsoft login page. After signing in, you may see a consent screen that says:

> **Microsoft Graph Command Line Tools** — *Microsoft Corporation (Verified publisher)*
> *This app would like to:* [list of permissions]

This is expected. CIRRUS authenticates using Microsoft's own pre-registered public client application ("Microsoft Graph Command Line Tools," app ID `14d82eec-204b-4c2f-b7e8-296a70dab67e`). It is a Microsoft-owned, verified-publisher app — not a third-party application. Microsoft built it specifically for CLI tools and scripts that need to call the Graph API.

**CIRRUS requests only read-only delegated permissions.** Delegated means the token is tied to the signed-in account — CIRRUS can only access data the analyst themselves is authorized to see. It cannot read anything beyond what the signed-in account's roles permit.

### Permissions requested and why

| Scope | Used for |
|---|---|
| `AuditLog.Read.All` | Sign-in logs, Entra directory audit events |
| `Directory.Read.All` | Users, groups, devices, app registrations, Conditional Access policies |
| `Policy.Read.All` | Authorization policies, authentication strength policies |
| `MailboxSettings.Read` | Mailbox forwarding configuration (SMTP forwarding) |
| `User.Read.All` | User profiles, assigned licenses, identity federation |
| `IdentityRiskyUser.Read.All` | Entra Identity Protection — user risk state and history |
| `IdentityRiskEvent.Read.All` | Entra Identity Protection — individual risk detections |
| `UserAuthenticationMethod.Read.All` | Registered MFA methods (authenticator apps, FIDO2 keys, phone numbers, etc.) |
| `AuditLogsQuery.Read.All` | Unified Audit Log (Exchange, SharePoint, Teams activity) |
| `SecurityEvents.Read.All` | Microsoft Defender security alerts |
| `Reports.Read.All` | M365 usage and activity reports (compliance audit) |
| `RoleManagement.Read.Directory` | Directory role assignments — who holds which admin roles |

### Admin consent

Many hardened enterprise tenants disable user-level consent and require an administrator to pre-approve any application. If the analyst account cannot consent on its own, a **Global Administrator** in the customer tenant must grant admin consent for the application before CIRRUS can authenticate.

To grant admin consent, the Global Admin opens:
```
https://login.microsoftonline.com/<tenant-id>/adminconsent?client_id=14d82eec-204b-4c2f-b7e8-296a70dab67e
```

After approval, all users in the tenant can use the application without individual consent prompts.

### Token cache and security

CIRRUS caches tokens in `~/.cirrus/token_cache.json`. This file contains refresh tokens — treat it as sensitive. On shared analyst workstations, run `cirrus auth logout` at the end of each session. The cache is per-tenant; credentials for one tenant are never used to access another.

### Using a custom app registration

Organizations that want CIRRUS to appear under their own display name in customer tenants can register their own Azure app and pass its client ID at runtime:

```bash
cirrus run bec --tenant contoso.com --client-id <your-app-id>
```

The `--client-id` flag is supported on every command that authenticates. See the Microsoft documentation on registering a multi-tenant public client application for setup steps.

---

## Required Roles

CIRRUS uses **delegated permissions** — the signed-in account must hold the roles that authorize access to the data being collected. This section covers what roles are needed and how to configure a dedicated investigation account when one needs to be provisioned ad hoc.

### Minimum roles by workflow

| Workflow | Minimum roles required |
|---|---|
| `cirrus triage` | Global Reader + Security Reader + Exchange Recipient Administrator ¹ |
| `cirrus run bec` | Global Reader + Security Reader + Exchange Recipient Administrator ¹ |
| `cirrus run ato` | Global Reader + Security Reader |
| `cirrus run bec-ato` | Global Reader + Security Reader + Exchange Recipient Administrator ¹ |
| `cirrus run full` | Global Reader + Security Reader + Exchange Recipient Administrator ¹ |
| `cirrus run audit` | Global Reader + Security Reader (+ Exchange Administrator for PowerShell checks) |

¹ Required for inbox rules and mail forwarding checks. Without this role those collectors are skipped — all other collectors continue normally. See [Exchange Recipient Administrator](#exchange-recipient-administrator-inbox-rules--mail-forwarding) below.

### What each role covers

**Global Reader** *(mandatory for all workflows)*
Provides read access to nearly all Microsoft 365 and Entra ID data via Graph API: users, groups, devices, audit logs, sign-in logs, app registrations, Conditional Access policies, role assignments, reports, and the Unified Audit Log. This single role satisfies the majority of what CIRRUS collects.

**Security Reader** *(mandatory for all workflows)*
Required for Identity Protection data (risky user state, risk detections) and Microsoft Defender security events. Without this role, triage and workflow runs will skip Identity Protection checks but otherwise function normally.

**Exchange Recipient Administrator** *(inbox rules + mail forwarding)*
Required to read inbox rules (`/mailFolders/inbox/messageRules`) and mailbox forwarding settings (`/mailboxSettings`) for users other than the signed-in account. This is a two-part requirement:

1. **Admin consent for `MailboxSettings.Read`** must be granted in the tenant. This scope is in CIRRUS's request list but is flagged by Microsoft as requiring admin consent — tokens issued without admin consent will not include it, and API calls return 403 even though the scope appears correct. Use the admin consent URL in the [Admin Consent](#admin-consent) section to approve it once per tenant.

2. **Exchange Recipient Administrator role** (or Exchange Administrator) on the investigation account. Global Reader covers Entra ID and M365 admin surfaces but does not grant delegated access to other users' Exchange mailbox data. Exchange Recipient Administrator is the minimum Exchange role that provides read access to mailbox properties for other users.

Without Exchange Recipient Administrator, inbox rule and mail forwarding checks are skipped in both triage and BEC/BEC+ATO/Full workflow runs. All other collectors continue to function normally.

**Important limitation — MFA methods for admin accounts:**
`UserAuthenticationMethod.Read.All` with delegated permissions has a Microsoft-enforced restriction: accounts holding admin roles (Global Admin, Exchange Admin, etc.) have their MFA methods protected. Global Reader can read MFA methods for non-admin users but **cannot** read MFA methods for accounts that hold any administrator role. To read MFA methods for admin accounts, the investigation account itself must hold **Privileged Authentication Administrator**. This is a higher-privilege role — evaluate whether it is appropriate for the engagement before requesting it.

**Exchange Administrator** *(compliance audit only)*
Required only for `cirrus run audit` when Exchange Online PowerShell checks are enabled. The PowerShell module (`ExchangeOnlineManagement`) connects separately from Graph API and uses its own authentication.

### Provisioning a dedicated investigation account

When a customer needs to create an account specifically for a CIRRUS engagement, provide them with these instructions:

**Account requirements:**
- Account type: Member (not Guest) in the customer's Entra ID tenant
- License: Any M365 license that enables the account to sign in (Microsoft 365 F1 or above is sufficient — a full E3/E5 license is not required for the investigation account itself, though the **tenant** must have appropriate licenses for the data to exist)
- MFA: Required — the account must have MFA configured before CIRRUS can use it

**Role assignments** (minimum for investigation workflows):
```
Global Reader
Security Reader
```

**Role assignments** (recommended — adds inbox rules + mail forwarding checks):
```
Global Reader
Security Reader
Exchange Recipient Administrator
```
Also requires admin consent for `MailboxSettings.Read` — see [Admin Consent](#admin-consent).

**Role assignments** (if compliance audit is in scope):
```
Global Reader
Security Reader
Exchange Administrator
```

**Role assignments** (if MFA methods of admin accounts must be collected):
```
Global Reader
Security Reader
Privileged Authentication Administrator
```

> **Note:** Privileged Authentication Administrator is a sensitive role that can modify authentication methods for other users, including Global Administrators. If requesting this role, document the business justification clearly and ensure it is revoked at engagement close.

**How to assign roles in the Entra admin center:**

1. Sign in to [https://entra.microsoft.com](https://entra.microsoft.com)
2. Navigate to: **Identity → Users → [select the account]**
3. Select **Assigned roles → Add assignments**
4. Search for and assign each role listed above

**Account offboarding after the engagement:**

At engagement close, the investigation account should be disabled or deleted, and the CIRRUS application entry removed from Enterprise Applications. CIRRUS provides a cleanup command to assist:

```bash
# Clears local credentials and provides exact admin instructions for tenant cleanup
cirrus auth cleanup --tenant contoso.com
```

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

# Clear credentials and print tenant-side cleanup instructions for an admin
cirrus auth cleanup --tenant contoso.com
```

---

### Quick Triage

Runs 8 targeted checks on a suspected compromised account **in parallel** and creates a **handoff package** — a timestamped case folder containing structured findings and raw evidence ready for the cyber team or SIEM ingestion.

**Checks (all run simultaneously):**

| Check | What it looks for | Output file (in `triage/`) |
|---|---|---|
| Sign-in activity | Unusual countries, impossible travel, device code/ROPC, legacy auth, risk signals | `sign_ins` |
| MFA methods | Recently added methods, FIDO2 keys, external email OTP, multiple authenticator apps | `mfa_methods` |
| Inbox rules | Forwarding rules, permanent delete, hidden-folder rules, finance keywords | `inbox_rules` |
| Mail forwarding | External SMTP forward, no-local-copy configuration | `mail_forwarding` |
| OAuth grants | High-risk scopes (Mail.Read, Files.ReadWrite.All, full_access_as_user, etc.) | `oauth_grants` |
| Registered devices | Recently registered, personal/BYOD devices | `devices` |
| Directory audit | MFA changes, admin password resets, role assignments in the window | `audit_activity` |
| Identity Protection | Risk state and risk level (skipped gracefully if no Entra ID P2) | `risky_status` |

Each check writes a `.csv` to `triage/` and `.json` / `.ndjson` to `triage/json/`. `triage_report.json` contains the full structured findings with verdict, flags, and check results for every user. When triage completes, `analysis.xlsx` is generated at the case root combining all triage CSVs into a single workbook.

```bash
# Single user — creates case folder with triage evidence package
cirrus triage --tenant contoso.com --user john@contoso.com

# Wider window
cirrus triage --tenant contoso.com --user john@contoso.com --days 14

# Triage + full BEC+ATO collection in one command (complete handoff package)
cirrus triage --tenant contoso.com --user john@contoso.com --workflow

# Triage + collection, skip correlation (collect-only handoff — cyber team analyzes)
cirrus triage --tenant contoso.com --user john@contoso.com --workflow --collect-only

# Multiple users
cirrus triage --tenant contoso.com --users john@contoso.com --users jane@contoso.com

# From a file (one UPN per line, # comments ignored)
cirrus triage --tenant contoso.com --users-file suspects.txt

# Interactive wizard — prompts for all inputs; offers to run BEC+ATO if verdict is HIGH/WARN
cirrus triage
```

**Handoff workflow:**

| Role | Command |
|---|---|
| Helpdesk — quick triage only | `cirrus triage --tenant contoso.com --user john@contoso.com` |
| Helpdesk — full package | `cirrus triage --tenant contoso.com --user john@contoso.com --workflow` |
| Cyber — extend triage case | `cirrus run bec-ato --tenant contoso.com --existing-case investigations/CASE_DIR/` |
| Cyber — correlation + report | `cirrus analyze investigations/CASE_DIR/` |
| Cyber — IP enrichment | `cirrus enrich investigations/CASE_DIR/` |

**Case folder contents after triage:**
```
CONTOSO_20260317_143022/
├── case_audit.jsonl          ← tamper-evident chain-of-custody (SHA-256 chained)
├── case_audit.txt            ← human-readable audit log
├── triage_report.json        ← structured findings: verdict, flags, checks per user
├── analysis.xlsx             ← all triage CSVs in one Excel workbook
├── triage/                   ← analyst-facing CSVs
│   ├── sign_ins.csv
│   ├── mfa_methods.csv
│   ├── inbox_rules.csv
│   ├── mail_forwarding.csv
│   ├── oauth_grants.csv
│   ├── devices.csv
│   ├── audit_activity.csv
│   ├── risky_status.csv
│   └── json/                 ← SIEM / tool-format files
│       ├── sign_ins.json / .ndjson
│       └── ...
```
With `--workflow`, the full BEC+ATO collector outputs are added to a `collection/` subfolder in the same case folder.

**Sample terminal output:**
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

  john@contoso.com  Verdict: HIGH RISK  4/7 checks flagged

╭─ Triage Complete — Handoff Package Ready ─────────────────────────────────╮
│  Overall verdict: HIGH RISK                                                │
│  Case folder:     investigations/CONTOSO_20260317_143022                   │
│                                                                            │
│  To add full BEC+ATO collection, the cyber team can run:                   │
│    cirrus run bec-ato --tenant contoso.com \                               │
│      --existing-case investigations/CONTOSO_20260317_143022                │
╰────────────────────────────────────────────────────────────────────────────╯
```

---

### IP Enrichment

Enriches every public IP address found in a collected case with geolocation, ASN, hosting/proxy/Tor indicators, and optionally AbuseIPDB abuse scores. Writes `ip_enrichment.json` to the case folder without modifying any collector files.

> **Why opt-in?** Enrichment makes external network calls to third-party services. Running it automatically during every workflow would add latency and make offline-only collection impossible. Run it explicitly once collection is complete.

**Data sources:**

| Source | Key required? | What it provides |
|--------|--------------|-----------------|
| [ip-api.com](https://ip-api.com) | No | Country, city, ASN, org/ISP, datacenter flag, proxy flag, Tor exit flag |
| [AbuseIPDB](https://www.abuseipdb.com) | Yes (free) | Abuse confidence score (0–100), total abuse reports |

**AbuseIPDB setup (one-time):**
1. Register for a free account at [abuseipdb.com/register](https://www.abuseipdb.com/register)
2. Generate an API key from your dashboard
3. Set it in your shell: `export ABUSEIPDB_KEY=your_key_here`

```bash
# Enrich IPs in a case folder — ip-api.com only (no key needed)
cirrus enrich investigations/CONTOSO_20260317_143022

# With AbuseIPDB abuse scores
cirrus enrich investigations/CONTOSO_20260317_143022 --abuseipdb-key YOUR_KEY

# Using the environment variable (recommended — set once in your shell profile)
export ABUSEIPDB_KEY=your_key_here
cirrus enrich investigations/CONTOSO_20260317_143022
```

**Sample output:**
```
                    IP Enrichment — 6 address(es)
┌─────────────────┬─────────┬──────────────┬────────────────────────────┬────────────────────┬────────┐
│ IP Address      │ Country │ City         │ ASN / Org                  │ Flags              │ Abuse% │
├─────────────────┼─────────┼──────────────┼────────────────────────────┼────────────────────┼────────┤
│ 185.220.101.42  │ DE      │ Frankfurt    │ AS4224 Tor Project         │ TOR_EXIT_NODE      │ 100    │
│ 45.142.212.100  │ NL      │ Amsterdam    │ AS209588 Serverius         │ DATACENTER/HOSTING │ 82     │
│ 104.26.12.55    │ US      │ San Jose     │ AS13335 Cloudflare         │ —                  │ 0      │
│ 8.8.8.8         │ US      │ Ashburn      │ AS15169 Google LLC         │ DATACENTER/HOSTING │ 0      │
│ 198.51.100.5    │ GB      │ London       │ AS12345 Some VPN Ltd       │ PROXY/VPN          │ 45     │
│ 2.56.188.21     │ RU      │ Moscow       │ AS57523 Chang Way Tech     │ —                  │ 12     │
└─────────────────┴─────────┴──────────────┴────────────────────────────┴────────────────────┴────────┘

Total: 6 IP(s)  3 suspicious
Output: investigations/CONTOSO_20260317_143022/ip_enrichment.json
```

Once `ip_enrichment.json` exists, re-running `cirrus analyze` will automatically include:
- An **IP Enrichment tab** in `investigation_report.html` with the full enrichment table
- A new `hosting_provider_signin` correlation finding for any successful sign-in from a datacenter, proxy, or Tor IP

---

### Domain Enrichment

Extracts external domains from IOC flags in collector output (forwarding addresses, SMTP forward targets, external email OTP addresses) and enriches each with registration data and DNS checks. No API key required.

**Data collected per domain:**

| Check | Source |
|-------|--------|
| Registration date and domain age | RDAP (via IANA bootstrap) |
| Registrar name | RDAP |
| MX records — routes to consumer provider? | DNS |
| SPF record present | DNS TXT |
| DMARC record present | DNS TXT `_dmarc.*` |

**Threat tags applied automatically:**

| Tag | Meaning |
|-----|---------|
| `NEW_DOMAIN` | Domain registered within the last 30 days |
| `CONSUMER_MX` | Mail routes to Gmail, Outlook.com, Yahoo, etc. |
| `NO_MX` | Domain has no mail exchanger |
| `NO_SPF` | No SPF record — domain can be freely spoofed |
| `NO_DMARC` | No DMARC record — no enforcement policy |

```bash
cirrus enrich-domains investigations/CONTOSO_20260317_143022
```

Writes `domain_enrichment.json` to the case folder. A **Domains tab** appears in `investigation_report.html` when you next run `cirrus analyze`.

---

### Blast Radius

Maps the full access footprint of a potentially compromised account by querying Microsoft Graph for all access dimensions in parallel. No case folder is required — results display in the terminal immediately. Use this early in an investigation to understand what an attacker could reach if the account is compromised.

**Access dimensions checked (all run simultaneously):**

| Dimension | What it looks for |
|---|---|
| Directory roles | Entra ID directory roles assigned — flags Global Administrator and other admin roles as HIGH |
| Group memberships | Group memberships — flags role-assignable groups as HIGH |
| App role assignments | Application permissions granted to the user — flags high-impact permissions (Mail.ReadWrite, Files.ReadWrite.All, etc.) |
| Owned objects | Objects owned by this account — flags owned app registrations (an attacker can add credentials to these) |
| OAuth grants | Delegated permission grants — flags high-risk scopes |
| Recent sign-in apps | Applications this account has authenticated to recently |

```bash
# Assess a single account
cirrus blast-radius --tenant contoso.com --user john@contoso.com

# Save results to an existing case folder
cirrus blast-radius --tenant contoso.com --user john@contoso.com \
  --case-dir investigations/CONTOSO_20260317_143022

# Multiple users from a file
cirrus blast-radius --tenant contoso.com --users-file suspects.txt

# Interactive wizard
cirrus blast-radius
```

**Sample output:**
```
  ✗  Directory roles          HIGH    2 role(s) — 2 HIGH-PRIVILEGE
       → [HIGH] Global Administrator
       → [HIGH] Exchange Administrator
  ✓  Group memberships        CLEAN   3 group(s)
  ✗  App role assignments     HIGH    1 app role(s) — 1 high-impact
       → [HIGH] Microsoft Graph — Mail.ReadWrite.All
  ⚠  Owned objects            WARN    2 object(s): 1× application, 1× group
       → [HIGH] App registration: Contoso Reporting App
  ✗  OAuth grants (delegated) HIGH    3 grant(s) — 2 with high-risk scopes
       → [HIGH] App d1e3f2a… — scopes: Mail.ReadWrite, Files.ReadWrite.All
  ⚠  Recent sign-in apps      WARN    12 sign-in(s) · 7 distinct app(s)

╭─ User: john@contoso.com   Risk: HIGH RISK   4/5 dimensions flagged ──────────────────╮
│  High-privilege indicators:                                                           │
│    → HIGH_PRIV_ROLE:Global Administrator                                              │
│    → HIGH_PRIV_ROLE:Exchange Administrator                                            │
│    → HIGH_APP_ROLE:Microsoft Graph:Mail.ReadWrite.All                                 │
╰───────────────────────────────────────────────────────────────────────────────────────╯
```

If `--case-dir` is provided, results are written to `blast_radius.json` in that folder.

---

### Threat Hunt

Performs a proactive tenant-wide threat hunt without a known starting account. Runs 5 checks in parallel and surfaces suspicious targets ranked by signal count. Use this for initial discovery before pivoting to a targeted triage or workflow run.

**Hunt checks:**

| Check | What it surfaces |
|---|---|
| Sign-in anomalies | Accounts with device code auth, impossible travel, legacy auth, or high Identity Protection risk scores |
| Stale accounts | Enabled, licensed accounts with no sign-in activity in the last N days (default 90) — prime low-noise ATO targets |
| Risky OAuth apps | Apps with high-risk scopes (Mail.Read, Files.ReadWrite.All, etc.) consented by multiple users or via admin consent for all users |
| Password spray | Source IPs attempting authentication against many distinct accounts within a short window |
| Privileged new accounts | Recently created accounts that already hold a privileged directory role |

```bash
# Hunt across the last 30 days (default)
cirrus hunt --tenant contoso.com

# Shorter window
cirrus hunt --tenant contoso.com --days 14

# Adjust stale account threshold
cirrus hunt --tenant contoso.com --stale-days 60

# Interactive wizard
cirrus hunt
```

**Sample output:**
```
                    Hunt Results — 3 suspicious target(s)
┏━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Severity ┃ Type   ┃ Target                         ┃ Signals ┃ Top Signal                          ┃
┡━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ HIGH     │ user   │ john@contoso.com               │       3 │ device_code sign-in from 185.x.x.x  │
│ HIGH     │ app    │ Contoso Reporting App           │       2 │ Mail.ReadWrite consented by 14 users │
│ MEDIUM   │ ip     │ 185.220.101.45                 │       1 │ spray: 47 targets, 3 successes       │
└──────────┴────────┴────────────────────────────────┴─────────┴─────────────────────────────────────┘
```

No case folder is created — use `cirrus triage` or a workflow command to collect evidence on flagged accounts.

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
| Sign-in logs | ✓ ¹ | ✓ | ✓ | ✓ | ✓ |
| Entra audit logs | ✓ ¹ | ✓ | ✓ | ✓ | ✓ |
| MFA methods | ✓ ¹ | ✓ | ✓ | ✓ | ✓ |
| Risky users / sign-ins | ✓ ¹ | ✓ | ✓ | ✓ | ✓ |
| Conditional Access | | | ✓ | ✓ | ✓ |
| Registered devices | ✓ ¹ | | ✓ | ✓ | |
| OAuth grants | ✓ ¹ | ✓ | ✓ | ✓ | ✓ |
| App registrations | | | ✓ | ✓ | |
| Mailbox rules | ✓ ¹ | ✓ | | ✓ | ✓ |
| Mail forwarding | ✓ ¹ | ✓ | | ✓ | ✓ |
| UAL | | ✓ | ✓ | ✓ | ✓ |
| Service principals | | | | | ✓ |
| Case folder / files | ✓ | ✓ | ✓ | ✓ | ✓ |
| Correlation + HTML report | optional ² | optional | optional | optional | optional |

¹ Triage collects a limited snapshot (up to 50 records per check) — sufficient for verdict, not full forensic depth. Use `--workflow` or `cirrus run bec-ato --existing-case` for complete paginated collection.
² With `--workflow`, triage runs correlation automatically; without it, run `cirrus analyze <case_dir>` manually.

---

### Post-Collection Analysis

After collection completes, CIRRUS runs the cross-collector correlation engine and generates an HTML investigation report. How this works depends on how you invoked the workflow:

**Interactive wizard (no `--tenant` flag):** CIRRUS prompts after the collection summary:
```
Run correlation analysis and generate HTML report? [Y/n]
```
Answer `n` to skip and move on immediately — you can always run it later.

**Scripted mode (`--tenant` provided):** Analysis runs automatically unless you pass `--collect-only`.

**`--collect-only` flag:** Skips analysis entirely for maximum speed. Use this when you know exactly what you need and time is critical — evidence is captured and preserved, analysis can follow later.

```bash
# Scripted — evidence only, no analysis
cirrus run ato --tenant contoso.com --user john@contoso.com --days 30 --collect-only

# Run analysis on any case folder at any time
cirrus analyze investigations/CONTOSO_20260317_143022
```

`cirrus analyze` is also useful when you want to re-run correlation after adding new collectors, pulling in data from another tool, or regenerating the report after manually reviewing output files.

It writes:
- `ioc_correlation.json` — machine-readable findings (SIEM-ingestible)
- `ioc_correlation.txt` — formatted text report for case notes
- `investigation_report.html` — full self-contained HTML investigation report
- `analysis.xlsx` — all triage and collection CSVs combined into a single Excel workbook

See [Cross-Collector Correlation](#cross-collector-correlation) for the full list of detection rules.

**Optional enrichment step:** After collection, run `cirrus enrich` to annotate all IPs with geolocation, ASN, and threat intelligence. The enrichment results are folded into the HTML report as a dedicated tab and unlock the `hosting_provider_signin` correlation rule:

```bash
# Collect evidence
cirrus run ato --tenant contoso.com --user john@contoso.com --days 30

# Enrich IPs (run after collection)
cirrus enrich investigations/CONTOSO_20260317_143022

# Re-run analysis to pick up the new correlation rule and add the IP tab to the report
cirrus analyze investigations/CONTOSO_20260317_143022
```

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

Every workflow run creates a timestamped case folder. Analyst-facing CSVs sit at the top level of each subfolder; JSON and NDJSON are grouped under `json/` to keep SIEM-format files out of the way:

```
investigations/
└── CONTOSO_20260317_143022/
    ├── case_audit.jsonl                ← tamper-evident chain-of-custody log
    ├── case_audit.txt                  ← human-readable audit log
    ├── triage_report.json              ← structured triage findings (triage runs only)
    ├── ioc_correlation.json            ← cross-collector findings (machine-readable)
    ├── ioc_correlation.txt             ← formatted correlation report
    ├── investigation_report.html       ← self-contained HTML investigation report
    ├── analysis.xlsx                   ← all triage + collection CSVs in one workbook
    │
    ├── triage/                         ← quick-triage check outputs
    │   ├── sign_ins.csv
    │   ├── mfa_methods.csv
    │   ├── inbox_rules.csv
    │   ├── mail_forwarding.csv
    │   ├── oauth_grants.csv
    │   ├── devices.csv
    │   ├── audit_activity.csv
    │   ├── risky_status.csv
    │   └── json/                       ← SIEM / tool-format files
    │       ├── sign_ins.json / .ndjson
    │       └── ...
    │
    └── collection/                     ← workflow collector outputs
        ├── users.csv
        ├── signin_logs.csv
        ├── entra_audit_logs.csv
        ├── mfa_methods.csv
        ├── risky_users.csv             ← P2 license required
        ├── risky_signins.csv           ← P2 license required
        ├── registered_devices.csv      ← ATO / BEC+ATO workflows
        ├── app_registrations.csv       ← ATO / BEC+ATO workflows
        ├── mailbox_rules.csv
        ├── mail_forwarding.csv
        ├── oauth_grants.csv
        ├── conditional_access_policies.csv  ← P1 license required
        ├── sp_signin_logs.csv          ← P1 license required
        ├── service_principals.csv      ← full workflow only
        ├── unified_audit_log.csv
        └── json/                       ← SIEM / tool-format files
            ├── signin_logs.json / .ndjson
            ├── unified_audit_log.json / .ndjson   ← UAL NDJSON is SOF-ELK normalized
            └── ...
```

Each collector produces three output files:
- **`.json`** — Pretty-printed JSON array. Human-readable, easy to open in any editor or `jq`.
- **`.csv`** — Flattened CSV in `triage/` or `collection/`. Analyst-facing; also the source for `analysis.xlsx`.
- **`.ndjson`** — JSON Lines (one object per line). Ready for SOF-ELK, Elastic, or any Logstash pipeline.

### SOF-ELK Ingestion

[SOF-ELK](https://github.com/philhagen/sof-elk) automatically ingests files placed in specific directories on the VM:

| Collector | SOF-ELK target directory |
|-----------|--------------------------|
| `unified_audit_log.ndjson` | `/logstash/microsoft365/` |
| `signin_logs.ndjson` | `/logstash/azure/` |
| `entra_audit_logs.ndjson` | `/logstash/azure/` |

```bash
scp investigations/CONTOSO_20260317_143022/collection/json/unified_audit_log.ndjson \
    analyst@sofelk:/logstash/microsoft365/

scp investigations/CONTOSO_20260317_143022/collection/json/signin_logs.ndjson \
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
| `password_spray` | **HIGH / MEDIUM** | Single IP with 10+ failures across 5+ accounts. Elevated to HIGH when the same IP also has a successful sign-in |
| `mass_mail_access` | **HIGH / MEDIUM** | 50+ MailItemsAccessed UAL events for a single user. Elevated to HIGH when the user also has interactive sign-in activity |
| `new_account_with_signin` | **MEDIUM** | Recently-created user account with active sign-in events — potential attacker backdoor account |
| `cross_ip_correlation` | **MEDIUM** | Same public IP in both sign-in logs and directory audit logs — same session performed auth and directory changes |
| `hosting_provider_signin` | **MEDIUM** | Successful sign-in from an IP identified as a datacenter, hosting provider, proxy, or Tor exit node. Requires `ip_enrichment.json` (run `cirrus enrich` first) |

Three output files are written to the case folder:
- `ioc_correlation.json` — machine-readable findings (suitable for SIEM ingestion)
- `ioc_correlation.txt` — formatted report for analyst review and case documentation
- `investigation_report.html` — self-contained HTML report with correlation findings, IOC timeline, per-user summary, per-collector flagged record tables, and optional IP enrichment tab

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

**In progress / next up:**
- [ ] Service principal sign-in logs collector — closes the blind spot where attackers pivot to OAuth app tokens after initial compromise; separate Graph endpoint from user sign-ins
- [ ] Tenant-wide OAuth app inventory — which apps have been granted consent across the tenant in the last N days; identifies rogue app phishing campaigns
- [ ] MITRE ATT&CK mapping — attach technique IDs (T1078, T1528, T1110.003, etc.) to correlation findings for SIEM integration and reporting
- [ ] Remediation checklist — dedicated report section mapping each finding to a prioritised, checkbox-style action list

**Planned:**
- [ ] Executive summary / management report — non-technical 1-page summary for client handoff
- [ ] Case notes (`cirrus case note`) — analyst annotations that persist into the HTML report
- [ ] App registration / service principal auth (`--client-id` / `--client-secret`) for unattended/automated collection
- [ ] SIEM push integrations (Splunk HEC, Microsoft Sentinel)
- [ ] Watch mode (`cirrus watch`) — recurring triage on a watchlist; useful for active retainers

**Completed:**
- [x] PIM role activation history — Privileged Identity Management activation logs with IOC flags for high-priv activations, missing justification, unusual hours, and self-activation (T1548)
- [x] Evidence packaging (`cirrus case package`) — zip with SHA-256 chain-of-custody manifest for legal handoff
- [x] Domain enrichment (`cirrus enrich-domains`) — RDAP registration age and MX/SPF/DMARC lookups on forwarding destinations and external email addresses
- [x] VirusTotal enrichment — extend `cirrus enrich --vt-key` with VT IP reputation alongside AbuseIPDB
- [x] Conditional Access coverage gaps — correlation rule identifies successful sign-ins that matched zero CA policies (T1078)
- [x] Tenant-wide threat hunt (`cirrus hunt`) — 5 parallel checks surface suspicious accounts, risky OAuth apps, password spray sources, and stale licensed accounts across the whole tenant without a known starting account
- [x] Stale account enumeration — `cirrus hunt` flags enabled/licensed users with no sign-in in 90+ days (prime low-noise ATO targets)
- [x] IP enrichment (`cirrus enrich`) — geo/ASN/hosting/proxy/Tor via ip-api.com + optional AbuseIPDB abuse scoring
- [x] Blast radius assessment (`cirrus blast-radius`) — 6 parallel Graph API checks mapping account access footprint
- [x] Additional correlation rules: password spray, mass mail access, hosting-provider sign-in (11 rules total)
- [x] Triage handoff package — `cirrus triage` now creates a case folder with SIEM-ready NDJSON per check, `triage_report.json` (structured verdict + flags), and chain-of-custody audit log; `--workflow` adds full BEC+ATO collection in the same pass; `cirrus run bec/ato/bec-ato` accept `--existing-case` to extend a triage case
- [x] Quick triage command (`cirrus triage`) — 8 parallel checks, results in seconds
- [x] HTML investigation report (`investigation_report.html`) — self-contained, print-friendly, offline-capable, with IP enrichment tab
- [x] Cross-collector correlation engine (auto-runs after every workflow)
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
