# CIRRUS
### Cloud Incident Response & Reconnaissance Utility Suite

[![Build](https://github.com/ctrlaltdean/cirrus/actions/workflows/build.yml/badge.svg)](https://github.com/ctrlaltdean/cirrus/actions/workflows/build.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

CIRRUS is a command-line tool for collecting forensic artifacts from Microsoft 365 and Entra ID (Azure AD) tenants during security incidents and compliance reviews. Designed for MSSP environments — it runs on analyst machines without any complex setup, supports multiple tenants, and produces clean output suitable for investigations, reporting, and evidence preservation.

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
  - [Investigation Workflows](#investigation-workflows)
  - [Compliance Audit](#compliance-audit)
  - [Dependency Management](#dependency-management)
  - [Case Management](#case-management)
- [Output Structure](#output-structure)
- [IOC Flags](#ioc-flags)
- [Chain of Custody](#chain-of-custody)
- [CIS Compliance Checks](#cis-compliance-checks)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## Features

| Feature | Description |
|---|---|
| **BEC Workflow** | Targeted 10-step collection for Business Email Compromise investigations |
| **Full Tenant Sweep** | Complete collection across all supported data sources |
| **CIS Compliance Audit** | 31 checks against CIS M365 & Entra ID Benchmarks with wizard UI |
| **Multi-Tenant** | Authenticate to and collect from multiple client tenants independently |
| **Flexible Targeting** | Single user, multiple users, file list, or entire tenant |
| **Chain of Custody** | Tamper-evident SHA-256 hash chain audit log per case |
| **Dual Output** | Every collector writes JSON + CSV |
| **IOC Flagging** | Collectors auto-annotate records with `_iocFlags` for quick triage |
| **Standalone Executable** | Single file download — no Python required on analyst machines |
| **Cross-Platform** | Windows, macOS, and Linux |

---

## Quick Start

```
cirrus run bec --tenant contoso.com --user john@contoso.com
```

That's it. CIRRUS opens a browser for authentication, collects all BEC-relevant artifacts for the target user, flags IOCs, writes JSON and CSV output, and records a chain-of-custody log. The whole run takes under two minutes on a typical tenant.

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
# Download, rename for convenience, and run
Rename-Item cirrus-windows-x64.exe cirrus.exe
.\cirrus.exe --help
```

**macOS / Linux:**
```bash
chmod +x cirrus-macos-x64
mv cirrus-macos-x64 cirrus
./cirrus --help
```

> **Tip:** Move the executable to a folder on your PATH (e.g. `C:\Tools` on Windows, `/usr/local/bin` on Mac/Linux) so you can run `cirrus` from any directory.

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

```bash
# Authenticate to a tenant (opens browser)
cirrus auth login --tenant contoso.com

# See all tenants with cached credentials
cirrus auth status

# Remove cached credentials for a tenant
cirrus auth logout --tenant contoso.com
```

---

### Investigation Workflows

#### BEC — Business Email Compromise

Targeted collection for a known (or suspected) compromised account. Collects in the order that best supports timeline reconstruction.

**What it collects:**
1. Target user details
2. Sign-in logs (last N days)
3. Entra directory audit logs (password resets, MFA changes, role assignments)
4. Risky user scores (Identity Protection)
5. Risky sign-in events
6. MFA / authentication methods (look for attacker-added methods)
7. Mailbox inbox rules (hide/forward/delete rules)
8. Mailbox forwarding settings (SMTP forwarding to external address)
9. OAuth app grants (malicious app consent)
10. Unified Audit Log — `MailItemsAccessed`, forwarding rules, file downloads

```bash
# Single user — most common
cirrus run bec --tenant contoso.com --user john@contoso.com

# Multiple users
cirrus run bec --tenant contoso.com \
  --users john@contoso.com \
  --users jane@contoso.com

# Load targets from a text file (one UPN per line)
cirrus run bec --tenant contoso.com --users-file targets.txt

# Extend the collection window
cirrus run bec --tenant contoso.com --user john@contoso.com --days 90

# Custom case name for your ticketing system
cirrus run bec --tenant contoso.com --user john@contoso.com --case-name INC-2026-042

# Custom output directory
cirrus run bec --tenant contoso.com --user john@contoso.com --output-dir D:\Cases
```

If you run `cirrus run bec --tenant contoso.com` without specifying a user, CIRRUS will prompt you interactively to choose a targeting method.

---

#### Full Tenant Collection

Sweeps the entire tenant for all supported artifact types. Use when the compromised account is not yet identified, or for proactive threat hunting.

**Collects everything in BEC, plus:** Conditional Access policies, Service Principals.

```bash
# Full sweep, all users, 90-day window
cirrus run full --tenant contoso.com --all-users --days 90

# Targeted to specific users but collecting all artifact types
cirrus run full --tenant contoso.com --users-file vip_users.txt
```

> **Note:** Full tenant sweeps on large tenants (1000+ users) can take 15–30 minutes and generate large output files. Consider using the BEC workflow with targeted users first if a compromised account is known.

---

### Compliance Audit

Checks your tenant configuration against **CIS Microsoft 365 Foundations Benchmark** and **CIS Entra ID Benchmark** controls. Each check reports `PASS`, `FAIL`, `WARN`, or `MANUAL` (with step-by-step verification instructions for checks that require PowerShell or the admin portal).

#### Interactive Wizard (Default)

Run with no flags to launch the guided wizard:

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

Ready to run. Proceed? [Y/n]:
```

> **Note:** Before authenticating, CIRRUS checks for optional PowerShell module dependencies (`ExchangeOnlineManagement`, `MicrosoftTeams`, `Microsoft.Online.SharePoint.PowerShell`) and shows their status. Missing modules fall back to manual instructions — they are not required to run the audit.

#### Direct Flags (Scripted / Automated)

```bash
# Full audit, all benchmarks
cirrus run audit --tenant contoso.com --benchmark all --level all

# CIS M365 Level 1 only
cirrus run audit --tenant contoso.com --benchmark cis-m365 --level 1

# Entra ID checks only, both levels
cirrus run audit --tenant contoso.com --benchmark cis-entra --level all

# Print to screen only, no output files written
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
  ...

  Summary:  14 PASS  7 FAIL  3 WARN  14 MANUAL  0 ERROR
```

> **Checks total 34.** The wizard prompt shows the actual count for the selected benchmark and level combination.

#### CIS Controls Coverage

All 34 checks attempt automation first. Checks marked **Hybrid** use PowerShell modules (`ExchangeOnlineManagement`, `MicrosoftTeams`, `Microsoft.Online.SharePoint.PowerShell`) when available and fall back to step-by-step manual instructions if the module is not installed or authentication fails.

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

### Dependency Management

CIRRUS checks PowerShell module availability automatically before each compliance audit. You can also check and install dependencies manually:

```bash
# Show status of all optional PowerShell modules and dnspython
cirrus deps check

# Install any missing dependencies (prompts for confirmation)
cirrus deps install
```

| Dependency | Purpose | Required? |
|------------|---------|-----------|
| `ExchangeOnlineManagement` | Automates Exchange, DKIM, UAL, and logging checks | Optional |
| `MicrosoftTeams` | Automates Teams external access, guest, and meeting checks | Optional |
| `Microsoft.Online.SharePoint.PowerShell` | Automates SharePoint sharing and legacy auth checks | Optional |
| `dnspython` | DNS-based DMARC / SPF checks | Optional |

Missing modules are installed via `Install-Module` (PowerShell Gallery) for PS modules and `pip` for Python packages.

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

## Output Structure

Every workflow run creates a timestamped case folder:

```
investigations/
└── CONTOSO_20260317_143022/
    ├── case_audit.jsonl                ← tamper-evident chain-of-custody log
    ├── case_audit.txt                  ← human-readable audit log
    │
    ├── users.json / .csv
    ├── signin_logs.json / .csv
    ├── entra_audit_logs.json / .csv
    ├── risky_users.json / .csv
    ├── risky_signins.json / .csv
    ├── mfa_methods.json / .csv
    ├── mailbox_rules.json / .csv
    ├── mail_forwarding.json / .csv
    ├── oauth_grants.json / .csv
    ├── conditional_access_policies.json / .csv
    ├── service_principals.json / .csv
    ├── unified_audit_log.json / .csv
    │
    └── compliance_audit.json / .csv / .txt   ← audit workflow only
```

---

## IOC Flags

Collectors annotate each record with a `_iocFlags` list. Records with flags should be reviewed first. The `_iocFlags` field appears in both JSON and CSV output.

| Flag | Collector | Meaning |
|------|-----------|---------|
| `EXTERNAL_SMTP_FORWARD:<addr>` | Mail Forwarding | Mailbox forwards to an external address |
| `NO_LOCAL_COPY:victim_receives_nothing` | Mail Forwarding | Forwarding set and `DeliverToMailboxAndForward = false` |
| `FORWARDS_TO:<addr>` | Mailbox Rules | Inbox rule forwards to external address |
| `PERMANENT_DELETE` | Mailbox Rules | Rule permanently deletes matching mail |
| `MARKS_AS_READ` | Mailbox Rules | Rule silently marks mail as read |
| `SUSPICIOUS_KEYWORD:<kw>` | Mailbox Rules | Rule condition matches finance/phishing keyword |
| `HIGH_RISK_SCOPE:<scope>` | OAuth Grants | App has a high-risk permission (Mail.Read, etc.) |
| `NO_MFA_REQUIREMENT` | Conditional Access | Policy does not require MFA |
| `POLICY_DISABLED` | Conditional Access | CA policy is disabled |
| `NO_VERIFIED_PUBLISHER` | Service Principals | App has no verified publisher |
| `MANY_CREDENTIALS:<n>` | Service Principals | App has an unusual number of client secrets/certs |

---

## Chain of Custody

Every case folder contains `case_audit.jsonl` — an append-only log of every action CIRRUS took during the investigation. Each entry records:

- UTC timestamp
- Analyst username and hostname
- OS platform
- Action taken (auth, collection start/complete, error, workflow events)
- Record count and SHA-256 hash of each output artifact
- SHA-256 hash of the previous log entry (tamper-evident chain)

Verify a case's integrity at any time:

```bash
cirrus case verify investigations/CONTOSO_20260317_143022
# ✓ Audit chain integrity verified
```

If any entry has been modified after the fact, the hash chain will fail and CIRRUS will report exactly which entries are suspect.

---

## Roadmap

- [ ] App registration / service principal auth (`--client-id` / `--client-secret`)
- [ ] Account Takeover (ATO) investigation workflow
- [ ] HTML investigation report with timeline visualization
- [ ] SIEM export (CEF, Splunk HEC, Microsoft Sentinel)
- [ ] Additional detection / analysis rules
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
