"""
CIRRUS CLI — main entry point.

Commands:
    cirrus auth login     — authenticate to a tenant
    cirrus auth logout    — clear cached credentials
    cirrus auth status    — show cached tenants
    cirrus auth cleanup   — clear credentials and print tenant cleanup instructions

    cirrus run bec        — run BEC investigation workflow
    cirrus run full       — run full-tenant collection
    cirrus run ato        — run ATO investigation workflow
    cirrus run bec-ato    — run combined BEC+ATO full attack chain workflow

    cirrus triage         — quick targeted checks on a suspected compromised account
    cirrus enrich         — enrich IPs from an existing case with geo/ASN/threat data
    cirrus blast-radius   — map access dimensions of a potentially compromised account
    cirrus analyze        — re-run cross-collector correlation on an existing case
    cirrus case verify    — verify chain-of-custody integrity for a case folder

Global options available on every command:
    --tenant       Tenant domain or GUID (required for run/collect commands)
    --output-dir   Where to write case folders (default: ./investigations)
    --case-name    Custom case name prefix
    --days         Days back to collect (default: 30)
    --user         Single target user UPN
    --users        Multiple target user UPNs (can be repeated)
    --users-file   Path to a text file with one UPN per line
    --all-users    Target the entire tenant (no user filter)
"""

from __future__ import annotations

import json
import sys
import time as _time
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from cirrus import __version__
from cirrus.auth.authenticator import (
    DEFAULT_CLIENT_ID,
    AuthenticationError,
    get_token,
    get_token_silent,
    list_cached_tenants,
    logout,
    lookup_service_principal,
)
from cirrus.compliance.report import render_terminal, save_report
from cirrus.compliance.runner import ComplianceRunner
from cirrus.output.case import Case
from cirrus.utils.deps import (
    DepStatus,
    check_all,
    install_all_missing,
)
from cirrus.utils.helpers import file_sha256
from cirrus.utils.updater import apply_update, check_for_update, is_frozen
from cirrus.workflows.ato import ATOWorkflow
from cirrus.workflows.base import render_summary
from cirrus.workflows.bec import BECWorkflow
from cirrus.workflows.bec_ato import BECATOWorkflow
from cirrus.workflows.full import FullWorkflow

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = typer.Typer(
    name="cirrus",
    help="CIRRUS — Cloud Incident Response & Reconnaissance Utility Suite",
    no_args_is_help=True,
    rich_markup_mode="rich",
)
auth_app = typer.Typer(help="Manage authentication and cached credentials.", no_args_is_help=True)
run_app = typer.Typer(help="Run investigation workflows.", no_args_is_help=True)
case_app = typer.Typer(help="Manage investigation cases.", no_args_is_help=True)
deps_app = typer.Typer(help="Check and install optional dependencies.", no_args_is_help=True)

app.add_typer(auth_app, name="auth")
app.add_typer(run_app, name="run")
app.add_typer(case_app, name="case")
app.add_typer(deps_app, name="deps")

console = Console()

DEFAULT_OUTPUT_DIR = Path("investigations")

# ---------------------------------------------------------------------------
# Silent update check (runs at banner display, rate-limited to once/24 h)
# ---------------------------------------------------------------------------

_UPDATE_CACHE = Path.home() / ".cirrus_update_check.json"
_UPDATE_CACHE_TTL = 86_400  # 24 hours in seconds


def _silent_update_check() -> None:
    """
    Non-blocking update notification.

    Checks the GitHub Releases API at most once per 24 hours (result cached
    in ~/.cirrus_update_check.json).  Uses a 3-second timeout so it never
    blocks a workflow.  All errors are silently ignored.
    """
    try:
        now = _time.time()
        cached: dict | None = None

        if _UPDATE_CACHE.exists():
            try:
                data = json.loads(_UPDATE_CACHE.read_text(encoding="utf-8"))
                if now - data.get("checked_at", 0) < _UPDATE_CACHE_TTL:
                    cached = data
            except Exception:
                pass

        if cached is None:
            info = check_for_update(timeout=3)
            if not info.error:
                cache_data = {
                    "checked_at": now,
                    "latest_version": info.latest_version,
                    "update_available": info.update_available,
                }
                try:
                    _UPDATE_CACHE.write_text(
                        json.dumps(cache_data), encoding="utf-8"
                    )
                except Exception:
                    pass
                cached = cache_data

        if cached and cached.get("update_available"):
            latest = cached.get("latest_version", "?")
            console.print(
                f"  [yellow]↑ Update available: v{latest}[/yellow]  "
                "[dim]Run [bold]cirrus update[/bold] to install.[/dim]"
            )
    except Exception:
        pass  # never surface update-check failures to the user

# ---------------------------------------------------------------------------
# Shared option types
# ---------------------------------------------------------------------------

TenantOpt = Annotated[str, typer.Option("--tenant", "-t", help="Tenant domain or GUID (e.g. contoso.com or <guid>)")]
OutputDirOpt = Annotated[Path, typer.Option("--output-dir", "-o", help="Directory to write case folders to.", show_default=True)]
CaseNameOpt = Annotated[Optional[str], typer.Option("--case-name", "-c", help="Custom case name prefix.")]
DaysOpt = Annotated[Optional[int], typer.Option("--days", "-d", help="Days back to collect (alternative to --start-date / --end-date).")]
StartDateOpt = Annotated[Optional[str], typer.Option("--start-date", help="Collection start date, YYYY-MM-DD (alternative to --days).")]
EndDateOpt = Annotated[Optional[str], typer.Option("--end-date", help="Collection end date, YYYY-MM-DD (default: today). Use with --start-date.")]
UserOpt = Annotated[Optional[str], typer.Option("--user", help="Single target user by UPN/email (e.g. john@contoso.com).")]
UsersOpt = Annotated[Optional[list[str]], typer.Option("--users", help="Target users by UPN/email — repeat flag for each (e.g. --users john@contoso.com --users jane@contoso.com).")]
UsersFileOpt = Annotated[Optional[Path], typer.Option("--users-file", help="Text file with one UPN per line. Lines starting with # are ignored.")]
AllUsersOpt = Annotated[bool, typer.Option("--all-users", help="Collect for all users in the tenant (no user filter). Use with caution on large tenants.")]
ClientIdOpt = Annotated[Optional[str], typer.Option("--client-id", help="Override the Azure app registration client ID (default: Microsoft Graph Command Line Tools).")]
# Optional tenant for run commands — prompts interactively if omitted.
TenantRunOpt = Annotated[Optional[str], typer.Option("--tenant", "-t", help="Tenant domain or GUID (e.g. contoso.com or <azure-ad-guid>). Prompted if omitted.")]
BenchmarkOpt = Annotated[Optional[str], typer.Option("--benchmark", "-b", help="Benchmark: cis-m365, cis-entra, or all. Omit to use the wizard.")]
LevelOpt = Annotated[Optional[str], typer.Option("--level", "-l", help="CIS levels: 1, 2, or all. Omit to use the wizard.")]
OptionalTenantOpt = Annotated[Optional[str], typer.Option("--tenant", "-t", help="Tenant domain or GUID. Prompted if omitted.")]
CollectOnlyOpt = Annotated[bool, typer.Option("--collect-only", help="Collect evidence only — skip correlation analysis and HTML report. Fastest option when you know exactly what you need.")]
ExistingCaseOpt = Annotated[Optional[Path], typer.Option("--existing-case", help="Continue collection into an existing case folder instead of creating a new one.")]

_DATE_FMT = "%Y-%m-%d"
# Maximum UAL retention periods (informational — shown in the wizard).
_UAL_RETENTION_STANDARD = 90
_UAL_RETENTION_E5 = 180


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _banner(skip_update_check: bool = False) -> None:
    console.print(
        Panel.fit(
            f"[bold cyan]CIRRUS[/bold cyan] [dim]v{__version__}[/dim]\n"
            "[dim]Cloud Incident Response & Reconnaissance Utility Suite[/dim]",
            border_style="bright_blue",
        )
    )
    if not skip_update_check:
        _silent_update_check()


def _validate_upn(upn: str) -> str | None:
    """Return an error string if the UPN looks wrong, else None."""
    if " " in upn:
        return f"'{upn}' contains spaces — UPNs must not have spaces."
    parts = upn.split("@")
    if len(parts) != 2:
        return f"'{upn}' must contain exactly one '@' character."
    local, domain = parts
    if not local:
        return f"'{upn}' has an empty local part before '@'."
    if "." not in domain:
        return f"'{upn}' domain part '{domain}' does not contain a '.' — expected e.g. contoso.com."
    return None


def _prompt_tenant() -> str:
    """Interactively prompt for a tenant domain or GUID."""
    console.print("[bold]Tenant[/bold]")
    console.print(
        "[dim]Enter the Microsoft 365 tenant domain or Azure AD tenant GUID.\n"
        "Examples:  contoso.com   contoso.onmicrosoft.com   xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx[/dim]"
    )
    while True:
        value = Prompt.ask("Tenant").strip()
        if value:
            return value
        console.print("[red]Tenant is required.[/red]")


def _show_run_summary(
    workflow: str,
    tenant: str,
    users: list[str] | None,
    start_dt: datetime,
    end_dt: datetime,
    output_dir: Path,
    case_name: str | None,
) -> None:
    """Print a pre-run confirmation summary panel and prompt to proceed."""
    span_days = (end_dt - start_dt).days + 1
    date_range = (
        f"{start_dt.strftime(_DATE_FMT)} \u2192 {end_dt.strftime(_DATE_FMT)}  ({span_days} days)"
    )
    targets = ", ".join(users) if users is not None else "All users in tenant"
    workflow_label = {
        "bec": "BEC Investigation",
        "ato": "ATO Investigation",
        "bec-ato": "BEC + ATO Investigation",
        "full": "Full Tenant Collection",
    }.get(workflow, workflow.upper())
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Key", style="bold", min_width=14)
    table.add_column("Value", style="cyan")
    table.add_row("Workflow", workflow_label)
    table.add_row("Tenant", tenant)
    table.add_row("Targets", targets)
    table.add_row("Date range", date_range)
    table.add_row("Output dir", str(output_dir))
    table.add_row("Case name", case_name if case_name else "auto-generated")
    console.print(
        Panel(
            table,
            title=f"[bold]{workflow_label} \u2014 Collection Summary[/bold]",
            border_style="bright_blue",
        )
    )
    if not Confirm.ask("[bold]Ready to proceed?[/bold]", default=True):
        raise typer.Exit(0)


def _resolve_users(
    user: str | None,
    users: list[str] | None,
    users_file: Path | None,
    all_users: bool,
) -> list[str] | None:
    """
    Merge user targeting flags into a single list.
    Returns None if --all-users is set.
    Prompts the analyst if nothing is specified.
    """
    if all_users:
        return None

    result: list[str] = []
    if user:
        result.append(user.strip())
    if users:
        result.extend(u.strip() for u in users if u.strip())
    if users_file:
        if not users_file.exists():
            console.print(f"[red]Users file not found:[/red] {users_file}")
            raise typer.Exit(1)
        lines = users_file.read_text().splitlines()
        result.extend(line.strip() for line in lines if line.strip() and not line.startswith("#"))

    if result:
        return result

    # Interactive prompt — nothing was specified via flags
    console.print("\n[bold]No target user specified.[/bold]")
    console.print(
        "[dim]A User Principal Name (UPN) is the account's sign-in email address.\n"
        "  Example:  john@contoso.com   or   john@contoso.onmicrosoft.com[/dim]\n"
    )
    console.print("[bold]How would you like to target users?[/bold]\n")
    console.print("  [cyan]1[/cyan]  Single user        [dim]e.g. john@contoso.com[/dim]")
    console.print("  [cyan]2[/cyan]  Multiple users     [dim]comma-separated, e.g. john@contoso.com, jane@contoso.com[/dim]")
    console.print("  [cyan]3[/cyan]  Load from file     [dim]plain text file with one UPN per line[/dim]")
    console.print("  [cyan]4[/cyan]  All users          [dim]no user filter — collects entire tenant (slow on large tenants)[/dim]")
    console.print()
    choice = Prompt.ask("Choice", choices=["1", "2", "3", "4"])

    if choice == "1":
        while True:
            upn = Prompt.ask("Enter user UPN [dim](e.g. john@contoso.com)[/dim]").strip()
            err = _validate_upn(upn)
            if err:
                console.print(f"[red]Invalid UPN:[/red] {err}")
            else:
                break
        return [upn]
    elif choice == "2":
        while True:
            raw = Prompt.ask(
                "Enter UPNs [dim](comma-separated, e.g. john@contoso.com, jane@contoso.com)[/dim]"
            ).strip()
            entries = [u.strip() for u in raw.split(",") if u.strip()]
            if not entries:
                console.print("[red]At least one UPN is required.[/red]")
                continue
            errors = [(u, _validate_upn(u)) for u in entries if _validate_upn(u)]
            if errors:
                for u, err in errors:
                    console.print(f"[red]Invalid UPN:[/red] {err}")
            else:
                break
        return entries
    elif choice == "3":
        while True:
            path_str = Prompt.ask(
                "Path to users file [dim](full path, e.g. C:\\suspects.txt or ./targets.txt)[/dim]"
            ).strip()
            p = Path(path_str)
            if not p.exists():
                console.print(f"[red]File not found:[/red] {p}  — check the path and try again.")
                continue
            break
        lines = p.read_text().splitlines()
        file_entries = [line.strip() for line in lines if line.strip() and not line.startswith("#")]
        if not file_entries:
            console.print(f"[red]No UPNs found in[/red] {p}. File must contain one UPN per line.")
            raise typer.Exit(1)
        bad = [(e, _validate_upn(e)) for e in file_entries if _validate_upn(e)]
        for entry, err in bad:
            console.print(f"[yellow]Warning — skipping invalid UPN in file:[/yellow] {err}")
        file_entries = [e for e in file_entries if not _validate_upn(e)]
        if not file_entries:
            console.print("[red]No valid UPNs remain after validation. Aborting.[/red]")
            raise typer.Exit(1)
        return file_entries
    else:
        return None  # all users


def _authenticate(tenant: str, client_id: str | None = None) -> tuple[str, str]:
    """
    Authenticate to the tenant and return (access_token, tenant).
    Handles errors with friendly messages.
    """
    kwargs = {}
    if client_id:
        kwargs["client_id"] = client_id
    try:
        console.print(f"\n[bold]Authenticating to:[/bold] [cyan]{tenant}[/cyan]")
        console.print(
            "[dim]A browser window will open. Sign in with a Microsoft 365 account that has "
            "one of the following roles:\n"
            "  \u2022 Global Reader  (recommended \u2014 read-only, broad access)\n"
            "  \u2022 Security Reader + Exchange Administrator  (for mailbox data)\n"
            "  \u2022 Global Administrator  (if the above roles are insufficient)\n"
            "Credentials are cached locally \u2014 you will not be prompted again unless the token expires.[/dim]\n"
        )
        token = get_token(tenant, **kwargs)
        console.print("[green]✓ Authentication successful[/green]\n")
        return token, tenant
    except AuthenticationError as e:
        console.print(f"[red]Authentication failed:[/red] {e}")
        raise typer.Exit(1)


def _resolve_date_range(
    days: int | None,
    start_date: str | None,
    end_date: str | None,
) -> tuple[datetime, datetime]:
    """
    Resolve the collection date range from CLI flags or interactive wizard.

    Priority:
      1. --start-date / --end-date  →  parse and return, no prompt
      2. --days                     →  compute from now, no prompt
      3. Neither provided           →  launch interactive wizard

    Returns (start_dt, end_dt) as UTC-aware datetimes.
    """
    today_end = datetime.now(timezone.utc).replace(
        hour=23, minute=59, second=59, microsecond=0
    )

    def _parse_date(s: str, flag: str) -> datetime:
        try:
            return datetime.strptime(s, _DATE_FMT).replace(tzinfo=timezone.utc)
        except ValueError:
            console.print(
                f"[red]Invalid {flag} format:[/red] '{s}'. "
                f"Expected YYYY-MM-DD (e.g. 2026-03-01)."
            )
            raise typer.Exit(1)

    def _validate(start: datetime, end: datetime) -> None:
        if start >= end:
            console.print(
                "[red]Start date must be before end date.[/red]"
            )
            raise typer.Exit(1)
        span_days = (end - start).days
        if span_days > _UAL_RETENTION_E5:
            console.print(
                f"[yellow]⚠  Range spans {span_days} days — exceeds the maximum UAL "
                f"retention of {_UAL_RETENTION_E5} days (E5/Advanced Auditing). "
                "Records older than your tenant's retention limit will not appear.[/yellow]"
            )
        if end > datetime.now(timezone.utc) + timedelta(minutes=5):
            console.print(
                "[yellow]⚠  End date is in the future — collection will stop at the "
                "latest available record.[/yellow]"
            )

    # --- Flag path: --start-date provided ---
    if start_date:
        start_dt = _parse_date(start_date, "--start-date")
        end_dt = _parse_date(end_date, "--end-date") if end_date else today_end
        end_dt = end_dt.replace(hour=23, minute=59, second=59)
        _validate(start_dt, end_dt)
        return start_dt, end_dt

    # --- Flag path: --days provided ---
    if days is not None:
        start_dt = datetime.now(timezone.utc) - timedelta(days=days)
        return start_dt, today_end

    # --- Interactive wizard ---
    console.print()
    console.print(
        Panel.fit(
            "[bold]Collection Date Range[/bold]\n"
            "[dim]Specify the window of logs to collect.[/dim]",
            border_style="bright_blue",
        )
    )
    console.print()

    # Retention reference table
    table = Table(show_header=True, header_style="bold", border_style="dim", box=None)
    table.add_column("Log type", style="cyan", min_width=28)
    table.add_column("Max retention", justify="right")
    table.add_column("Notes", style="dim")
    table.add_row(
        "Sign-in logs",
        "30 days",
        "Entra ID P1 required",
    )
    table.add_row(
        "Entra directory audit logs",
        "30 days",
        "Entra ID P1 required",
    )
    table.add_row(
        "Unified Audit Log (UAL)",
        f"{_UAL_RETENTION_STANDARD} days",
        f"{_UAL_RETENTION_E5} days with E5 / Advanced Auditing",
    )
    console.print(table)
    console.print()
    console.print(
        "  [dim]Enter dates in [bold]YYYY-MM-DD[/bold] format  "
        "(e.g. [bold]2026-03-01[/bold])[/dim]\n"
    )

    today_str = datetime.now(timezone.utc).strftime(_DATE_FMT)

    while True:
        start_str = Prompt.ask("  Start date [bold](YYYY-MM-DD)[/bold]").strip()
        if not start_str:
            console.print("  [red]Start date is required.[/red]")
            continue
        try:
            start_dt = datetime.strptime(start_str, _DATE_FMT).replace(tzinfo=timezone.utc)
            break
        except ValueError:
            console.print(
                f"  [red]Unrecognised date '[/red]{start_str}[red]' — use YYYY-MM-DD "
                f"(e.g. 2026-03-01).[/red]"
            )

    while True:
        end_str = Prompt.ask(
            f"  End date   [bold](YYYY-MM-DD)[/bold] [dim]press Enter for today ({today_str})[/dim]",
            default=today_str,
        ).strip()
        try:
            end_dt = datetime.strptime(end_str, _DATE_FMT).replace(
                hour=23, minute=59, second=59, tzinfo=timezone.utc
            )
            break
        except ValueError:
            console.print(
                f"  [red]Unrecognised date '[/red]{end_str}[red]' — use YYYY-MM-DD "
                f"(e.g. {today_str}).[/red]"
            )

    span = (end_dt - start_dt).days + 1
    console.print(
        f"\n  [green]✓[/green] Collecting [bold]{span} day(s)[/bold]  "
        f"[dim]({start_dt.strftime(_DATE_FMT)} → {end_dt.strftime(_DATE_FMT)})[/dim]\n"
    )

    _validate(start_dt, end_dt)
    return start_dt, end_dt


# ---------------------------------------------------------------------------
# auth commands
# ---------------------------------------------------------------------------

@auth_app.command("login")
def auth_login(
    tenant: TenantOpt,
    client_id: ClientIdOpt = None,
) -> None:
    """Authenticate to a Microsoft 365 tenant via interactive browser login."""
    _banner()
    _authenticate(tenant, client_id)
    console.print(f"[green]Credentials cached for[/green] [cyan]{tenant}[/cyan].")
    console.print("[dim]Run `cirrus auth status` to see all cached tenants.[/dim]")


@auth_app.command("logout")
def auth_logout(
    tenant: TenantOpt,
    client_id: ClientIdOpt = None,
) -> None:
    """Remove cached credentials for a tenant."""
    kwargs = {}
    if client_id:
        kwargs["client_id"] = client_id
    count = logout(tenant, **kwargs)
    if count:
        console.print(f"[green]Removed {count} cached account(s) for[/green] [cyan]{tenant}[/cyan].")
    else:
        console.print(f"[yellow]No cached credentials found for[/yellow] [cyan]{tenant}[/cyan].")


@auth_app.command("status")
def auth_status() -> None:
    """Show all tenants with cached credentials."""
    _banner()
    tenants = list_cached_tenants()
    if not tenants:
        console.print("[yellow]No cached credentials found.[/yellow]")
        console.print("[dim]Run `cirrus auth login --tenant <tenant>` to authenticate.[/dim]")
        return

    table = Table(title="Cached Credentials", border_style="bright_blue", header_style="bold magenta")
    table.add_column("Username")
    table.add_column("Tenant ID")
    table.add_column("Environment")
    for t in tenants:
        table.add_row(t["username"], t["tenant_id"], t["environment"])
    console.print(table)


@auth_app.command("cleanup")
def auth_cleanup(
    tenant: TenantOpt,
    client_id: ClientIdOpt = None,
) -> None:
    """
    Clear local credentials and print tenant-side cleanup instructions.

    Removes the cached token for the tenant, looks up the service principal
    that was created when CIRRUS authenticated (if a cached token is still
    available), and prints the exact PowerShell command and portal path an
    administrator needs to remove it from Enterprise Applications.

    Run this after an investigation is complete to leave no CIRRUS footprint
    in the customer tenant.
    """
    _banner(skip_update_check=True)
    effective_client_id = client_id or DEFAULT_CLIENT_ID

    # ── Step 1: Try a silent token lookup for the SP query ─────────────────
    console.print(f"\n[bold]Tenant:[/bold] [cyan]{tenant}[/cyan]\n")

    sp_id: str | None = None
    sp_name: str | None = None

    token = get_token_silent(tenant, effective_client_id)
    if token:
        console.print("[dim]Querying tenant for service principal...[/dim]")
        sp = lookup_service_principal(token, effective_client_id)
        if sp:
            sp_id = sp.get("id", "")
            sp_name = sp.get("displayName", "")
            console.print(
                Panel(
                    f"[bold]Display name:[/bold] {sp_name}\n"
                    f"[bold]App ID:[/bold]       {effective_client_id}\n"
                    f"[bold]SP Object ID:[/bold] [cyan]{sp_id}[/cyan]",
                    title="Service Principal Found",
                    border_style="bright_blue",
                )
            )
        else:
            console.print(
                "[yellow]Service principal not found in this tenant.[/yellow]\n"
                "[dim]It may have already been removed, or the account may not have "
                "consented yet.[/dim]"
            )
    else:
        console.print(
            "[yellow]No cached token available — cannot look up service principal.[/yellow]\n"
            "[dim]Run [bold]cirrus auth login[/bold] first if you need the SP Object ID.[/dim]"
        )

    # ── Step 2: Clear local token cache ────────────────────────────────────
    console.print()
    count = logout(tenant, effective_client_id)
    if count:
        console.print(f"[green]✓ Local token cache cleared[/green] — {count} cached account(s) removed for [cyan]{tenant}[/cyan].")
    else:
        console.print(f"[dim]No cached credentials found for {tenant} — local cache already clear.[/dim]")

    # ── Step 3: Admin instructions ─────────────────────────────────────────
    sp_id_display = sp_id or "<SP-Object-ID>"
    app_name_display = sp_name or (
        "Microsoft Graph Command Line Tools"
        if effective_client_id == DEFAULT_CLIENT_ID
        else effective_client_id
    )

    ps_block = (
        f"Connect-MgGraph -Scopes \"Application.ReadWrite.All\"\n"
        f"Remove-MgServicePrincipal -ServicePrincipalId {sp_id_display}"
    )
    if not sp_id:
        ps_block += (
            "\n\n# If you don't have the SP Object ID, find it first:\n"
            f"$sp = Get-MgServicePrincipal -Filter \"appId eq '{effective_client_id}'\"\n"
            f"Remove-MgServicePrincipal -ServicePrincipalId $sp.Id"
        )

    console.print(
        Panel(
            "[bold]PowerShell[/bold] [dim](Microsoft.Graph module required)[/dim]\n"
            f"  [cyan]{ps_block.replace(chr(10), chr(10) + '  ')}[/cyan]\n\n"
            "[bold]Entra admin center[/bold]\n"
            "  1. Sign in to https://entra.microsoft.com\n"
            f"  2. Navigate to: Identity → Applications → Enterprise applications\n"
            f"  3. Search for: [bold]{app_name_display}[/bold]\n"
            "  4. Open the result → Properties → Delete\n\n"
            "[dim]Deleting the service principal removes the entry from Enterprise\n"
            "Applications and revokes all delegated permission grants in one step.\n"
            "No further action is required after the SP is deleted.[/dim]",
            title="[bold]Tenant Cleanup — Admin Steps Required[/bold]",
            border_style="yellow",
        )
    )


# ---------------------------------------------------------------------------
# Analysis helper — prompt or flag, called after every workflow run
# ---------------------------------------------------------------------------

def _maybe_run_analysis(
    case: "Case",
    result: "WorkflowResult",
    collect_only: bool,
    interactive: bool,
) -> None:
    """
    Run cross-collector correlation + HTML report after a workflow completes.

    In scripted mode (tenant supplied via flag):  runs automatically unless
    --collect-only was passed.

    In interactive/wizard mode (tenant was prompted): asks the analyst before
    running, defaulting to yes.
    """
    if collect_only:
        console.print("[dim]Analysis skipped (--collect-only).[/dim]")
        return

    if interactive:
        console.print()
        if not Confirm.ask(
            "[bold]Run correlation analysis and generate HTML report?[/bold]",
            default=True,
        ):
            console.print(
                "[dim]Analysis skipped. Run [bold]cirrus analyze "
                f"{result.case_dir}[/bold] at any time to run it later.[/dim]"
            )
            return

    from cirrus.workflows.base import _run_correlation
    _run_correlation(case.case_dir, result, case)


# ---------------------------------------------------------------------------
# run commands
# ---------------------------------------------------------------------------

@run_app.command("bec")
def run_bec(
    tenant: TenantRunOpt = None,
    output_dir: OutputDirOpt = DEFAULT_OUTPUT_DIR,
    case_name: CaseNameOpt = None,
    days: DaysOpt = None,
    start_date: StartDateOpt = None,
    end_date: EndDateOpt = None,
    user: UserOpt = None,
    users: UsersOpt = None,
    users_file: UsersFileOpt = None,
    all_users: AllUsersOpt = False,
    client_id: ClientIdOpt = None,
    collect_only: CollectOnlyOpt = False,
    existing_case: ExistingCaseOpt = None,
) -> None:
    """
    [bold]BEC Investigation Workflow[/bold]

    Collects sign-in logs, audit events, inbox rules, forwarding settings,
    OAuth grants, MFA methods, risky user data, and the Unified Audit Log
    for target user(s).

    Run without flags to launch the interactive wizard.

    Examples (scripted):
        cirrus run bec --tenant contoso.com --user john@contoso.com --days 30
        cirrus run bec --tenant contoso.com --users john@contoso.com --users jane@contoso.com --start-date 2026-03-01 --end-date 2026-03-18
        cirrus run bec --tenant contoso.com --users-file targets.txt --days 14 --collect-only
        cirrus run bec --tenant contoso.com --all-users --start-date 2026-03-01 --end-date 2026-03-18
    """
    _banner()
    interactive = tenant is None
    if interactive:
        console.print(Panel.fit(
            "[bold]BEC Investigation Wizard[/bold]\n"
            "[dim]Answer a few questions to configure your collection run.\n"
            "Press Ctrl+C at any time to cancel.[/dim]",
            border_style="bright_blue",
        ))
        console.print()
        tenant = _prompt_tenant()
    else:
        console.print(f"[bold magenta]Workflow:[/bold magenta] Business Email Compromise (BEC)")
        console.print(f"[bold]Tenant:[/bold]  [cyan]{tenant}[/cyan]\n")

    target_users = _resolve_users(user, users, users_file, all_users)
    if target_users:
        console.print(f"[bold]Targets:[/bold] {', '.join(target_users)}\n")
    else:
        if not Confirm.ask("[yellow]⚠  No user filter — this will collect data for EVERY account in the tenant.\n   This can take a long time and produce large output files. Continue?[/yellow]"):
            raise typer.Exit(0)

    start_dt, end_dt = _resolve_date_range(days, start_date, end_date)

    if interactive and case_name is None:
        case_name_input = Prompt.ask(
            "Case name [dim](optional — e.g. INC-2026-001, leave blank to auto-generate)[/dim]",
            default="",
        ).strip()
        case_name = case_name_input or None

    _show_run_summary("bec", tenant, target_users, start_dt, end_dt, output_dir, case_name)

    token, _ = _authenticate(tenant, client_id)

    if existing_case:
        if not existing_case.exists():
            console.print(f"[red]Existing case not found:[/red] {existing_case}")
            raise typer.Exit(1)
        case = Case.open_existing(existing_case)
        console.print(f"[bold]Continuing case:[/bold] {case.case_dir}\n")
    else:
        output_dir.mkdir(parents=True, exist_ok=True)
        case = Case.create(tenant, output_dir, case_name)
        console.print(f"[bold]Case folder:[/bold] {case.case_dir}\n")

    case.audit.log_event("WORKFLOW_CONFIG", {
        "workflow": "bec",
        "tenant": tenant,
        "start_date": start_dt.strftime(_DATE_FMT),
        "end_date": end_dt.strftime(_DATE_FMT),
        "users": target_users or "all",
    })

    _client_id = client_id  # capture for closure
    token_provider = lambda: get_token(tenant, **({'client_id': _client_id} if _client_id else {}))
    workflow = BECWorkflow(token, case, token_provider=token_provider)
    result = workflow.run(
        users=target_users,
        tenant=tenant,
        start_dt=start_dt,
        end_dt=end_dt,
        run_analysis=False,
    )

    render_summary(result)
    if result.errors:
        console.print(f"[yellow]⚠ {len(result.errors)} collector(s) encountered errors. Check case_audit.txt for details.[/yellow]")
    console.print("[bold green]BEC collection complete.[/bold green]")

    _maybe_run_analysis(case, result, collect_only, interactive)
    case.close()


@run_app.command("ato")
def run_ato(
    tenant: TenantRunOpt = None,
    output_dir: OutputDirOpt = DEFAULT_OUTPUT_DIR,
    case_name: CaseNameOpt = None,
    days: DaysOpt = None,
    start_date: StartDateOpt = None,
    end_date: EndDateOpt = None,
    user: UserOpt = None,
    users: UsersOpt = None,
    users_file: UsersFileOpt = None,
    all_users: AllUsersOpt = False,
    client_id: ClientIdOpt = None,
    collect_only: CollectOnlyOpt = False,
    existing_case: ExistingCaseOpt = None,
) -> None:
    """
    [bold]Account Takeover (ATO) Investigation Workflow[/bold]

    Collects the authentication layer and persistence artifacts for an ATO
    investigation: sign-in logs, directory audit events, MFA methods, registered
    devices, Conditional Access policies, OAuth grants, newly created app
    registrations, and the Unified Audit Log.

    Use BEC when you already know the account was compromised and want to
    focus on mailbox-level artifacts (rules, forwarding). Use ATO when you
    are investigating the authentication event itself, looking for persistence
    mechanisms, or assessing blast radius.

    Run without flags to launch the interactive wizard.

    Examples (scripted):
        cirrus run ato --tenant contoso.com --user john@contoso.com --days 30
        cirrus run ato --tenant contoso.com --users john@contoso.com --users jane@contoso.com --start-date 2026-03-01 --end-date 2026-03-18
        cirrus run ato --tenant contoso.com --users-file targets.txt --days 14 --collect-only
        cirrus run ato --tenant contoso.com --all-users --start-date 2026-03-01 --end-date 2026-03-18
    """
    _banner()
    interactive = tenant is None
    if interactive:
        console.print(Panel.fit(
            "[bold]ATO Investigation Wizard[/bold]\n"
            "[dim]Answer a few questions to configure your collection run.\n"
            "Press Ctrl+C at any time to cancel.[/dim]",
            border_style="bright_blue",
        ))
        console.print()
        tenant = _prompt_tenant()
    else:
        console.print(f"[bold magenta]Workflow:[/bold magenta] Account Takeover (ATO) Investigation")
        console.print(f"[bold]Tenant:[/bold]  [cyan]{tenant}[/cyan]\n")

    target_users = _resolve_users(user, users, users_file, all_users)
    if target_users:
        console.print(f"[bold]Targets:[/bold] {', '.join(target_users)}\n")
    else:
        if not Confirm.ask("[yellow]⚠  No user filter — this will collect data for EVERY account in the tenant.\n   This can take a long time and produce large output files. Continue?[/yellow]"):
            raise typer.Exit(0)

    start_dt, end_dt = _resolve_date_range(days, start_date, end_date)

    if interactive and case_name is None:
        case_name_input = Prompt.ask(
            "Case name [dim](optional — e.g. INC-2026-001, leave blank to auto-generate)[/dim]",
            default="",
        ).strip()
        case_name = case_name_input or None

    _show_run_summary("ato", tenant, target_users, start_dt, end_dt, output_dir, case_name)

    token, _ = _authenticate(tenant, client_id)

    if existing_case:
        if not existing_case.exists():
            console.print(f"[red]Existing case not found:[/red] {existing_case}")
            raise typer.Exit(1)
        case = Case.open_existing(existing_case)
        console.print(f"[bold]Continuing case:[/bold] {case.case_dir}\n")
    else:
        output_dir.mkdir(parents=True, exist_ok=True)
        case = Case.create(tenant, output_dir, case_name)
        console.print(f"[bold]Case folder:[/bold] {case.case_dir}\n")

    case.audit.log_event("WORKFLOW_CONFIG", {
        "workflow": "ato",
        "tenant": tenant,
        "start_date": start_dt.strftime(_DATE_FMT),
        "end_date": end_dt.strftime(_DATE_FMT),
        "users": target_users or "all",
    })

    _client_id = client_id
    token_provider = lambda: get_token(tenant, **({'client_id': _client_id} if _client_id else {}))
    workflow = ATOWorkflow(token, case, token_provider=token_provider)
    result = workflow.run(
        users=target_users,
        tenant=tenant,
        start_dt=start_dt,
        end_dt=end_dt,
        run_analysis=False,
    )

    render_summary(result)
    if result.errors:
        console.print(f"[yellow]⚠ {len(result.errors)} collector(s) encountered errors. Check case_audit.txt for details.[/yellow]")
    console.print("[bold green]ATO collection complete.[/bold green]")

    _maybe_run_analysis(case, result, collect_only, interactive)
    case.close()


@run_app.command("bec-ato")
def run_bec_ato(
    tenant: TenantRunOpt = None,
    output_dir: OutputDirOpt = DEFAULT_OUTPUT_DIR,
    case_name: CaseNameOpt = None,
    days: DaysOpt = None,
    start_date: StartDateOpt = None,
    end_date: EndDateOpt = None,
    user: UserOpt = None,
    users: UsersOpt = None,
    users_file: UsersFileOpt = None,
    all_users: AllUsersOpt = False,
    client_id: ClientIdOpt = None,
    collect_only: CollectOnlyOpt = False,
    existing_case: ExistingCaseOpt = None,
) -> None:
    """
    [bold]BEC + ATO Combined Investigation Workflow[/bold]

    Runs both the BEC and ATO investigations in a single pass with no
    duplicated collection. Use this when you need to cover the full attack
    chain: how the account was taken over (authentication layer, persistence
    mechanisms) and what the attacker did with access (mailbox rules,
    forwarding, mail exfiltration).

    Most real-world BEC incidents begin with an ATO event. This workflow
    produces one case folder covering both phases.

    Run without flags to launch the interactive wizard.

    Examples (scripted):
        cirrus run bec-ato --tenant contoso.com --user john@contoso.com --days 30
        cirrus run bec-ato --tenant contoso.com --users john@contoso.com --users jane@contoso.com --start-date 2026-03-01 --end-date 2026-03-18
        cirrus run bec-ato --tenant contoso.com --users-file targets.txt --days 14 --collect-only
    """
    _banner()
    interactive = tenant is None
    if interactive:
        console.print(Panel.fit(
            "[bold]BEC + ATO Investigation Wizard[/bold]\n"
            "[dim]Answer a few questions to configure your collection run.\n"
            "Press Ctrl+C at any time to cancel.[/dim]",
            border_style="bright_blue",
        ))
        console.print()
        tenant = _prompt_tenant()
    else:
        console.print(f"[bold magenta]Workflow:[/bold magenta] BEC + ATO Combined Investigation")
        console.print(f"[bold]Tenant:[/bold]  [cyan]{tenant}[/cyan]\n")

    target_users = _resolve_users(user, users, users_file, all_users)
    if target_users:
        console.print(f"[bold]Targets:[/bold] {', '.join(target_users)}\n")
    else:
        if not Confirm.ask("[yellow]⚠  No user filter — this will collect data for EVERY account in the tenant.\n   This can take a long time and produce large output files. Continue?[/yellow]"):
            raise typer.Exit(0)

    start_dt, end_dt = _resolve_date_range(days, start_date, end_date)

    if interactive and case_name is None:
        case_name_input = Prompt.ask(
            "Case name [dim](optional — e.g. INC-2026-001, leave blank to auto-generate)[/dim]",
            default="",
        ).strip()
        case_name = case_name_input or None

    _show_run_summary("bec-ato", tenant, target_users, start_dt, end_dt, output_dir, case_name)

    token, _ = _authenticate(tenant, client_id)

    if existing_case:
        if not existing_case.exists():
            console.print(f"[red]Existing case not found:[/red] {existing_case}")
            raise typer.Exit(1)
        case = Case.open_existing(existing_case)
        console.print(f"[bold]Continuing case:[/bold] {case.case_dir}\n")
    else:
        output_dir.mkdir(parents=True, exist_ok=True)
        case = Case.create(tenant, output_dir, case_name)
        console.print(f"[bold]Case folder:[/bold] {case.case_dir}\n")

    case.audit.log_event("WORKFLOW_CONFIG", {
        "workflow": "bec-ato",
        "tenant": tenant,
        "start_date": start_dt.strftime(_DATE_FMT),
        "end_date": end_dt.strftime(_DATE_FMT),
        "users": target_users or "all",
    })

    _client_id = client_id
    token_provider = lambda: get_token(tenant, **({'client_id': _client_id} if _client_id else {}))
    workflow = BECATOWorkflow(token, case, token_provider=token_provider)
    result = workflow.run(
        users=target_users,
        tenant=tenant,
        start_dt=start_dt,
        end_dt=end_dt,
        run_analysis=False,
    )

    render_summary(result)
    if result.errors:
        console.print(f"[yellow]⚠ {len(result.errors)} collector(s) encountered errors. Check case_audit.txt for details.[/yellow]")
    console.print("[bold green]BEC + ATO collection complete.[/bold green]")

    _maybe_run_analysis(case, result, collect_only, interactive)
    case.close()


@run_app.command("full")
def run_full(
    tenant: TenantRunOpt = None,
    output_dir: OutputDirOpt = DEFAULT_OUTPUT_DIR,
    case_name: CaseNameOpt = None,
    days: DaysOpt = None,
    start_date: StartDateOpt = None,
    end_date: EndDateOpt = None,
    user: UserOpt = None,
    users: UsersOpt = None,
    users_file: UsersFileOpt = None,
    all_users: AllUsersOpt = False,
    client_id: ClientIdOpt = None,
    collect_only: CollectOnlyOpt = False,
) -> None:
    """
    [bold]Full Tenant Collection Workflow[/bold]

    Sweeps the entire tenant for all supported artifact types.
    Use when the compromised account is unknown, or for proactive threat hunting.

    Run without flags to launch the interactive wizard.

    Examples (scripted):
        cirrus run full --tenant contoso.com --all-users --days 90
        cirrus run full --tenant contoso.com --all-users --start-date 2026-03-01 --end-date 2026-03-18
        cirrus run full --tenant contoso.com --users-file targets.txt --days 30 --collect-only
    """
    _banner()
    interactive = tenant is None
    if interactive:
        console.print(Panel.fit(
            "[bold]Full Tenant Collection Wizard[/bold]\n"
            "[dim]Answer a few questions to configure your collection run.\n"
            "Press Ctrl+C at any time to cancel.[/dim]",
            border_style="bright_blue",
        ))
        console.print()
        tenant = _prompt_tenant()
    else:
        console.print(f"[bold magenta]Workflow:[/bold magenta] Full Tenant Collection")
        console.print(f"[bold]Tenant:[/bold]  [cyan]{tenant}[/cyan]\n")

    console.print(
        "[yellow]⚠  Full collection on large tenants may take a long time "
        "and generate large output files.[/yellow]\n"
    )

    target_users = _resolve_users(user, users, users_file, all_users)
    if target_users:
        console.print(f"[bold]Targets:[/bold] {', '.join(target_users)}\n")
    else:
        if not Confirm.ask("[yellow]⚠  No user filter — this will collect data for EVERY account in the tenant.\n   This can take a long time and produce large output files. Continue?[/yellow]"):
            raise typer.Exit(0)

    start_dt, end_dt = _resolve_date_range(days, start_date, end_date)

    if interactive and case_name is None:
        case_name_input = Prompt.ask(
            "Case name [dim](optional — e.g. INC-2026-001, leave blank to auto-generate)[/dim]",
            default="",
        ).strip()
        case_name = case_name_input or None

    _show_run_summary("full", tenant, target_users, start_dt, end_dt, output_dir, case_name)

    token, _ = _authenticate(tenant, client_id)

    output_dir.mkdir(parents=True, exist_ok=True)
    case = Case.create(tenant, output_dir, case_name)
    console.print(f"[bold]Case folder:[/bold] {case.case_dir}\n")

    case.audit.log_event("WORKFLOW_CONFIG", {
        "workflow": "full",
        "tenant": tenant,
        "start_date": start_dt.strftime(_DATE_FMT),
        "end_date": end_dt.strftime(_DATE_FMT),
        "users": target_users or "all",
    })

    _client_id = client_id  # capture for closure
    token_provider = lambda: get_token(tenant, **({'client_id': _client_id} if _client_id else {}))
    workflow = FullWorkflow(token, case, token_provider=token_provider)
    result = workflow.run(
        users=target_users,
        tenant=tenant,
        start_dt=start_dt,
        end_dt=end_dt,
        run_analysis=False,
    )

    render_summary(result)
    if result.errors:
        console.print(f"[yellow]⚠ {len(result.errors)} collector(s) encountered errors.[/yellow]")
    console.print("[bold green]Full collection complete.[/bold green]")

    _maybe_run_analysis(case, result, collect_only, interactive)
    case.close()


# ---------------------------------------------------------------------------
# Audit wizard
# ---------------------------------------------------------------------------

@dataclass
class AuditConfig:
    tenant: str
    benchmark: str        # "cis-m365" | "cis-entra" | "all"
    levels: list[int]     # [1] | [2] | [1, 2]
    output_dir: Path
    case_name: str | None
    no_save: bool

    @property
    def benchmark_label(self) -> str:
        return {
            "cis-m365": "CIS Microsoft 365 Foundations Benchmark",
            "cis-entra": "CIS Entra ID Benchmark",
            "all": "CIS M365 + CIS Entra (both)",
        }.get(self.benchmark, self.benchmark)

    @property
    def level_label(self) -> str:
        if self.levels == [1]:
            return "Level 1 only"
        if self.levels == [2]:
            return "Level 2 only"
        return "Level 1 & 2 (all)"

    @property
    def check_count(self) -> int:
        from cirrus.compliance.runner import ALL_CHECKS
        return sum(
            1 for c in ALL_CHECKS
            if c.level in self.levels
            and (
                self.benchmark == "all"
                or (self.benchmark == "cis-m365" and "M365" in c.benchmark)
                or (self.benchmark == "cis-entra" and "Entra" in c.benchmark)
            )
        )


def _audit_wizard(
    tenant: str | None,
    benchmark: str | None,
    level: str | None,
    output_dir: Path,
    case_name: str | None,
    no_save: bool,
) -> AuditConfig:
    """
    Interactive wizard for the compliance audit command.
    Only prompts for values that weren't already supplied via flags.
    """
    console.print(
        Panel.fit(
            "[bold]CIS Compliance Audit Wizard[/bold]\n"
            "[dim]Answer a few questions to configure your audit run.\n"
            "Press Ctrl+C at any time to cancel.[/dim]",
            border_style="bright_blue",
        )
    )
    console.print()

    # --- Tenant ---
    if not tenant:
        tenant = Prompt.ask("[bold]Tenant domain or GUID[/bold] (e.g. contoso.com)").strip()
        if not tenant:
            console.print("[red]Tenant is required.[/red]")
            raise typer.Exit(1)

    # --- Benchmark ---
    if not benchmark:
        console.print("[bold]Which benchmark would you like to run?[/bold]")
        console.print("  [cyan]1[/cyan]  CIS Microsoft 365 Foundations Benchmark")
        console.print("  [cyan]2[/cyan]  CIS Entra ID Benchmark")
        console.print("  [cyan]3[/cyan]  Both  [dim](recommended — maximum coverage)[/dim]")
        console.print()
        bmark_choice = Prompt.ask("Choice", choices=["1", "2", "3"], default="3")
        benchmark = {"1": "cis-m365", "2": "cis-entra", "3": "all"}[bmark_choice]
        console.print()

    # --- Level ---
    if not level:
        console.print("[bold]Which CIS levels should be included?[/bold]")
        console.print("  [cyan]1[/cyan]  Level 1 only  [dim](broadly applicable, lower disruption risk)[/dim]")
        console.print("  [cyan]2[/cyan]  Level 2 only  [dim](stricter, higher security impact)[/dim]")
        console.print("  [cyan]3[/cyan]  Both levels   [dim](recommended — full coverage)[/dim]")
        console.print()
        level_choice = Prompt.ask("Choice", choices=["1", "2", "3"], default="3")
        level = {"1": "1", "2": "2", "3": "all"}[level_choice]
        console.print()

    levels = {"1": [1], "2": [2], "all": [1, 2]}[level]

    # --- Output ---
    if not no_save:
        console.print("[bold]Output settings[/bold]")
        save_files = Confirm.ask("Save output files (JSON, CSV, TXT)?", default=True)
        no_save = not save_files

        if not no_save and not case_name:
            custom_name = Prompt.ask(
                "Case name [dim](optional — e.g. INC-2026-001, leave blank to auto-generate)[/dim]",
                default="",
            ).strip()
            case_name = custom_name or None
        console.print()

    cfg = AuditConfig(
        tenant=tenant,
        benchmark=benchmark,
        levels=levels,
        output_dir=output_dir,
        case_name=case_name,
        no_save=no_save,
    )

    # --- Confirmation summary ---
    table = Table(border_style="bright_blue", show_header=False, box=None, padding=(0, 2))
    table.add_column("Key", style="bold", min_width=14)
    table.add_column("Value", style="cyan")
    table.add_row("Tenant",    cfg.tenant)
    table.add_row("Benchmark", cfg.benchmark_label)
    table.add_row("Levels",    cfg.level_label)
    table.add_row("Checks",    f"{cfg.check_count} total")
    if not cfg.no_save:
        folder = cfg.output_dir / f"{cfg.tenant.split('.')[0].upper()}_AUDIT_*"
        table.add_row("Output",    str(cfg.output_dir))
        if cfg.case_name:
            table.add_row("Case name", cfg.case_name)

    console.print(
        Panel(
            table,
            title="[bold]Audit Configuration[/bold]",
            border_style="bright_blue",
        )
    )
    console.print()

    if not Confirm.ask("[bold]Ready to run. Proceed?[/bold]", default=True):
        console.print("[dim]Cancelled.[/dim]")
        raise typer.Exit(0)

    console.print()
    return cfg


# ---------------------------------------------------------------------------
# run audit command
# ---------------------------------------------------------------------------

@run_app.command("audit")
def run_audit(
    tenant: OptionalTenantOpt = None,
    output_dir: OutputDirOpt = DEFAULT_OUTPUT_DIR,
    case_name: CaseNameOpt = None,
    benchmark: BenchmarkOpt = None,
    level: LevelOpt = None,
    client_id: ClientIdOpt = None,
    no_save: Annotated[bool, typer.Option("--no-save", help="Print results only, do not write output files.")] = False,
) -> None:
    """
    [bold]CIS Compliance Audit[/bold]

    Checks tenant configuration against CIS Microsoft 365 Foundations
    and CIS Entra ID Benchmark controls. Reports PASS / FAIL / WARN for
    automated checks, and MANUAL with step-by-step instructions for controls
    that require PowerShell or portal verification.

    Run without flags to launch the interactive wizard.

    Examples:
        cirrus run audit
        cirrus run audit --tenant contoso.com --benchmark cis-m365 --level 1
        cirrus run audit --tenant contoso.com --benchmark all --level all
        cirrus run audit --tenant contoso.com --no-save
    """
    _banner()

    # --- Wizard: fires when any key option is missing ---
    use_wizard = not benchmark or not level or not tenant
    if use_wizard:
        cfg = _audit_wizard(
            tenant=tenant,
            benchmark=benchmark,
            level=level,
            output_dir=output_dir,
            case_name=case_name,
            no_save=no_save,
        )
        tenant = cfg.tenant
        benchmark = cfg.benchmark
        levels = cfg.levels
        output_dir = cfg.output_dir
        case_name = cfg.case_name
        no_save = cfg.no_save
    else:
        # Direct flag path — validate and resolve
        valid_benchmarks = ("cis-m365", "cis-entra", "all")
        if benchmark not in valid_benchmarks:
            console.print(f"[red]Invalid --benchmark:[/red] {benchmark}. Choose from: {', '.join(valid_benchmarks)}")
            raise typer.Exit(1)

        level_map = {"1": [1], "2": [2], "all": [1, 2]}
        if level not in level_map:
            console.print(f"[red]Invalid --level:[/red] {level}. Choose from: 1, 2, all")
            raise typer.Exit(1)
        levels = level_map[level]

        console.print(f"[bold magenta]Workflow:[/bold magenta] CIS Compliance Audit")
        console.print(f"[bold]Tenant:[/bold]    [cyan]{tenant}[/cyan]")
        console.print(f"[bold]Benchmark:[/bold] {benchmark}")
        console.print(f"[bold]Level:[/bold]     {level}\n")

    # --- Dependency status check ---
    console.print("\n[bold]Checking optional dependencies...[/bold]")
    dep_results = check_all()
    missing = [d for d in dep_results if not d.ok]
    if missing:
        dep_table = Table(border_style="dim", show_header=False, box=None, padding=(0, 2))
        dep_table.add_column("Status", min_width=12)
        dep_table.add_column("Dependency")
        dep_table.add_column("Notes", style="dim")
        for dep in dep_results:
            if dep.ok:
                dep_table.add_row(f"[green]✓[/green] {dep.version or 'OK'}", dep.name, "")
            else:
                dep_table.add_row("[yellow]✗ MISSING[/yellow]", dep.name, dep.message)
        console.print(dep_table)
        console.print(
            f"  [yellow]{len(missing)} dependency/dependencies missing — "
            "those checks will show as MANUAL.[/yellow]\n"
            "  [dim]Run [bold]cirrus deps install[/bold] to install them.[/dim]\n"
        )
    else:
        console.print("  [green]All optional dependencies available.[/green]\n")

    token, _ = _authenticate(tenant, client_id)

    # Run the compliance audit
    runner = ComplianceRunner(token, benchmark=benchmark, levels=levels, tenant=tenant)
    report = runner.run()

    # Render terminal report
    render_terminal(report, tenant)

    # Save output files unless --no-save
    if not no_save:
        output_dir.mkdir(parents=True, exist_ok=True)
        case = Case.create(tenant, output_dir, case_name or f"{tenant.split('.')[0].upper()}_AUDIT")
        case.audit.log_event("COMPLIANCE_AUDIT", {
            "benchmark": benchmark,
            "levels": levels,
            "tenant": tenant,
            "total_checks": len(report.results),
            "passed": len(report.passed),
            "failed": len(report.failed),
            "warned": len(report.warned),
            "manual": len(report.manual),
        })

        json_path, csv_path, txt_path = save_report(report, case.case_dir, tenant)
        case.close()

        console.print(f"\n[bold]Output saved to:[/bold] {case.case_dir}")
        console.print(f"  [dim]compliance_audit.json[/dim]")
        console.print(f"  [dim]compliance_audit.csv[/dim]")
        console.print(f"  [dim]compliance_audit.txt[/dim]  ← full remediation guidance")

    # Non-zero exit when FAILs exist — useful for scheduled/automated runs
    if report.failed:
        raise typer.Exit(1)


# ---------------------------------------------------------------------------
# deps commands
# ---------------------------------------------------------------------------

@deps_app.command("check")
def deps_check() -> None:
    """
    Show the status of optional CIRRUS dependencies.

    Checks for: dnspython (DNS compliance checks),
    PowerShell 7 (Exchange Online PS), ExchangeOnlineManagement module.
    """
    _banner()
    console.print("[bold]Checking optional dependencies...[/bold]\n")

    results = check_all()

    table = Table(border_style="bright_blue", header_style="bold magenta", show_header=True)
    table.add_column("Dependency", style="bold", min_width=28)
    table.add_column("Status", min_width=10)
    table.add_column("Version", min_width=10)
    table.add_column("Notes")

    all_ok = True
    for dep in results:
        if dep.status == DepStatus.OK:
            status_str = "[green]✓  OK[/green]"
            notes = dep.message
        else:
            status_str = "[yellow]✗  MISSING[/yellow]"
            notes = dep.message + (f"\n  Install: {dep.install_hint}" if dep.install_hint else "")
            all_ok = False
        table.add_row(dep.name, status_str, dep.version or "—", notes)

    console.print(table)

    if not all_ok:
        console.print(
            "\n[yellow]Some dependencies are missing. Run [bold]cirrus deps install[/bold] "
            "to install them automatically.[/yellow]"
        )
    else:
        console.print("\n[green]All optional dependencies are installed.[/green]")


@deps_app.command("install")
def deps_install() -> None:
    """
    Install missing optional CIRRUS dependencies.

    Installs: dnspython (via pip), ExchangeOnlineManagement module (via
    PowerShell Install-Module). PowerShell itself must be installed manually.
    """
    _banner()
    console.print("[bold]Checking dependencies...[/bold]\n")

    results = check_all()
    missing = [d for d in results if d.status != DepStatus.OK]

    if not missing:
        console.print("[green]All optional dependencies are already installed.[/green]")
        return

    for dep in missing:
        console.print(f"  [yellow]✗ Missing:[/yellow] {dep.name} — {dep.message}")
    console.print()

    if not Confirm.ask(f"Install {len(missing)} missing dependency/dependencies?", default=True):
        console.print("[dim]Cancelled.[/dim]")
        raise typer.Exit(0)

    console.print()
    outcomes = install_all_missing(results)

    any_failed = False
    for name, ok, msg in outcomes:
        if ok:
            console.print(f"  [green]✓ {name}:[/green] {msg}")
        else:
            console.print(f"  [red]✗ {name}:[/red] {msg}")
            any_failed = True

    console.print()
    if any_failed:
        console.print(
            "[yellow]Some installations failed. See messages above for details.[/yellow]"
        )
        raise typer.Exit(1)
    else:
        console.print("[green]Done. Run [bold]cirrus deps check[/bold] to verify.[/green]")


# ---------------------------------------------------------------------------
# case commands
# ---------------------------------------------------------------------------

@case_app.command("verify")
def case_verify(
    case_dir: Annotated[Path, typer.Argument(help="Path to the case folder to verify.")],
) -> None:
    """
    Verify the chain-of-custody integrity of a case folder's audit log.

    Checks that no entries in case_audit.jsonl have been tampered with
    by recomputing and comparing SHA-256 entry hashes.
    """
    _banner()
    if not case_dir.exists():
        console.print(f"[red]Case folder not found:[/red] {case_dir}")
        raise typer.Exit(1)

    case = Case.open_existing(case_dir)
    is_valid, errors = case.verify_integrity()

    if is_valid:
        console.print(f"[green]✓ Audit chain integrity verified:[/green] {case_dir}")
    else:
        console.print(f"[red]✗ Audit chain integrity FAILED:[/red] {case_dir}")
        for err in errors:
            console.print(f"  [red]•[/red] {err}")
        raise typer.Exit(2)


@case_app.command("package")
def case_package(
    case_dir: Annotated[Path, typer.Argument(help="Path to the case folder to package.")],
    output: Annotated[Optional[Path], typer.Option("--output", "-o", help="Output zip path (default: <case_name>.zip beside the case folder).")] = None,
) -> None:
    """
    Package a case folder into a zip archive with a SHA-256 file manifest.

    Creates a self-contained zip containing all case artifacts and a
    chain_of_custody.json / chain_of_custody.txt with SHA-256 hashes of
    every file. Suitable for legal handoff, evidence preservation, or
    archival.

    \\b
    Examples:
        cirrus case package ./investigations/CONTOSO_ATO_2026-03-30
        cirrus case package ./investigations/CONTOSO_ATO_2026-03-30 -o evidence.zip
    """
    import hashlib
    import zipfile

    _banner()

    if not case_dir.exists() or not case_dir.is_dir():
        console.print(f"[red]Case folder not found:[/red] {case_dir}")
        raise typer.Exit(1)

    zip_path = output or case_dir.parent / f"{case_dir.name}.zip"
    if zip_path.exists():
        console.print(f"[yellow]Output file already exists:[/yellow] {zip_path}")
        if not Confirm.ask("Overwrite?", default=False):
            raise typer.Exit(0)
        zip_path.unlink()

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # ── Collect all files and compute SHA-256 ──────────────────────────────
    file_hashes: list[dict] = []
    all_files = sorted(
        (p for p in case_dir.rglob("*") if p.is_file()),
        key=lambda p: str(p.relative_to(case_dir)),
    )

    with console.status("[dim]Computing file hashes...[/dim]"):
        for fp in all_files:
            h = hashlib.sha256()
            with fp.open("rb") as fh:
                for chunk in iter(lambda: fh.read(65536), b""):
                    h.update(chunk)
            file_hashes.append({
                "file": str(fp.relative_to(case_dir)).replace("\\", "/"),
                "size_bytes": fp.stat().st_size,
                "sha256": h.hexdigest(),
            })

    # ── Chain of custody document ──────────────────────────────────────────
    coc_data = {
        "generated_at": generated_at,
        "case_name": case_dir.name,
        "total_files": len(file_hashes),
        "total_bytes": sum(f["size_bytes"] for f in file_hashes),
        "files": file_hashes,
    }
    coc_json = json.dumps(coc_data, indent=2, ensure_ascii=False)

    coc_lines = [
        "CIRRUS — Chain of Custody Manifest",
        f"Case:      {case_dir.name}",
        f"Packaged:  {generated_at}",
        f"Files:     {len(file_hashes)}",
        f"Total:     {coc_data['total_bytes']:,} bytes",
        "",
        f"{'SHA-256':<64}  {'Size':>12}  File",
        "-" * 100,
    ]
    for f in file_hashes:
        coc_lines.append(f"{f['sha256']}  {f['size_bytes']:>12,}  {f['file']}")
    coc_text = "\n".join(coc_lines) + "\n"

    # ── Write zip ─────────────────────────────────────────────────────────
    with console.status(f"[dim]Creating {zip_path.name}...[/dim]"):
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for fp in all_files:
                zf.write(fp, arcname=str(fp.relative_to(case_dir.parent)))
            # Add manifest files at root level of zip
            zf.writestr(f"{case_dir.name}/chain_of_custody.json", coc_json)
            zf.writestr(f"{case_dir.name}/chain_of_custody.txt", coc_text)

    zip_size = zip_path.stat().st_size
    console.print(f"\n[green]✓ Package created:[/green] [cyan]{zip_path}[/cyan]")
    console.print(f"  [dim]Files:[/dim]   {len(file_hashes)} artifacts + 2 manifest files")
    console.print(f"  [dim]Size:[/dim]    {zip_size:,} bytes ({zip_size // 1024:,} KB)")
    console.print(f"  [dim]Manifest:[/dim] chain_of_custody.json / chain_of_custody.txt (SHA-256 per file)\n")


@case_app.command("list")
def case_list(
    output_dir: OutputDirOpt = DEFAULT_OUTPUT_DIR,
) -> None:
    """List all case folders in the output directory."""
    _banner()
    if not output_dir.exists():
        console.print(f"[yellow]No cases found.[/yellow] (output dir does not exist: {output_dir})")
        return

    cases = sorted(output_dir.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True)
    cases = [c for c in cases if c.is_dir()]

    if not cases:
        console.print(f"[yellow]No case folders found in[/yellow] {output_dir}.")
        return

    table = Table(title="Investigation Cases", border_style="bright_blue", header_style="bold magenta")
    table.add_column("Case Folder", style="cyan")
    table.add_column("Artifacts")
    table.add_column("Audit Log")

    for c in cases:
        # Count .json files (case_audit.jsonl doesn't match *.json).
        # Also count .ndjson files separately since they appear first during
        # streaming — a partial run may have .ndjson but no .json yet.
        json_count = len(list(c.glob("*.json")))
        ndjson_count = len(list(c.glob("*.ndjson")))
        artifacts = max(json_count, ndjson_count)
        audit_ok = "✓" if (c / "case_audit.jsonl").exists() else "✗"
        table.add_row(c.name, str(artifacts), audit_ok)

    console.print(table)


# ---------------------------------------------------------------------------
# Analyze command  (re-run correlation on an existing case)
# ---------------------------------------------------------------------------
# Triage command  (quick per-user checks, no case folder)
# ---------------------------------------------------------------------------

DaysTriOpt = Annotated[int, typer.Option("--days", help="How many days back to check (default 7).")]


@app.command("triage")
def triage(
    tenant:     TenantRunOpt = None,
    user:       Annotated[Optional[str],       typer.Option("--user",       help="UPN of the suspected compromised account.")] = None,
    users:      Annotated[Optional[list[str]], typer.Option("--users",      help="Multiple UPNs (repeat flag).")] = None,
    users_file: Annotated[Optional[Path],      typer.Option("--users-file", help="File with one UPN per line.")] = None,
    days:       DaysTriOpt = 7,
    run_workflow: Annotated[bool, typer.Option("--workflow", "-w", help="After triage, run the full BEC+ATO collection workflow into the same case folder.")] = False,
    collect_only: CollectOnlyOpt = False,
    output_dir: OutputDirOpt = DEFAULT_OUTPUT_DIR,
    case_name:  CaseNameOpt = None,
    client_id:  ClientIdOpt = None,
) -> None:
    """
    [bold]Triage + Handoff Package[/bold]

    Runs 8 high-signal checks on a suspected compromised account (MFA methods,
    inbox rules, mail forwarding, OAuth grants, registered devices, sign-in
    locations, directory audit changes, Identity Protection risk) — all in
    parallel.

    Creates a case folder containing:
      • triage_report.json       — structured findings (verdict, flags, checks)
      • triage_<check>.json/csv/ndjson  — raw API records per check (SIEM-ready)
      • case_audit.jsonl         — tamper-evident chain-of-custody log

    Add [bold]--workflow[/bold] to also run the full BEC+ATO collection into the
    same case folder so the handoff package is complete for the cyber team.

    \\b
    Examples:
        cirrus triage --tenant contoso.com --user john@contoso.com
        cirrus triage --tenant contoso.com --user john@contoso.com --days 14 --workflow
        cirrus triage --tenant contoso.com --users-file suspects.txt --workflow --collect-only
    """
    _banner()

    # ── Tenant & auth ──────────────────────────────────────────────────────
    interactive = tenant is None
    if interactive:
        tenant = _prompt_tenant()

    token, username = _authenticate(tenant, client_id)

    # ── Resolve user list ──────────────────────────────────────────────────
    target_users: list[str] = []
    if user:
        err = _validate_upn(user)
        if err:
            console.print(f"[red]Invalid UPN:[/red] {err}")
            raise typer.Exit(1)
        target_users.append(user)
    if users:
        for u in users:
            err = _validate_upn(u)
            if err:
                console.print(f"[red]Invalid UPN:[/red] {err}")
                raise typer.Exit(1)
            target_users.append(u)
    if users_file:
        if not users_file.exists():
            console.print(f"[red]File not found:[/red] {users_file}")
            raise typer.Exit(1)
        for line in users_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                err = _validate_upn(line)
                if err:
                    console.print(f"[yellow]Warning — skipping invalid UPN in file:[/yellow] {err}")
                    continue
                target_users.append(line)

    if not target_users:
        while True:
            upn_input = Prompt.ask(
                "\n[bold]Target user[/bold] [dim](the account's sign-in email, e.g. john@contoso.com)[/dim]"
            ).strip()
            err = _validate_upn(upn_input)
            if err:
                console.print(f"[red]Invalid UPN:[/red] {err}")
            else:
                target_users = [upn_input]
                break

    target_users = list(dict.fromkeys(target_users))  # deduplicate, preserve order

    # ── Create case folder ─────────────────────────────────────────────────
    output_dir.mkdir(parents=True, exist_ok=True)
    case = Case.create(tenant, output_dir, case_name)
    console.print(f"\n[bold]Case folder:[/bold] {case.case_dir}\n")
    case.audit.log_event("TRIAGE_START", {
        "analyst": username,
        "tenant": tenant,
        "users": target_users,
        "days": days,
        "workflow": run_workflow,
    })

    # ── Run triage checks for each user ────────────────────────────────────
    from cirrus.analysis.triage import run_triage
    from collections import defaultdict as _defaultdict

    all_reports = []
    all_raw: dict[str, list[dict]] = _defaultdict(list)
    any_mailbox_consent_needed = False

    for upn in target_users:
        console.print(
            f"[bold]Running triage:[/bold]  {upn}  "
            f"[dim](last {days} day{'s' if days != 1 else ''})[/dim]\n"
        )

        with console.status(f"[dim]Running 8 checks in parallel...[/dim]"):
            report, raw_records, mailbox_scope_missing, mailbox_role_missing = run_triage(token=token, upn=upn, days=days)

        if mailbox_scope_missing or mailbox_role_missing:
            any_mailbox_consent_needed = True

        all_reports.append(report)
        for check_key, records in raw_records.items():
            all_raw[check_key].extend(records)

        _render_triage_report(report)

        if mailbox_role_missing:
            _render_mailbox_role_hint()
        elif mailbox_scope_missing:
            _render_mailbox_consent_hint(tenant)

        if len(target_users) > 1:
            console.print()

    # ── Save raw check data to case folder ─────────────────────────────────
    from cirrus.output.writer import save_collection

    console.print("\n[dim]Saving triage evidence to case folder...[/dim]")
    for check_key, records in all_raw.items():
        if not records:
            continue
        json_path, csv_path, ndjson_path, json_hash, csv_hash, ndjson_hash = save_collection(
            records, case.case_dir, f"triage_{check_key}"
        )
        case.audit.log_collection_complete(
            f"triage_{check_key}", len(records), json_path, json_hash
        )

    # ── Save structured triage_report.json ────────────────────────────────
    import json as _json
    triage_report_data = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "analyst": username,
        "tenant": tenant,
        "days": days,
        "users_triaged": target_users,
        "overall_verdict": max(
            (r.verdict for r in all_reports),
            key=lambda v: {"high": 3, "warn": 2, "clean": 1}.get(v, 0),
            default="clean",
        ),
        "workflow_run": False,  # updated below if workflow runs
        "reports": [asdict(r) for r in all_reports],
    }
    report_path = case.case_dir / "triage_report.json"
    report_path.write_text(
        _json.dumps(triage_report_data, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )
    case.audit.log_event("TRIAGE_REPORT_WRITTEN", {
        "file": str(report_path),
        "file_hash": file_sha256(report_path),
        "users_triaged": target_users,
        "overall_verdict": triage_report_data["overall_verdict"],
    })

    # ── Optionally run BEC+ATO workflow ────────────────────────────────────
    overall_verdict = triage_report_data["overall_verdict"]
    should_run_workflow = run_workflow
    if not should_run_workflow and interactive and overall_verdict in ("high", "warn"):
        console.print()
        should_run_workflow = Confirm.ask(
            f"[bold]Verdict is {overall_verdict.upper()} — run full BEC+ATO collection now?[/bold]",
            default=True,
        )

    if should_run_workflow:
        console.print(f"\n[bold magenta]Running BEC+ATO workflow...[/bold magenta]\n")
        start_dt = datetime.now(timezone.utc) - timedelta(days=days)
        end_dt   = datetime.now(timezone.utc).replace(hour=23, minute=59, second=59, microsecond=0)
        _client_id = client_id
        token_provider = lambda: get_token(tenant, **({'client_id': _client_id} if _client_id else {}))
        bec_ato = BECATOWorkflow(token, case, token_provider=token_provider)
        wf_result = bec_ato.run(
            users=target_users,
            tenant=tenant,
            start_dt=start_dt,
            end_dt=end_dt,
            run_analysis=not collect_only,
        )
        render_summary(wf_result)
        if wf_result.errors:
            console.print(f"[yellow]⚠ {len(wf_result.errors)} collector(s) encountered errors.[/yellow]")
        # Update workflow_run flag in triage_report.json
        triage_report_data["workflow_run"] = True
        report_path.write_text(
            _json.dumps(triage_report_data, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )

    case.audit.log_event("TRIAGE_COMPLETE", {"overall_verdict": overall_verdict})
    case.close()

    # ── Final handoff summary ──────────────────────────────────────────────
    _render_triage_handoff(
        case_dir=case.case_dir,
        tenant=tenant,
        reports=all_reports,
        workflow_ran=should_run_workflow,
        collect_only=collect_only,
        mailbox_consent_needed=any_mailbox_consent_needed,
    )


def _render_triage_report(report: "TriageReport") -> None:
    """Render one user's triage results to the terminal."""
    STATUS_ICON  = {"high": "[red]✗[/red]",   "warn": "[yellow]⚠[/yellow]",
                    "clean": "[green]✓[/green]", "error": "[dim]![/dim]",
                    "skipped": "[dim]–[/dim]"}
    STATUS_LABEL = {"high": "[red]HIGH[/red]",   "warn": "[yellow]WARN[/yellow]",
                    "clean": "[green]CLEAN[/green]", "error": "[dim]ERROR[/dim]",
                    "skipped": "[dim]SKIP[/dim]"}

    table = Table(
        show_header=True,
        header_style="bold",
        border_style="bright_blue",
        show_lines=False,
        box=None,
        pad_edge=True,
    )
    table.add_column("", width=3, no_wrap=True)
    table.add_column("Check", style="bold", min_width=22, no_wrap=True)
    table.add_column("Status", width=10, no_wrap=True)
    table.add_column("Summary")

    for check in report.checks:
        icon  = STATUS_ICON.get(check.status, "?")
        label = STATUS_LABEL.get(check.status, check.status)
        table.add_row(icon, check.label, label, check.summary)

    console.print(table)

    # Detail bullets for flagged checks
    for check in report.checks:
        if check.detail and check.status in ("high", "warn"):
            console.print(f"\n  [bold]{check.label}[/bold]")
            for line in check.detail[:6]:
                color = "red" if any(
                    line.startswith(p) for p in (
                        "HIGH_", "SUSPICIOUS_", "IMPOSSIBLE_", "EXTERNAL_", "NO_LOCAL_",
                        "USABLE_", "ADMIN_PASSWORD", "APP_CONSENT", "RISK_STATE:",
                    )
                ) else "yellow"
                console.print(f"    [{color}]→[/{color}] {line}")

    # Per-user verdict line
    verdict = report.verdict
    flagged = report.flagged_count
    total   = len([c for c in report.checks if c.status != "skipped"])
    console.print()
    if verdict == "high":
        verdict_str = "[bold red]HIGH RISK[/bold red]"
    elif verdict == "warn":
        verdict_str = "[bold yellow]SUSPICIOUS[/bold yellow]"
    else:
        verdict_str = "[bold green]CLEAN[/bold green]"
    console.print(
        f"  [bold]{report.user}[/bold]  Verdict: {verdict_str}  "
        f"[dim]{flagged}/{total} checks flagged[/dim]"
    )


def _render_mailbox_role_hint() -> None:
    """Print an inline warning when scope is present but 403 still occurs (role missing)."""
    console.print(
        f"\n  [yellow bold]⚠ Inbox Rules and Mail Forwarding were skipped (403).[/yellow bold]\n"
        f"  [dim]The MailboxSettings.Read scope was granted correctly — this is a role issue.[/dim]\n"
        f"  [dim]Delegated access to other users' mailbox data requires an Exchange admin role.[/dim]\n"
        f"\n"
        f"  [bold]Fix:[/bold] Assign [bold]Exchange Recipient Administrator[/bold] to the account\n"
        f"  running CIRRUS in the Microsoft 365 admin center or Entra ID:\n"
        f"\n"
        f"    Microsoft 365 admin center → Active users → [account] → Roles\n"
        f"    [dim]or[/dim]\n"
        f"    Entra ID → Users → [account] → Assigned roles → Add assignment\n"
        f"\n"
        f"  After the role is assigned, re-run triage — no re-authentication needed.\n"
    )


def _render_mailbox_consent_hint(tenant: str) -> None:
    """Print an inline warning when MailboxSettings.Read is missing from the token (unusual)."""
    console.print(
        f"\n  [yellow bold]⚠ Inbox Rules and Mail Forwarding were skipped.[/yellow bold]\n"
        f"  [dim]MailboxSettings.Read was not found in the token — try clearing your cached token.[/dim]\n"
        f"\n"
        f"  [bold]Fix:[/bold]\n"
        f"    [cyan]cirrus auth logout[/cyan]\n"
        f"    [cyan]cirrus auth login --tenant {tenant}[/cyan]\n"
        f"\n"
        f"  [dim]If the problem persists, your account also needs the[/dim]\n"
        f"  [dim]Exchange Recipient Administrator role to read other users' mailbox data.[/dim]\n"
    )


def _render_triage_handoff(
    case_dir: "Path",
    tenant: str,
    reports: list,
    workflow_ran: bool,
    collect_only: bool,
    mailbox_consent_needed: bool = False,
) -> None:
    """Print the final handoff panel after all triage work is done."""
    overall = max(
        (r.verdict for r in reports),
        key=lambda v: {"high": 3, "warn": 2, "clean": 1}.get(v, 0),
        default="clean",
    )
    if overall == "high":
        border = "red"
        verdict_str = "[bold red]HIGH RISK[/bold red]"
    elif overall == "warn":
        border = "yellow"
        verdict_str = "[bold yellow]SUSPICIOUS[/bold yellow]"
    else:
        border = "green"
        verdict_str = "[bold green]CLEAN[/bold green]"

    lines: list[str] = [
        f"[bold]Overall verdict:[/bold] {verdict_str}",
        f"[bold]Case folder:[/bold]     [cyan]{case_dir}[/cyan]",
        "",
    ]

    if mailbox_consent_needed:
        lines += [
            "[yellow]⚠ Inbox Rules / Mail Forwarding skipped — Exchange Recipient Administrator role required.[/yellow]",
            "[dim]See fix instructions printed above the handoff panel.[/dim]",
            "",
        ]

    if workflow_ran and not collect_only:
        lines += [
            "[dim]The case folder contains triage evidence + full BEC+ATO collection.[/dim]",
            "[dim]Hand off the case folder to your cyber team. They can run:[/dim]",
            "",
            f"  [cyan]cirrus analyze {case_dir}[/cyan]",
            f"  [cyan]cirrus enrich {case_dir}[/cyan]",
            f"  [cyan]cirrus enrich-domains {case_dir}[/cyan]",
        ]
    elif workflow_ran and collect_only:
        lines += [
            "[dim]The case folder contains triage evidence + full BEC+ATO collection.[/dim]",
            "[dim]Correlation was skipped (--collect-only). The cyber team can run:[/dim]",
            "",
            f"  [cyan]cirrus analyze {case_dir}[/cyan]",
            f"  [cyan]cirrus enrich {case_dir}[/cyan]",
        ]
    else:
        lines += [
            "[dim]The case folder contains quick triage evidence (limited record counts).[/dim]",
            "[dim]To add full BEC+ATO collection, the cyber team can run:[/dim]",
            "",
            f"  [cyan]cirrus run bec-ato --tenant {tenant} --existing-case {case_dir}[/cyan]",
            "",
            "[dim]Or to just re-run correlation on what's already collected:[/dim]",
            f"  [cyan]cirrus analyze {case_dir}[/cyan]",
        ]

    console.print(
        Panel(
            "\n".join(lines),
            title="[bold]Triage Complete — Handoff Package Ready[/bold]",
            border_style=border,
            expand=False,
        )
    )


# ---------------------------------------------------------------------------
# Enrich command
# ---------------------------------------------------------------------------

@app.command("enrich")
def enrich(
    case_dir: Annotated[Path, typer.Argument(help="Path to the case folder to enrich.")],
    abuseipdb_key: Annotated[Optional[str], typer.Option(
        "--abuseipdb-key",
        envvar="ABUSEIPDB_KEY",
        help=(
            "AbuseIPDB API key for threat intelligence enrichment (optional). "
            "Register free at https://www.abuseipdb.com/register — free tier: "
            "1,000 requests/day. Set once in your shell: export ABUSEIPDB_KEY=<key>"
        ),
    )] = None,
    vt_key: Annotated[Optional[str], typer.Option(
        "--vt-key",
        envvar="VT_KEY",
        help=(
            "VirusTotal API key for additional IP reputation data (optional). "
            "Register free at https://www.virustotal.com/ — free tier: 4 lookups/minute. "
            "Set once in your shell: export VT_KEY=<key>"
        ),
    )] = None,
) -> None:
    """
    Enrich IP addresses from a collected case with geo, ASN, and threat data.

    Reads all collector JSON files in the case folder, extracts public IP
    addresses, and queries ip-api.com for geolocation/ASN/datacenter/proxy/Tor
    information. Optionally queries AbuseIPDB for abuse confidence scores.

    Writes ip_enrichment.json to the case folder. Does NOT modify any
    collector output files.

    \\b
    IP data sources:
        ip-api.com   — free, no key required, batch geo/ASN/hosting/proxy/tor
        AbuseIPDB    — optional, requires free API key (see --abuseipdb-key)
                       Register: https://www.abuseipdb.com/register  (1,000/day free)
        VirusTotal   — optional, requires free API key (see --vt-key)
                       Register: https://www.virustotal.com/  (4/min free)

    \\b
    Examples:
        cirrus enrich ./investigations/CONTOSO_20260101_120000
        cirrus enrich ./investigations/CONTOSO_20260101_120000 --abuseipdb-key abc123
        cirrus enrich ./investigations/CONTOSO_20260101_120000 --vt-key xyz789
        ABUSEIPDB_KEY=abc123 VT_KEY=xyz789 cirrus enrich ./investigations/CONTOSO_20260101_120000
    """
    _banner()

    if not case_dir.exists() or not case_dir.is_dir():
        console.print(f"[red]Case folder not found:[/red] {case_dir}")
        raise typer.Exit(1)

    if abuseipdb_key:
        console.print(
            f"\n[bold]Enriching IPs[/bold] in [cyan]{case_dir}[/cyan] "
            f"[dim](ip-api.com + AbuseIPDB)[/dim]\n"
        )
    else:
        console.print(
            f"\n[bold]Enriching IPs[/bold] in [cyan]{case_dir}[/cyan] "
            f"[dim](ip-api.com only — use --abuseipdb-key for threat scores)[/dim]\n"
        )

    from cirrus.analysis.ip_enrichment import run_enrichment

    progress_msgs: list[str] = []

    def _on_progress(msg: str) -> None:
        progress_msgs.append(msg)

    with console.status("[dim]Querying enrichment APIs...[/dim]"):
        result = run_enrichment(case_dir, abuseipdb_key=abuseipdb_key, vt_key=vt_key, on_progress=_on_progress)

    total = result.get("total_ips", 0)
    suspicious = result.get("suspicious_count", 0)
    ips_dict = result.get("ips") or {}

    if total == 0:
        console.print("[yellow]No public IP addresses found in case files.[/yellow]")
        return

    # Build display table
    table = Table(
        title=f"IP Enrichment — {total} address(es)",
        border_style="bright_blue",
        header_style="bold",
    )
    table.add_column("IP Address", style="cyan", no_wrap=True)
    table.add_column("Country", width=12)
    table.add_column("City", width=16)
    table.add_column("ASN / Org")
    table.add_column("Flags", style="yellow")
    if abuseipdb_key:
        table.add_column("Abuse%", width=8)

    for ip, data in sorted(ips_dict.items()):
        threat = ", ".join(data.get("threat_summary") or [])
        flag_style = "red" if threat else ""
        asn_org = data.get("asn") or ""
        org = data.get("org") or data.get("isp") or ""
        if org and asn_org:
            asn_org = f"{asn_org} {org}"
        elif org:
            asn_org = org

        row = [
            f"[{'red' if threat else 'cyan'}]{ip}[/{'red' if threat else 'cyan'}]",
            data.get("country_code") or "—",
            (data.get("city") or "—")[:16],
            (asn_org or "—")[:40],
            threat or "—",
        ]
        if abuseipdb_key:
            score = data.get("abuse_score")
            score_str = str(score) if score is not None else "—"
            if isinstance(score, int) and score >= 25:
                score_str = f"[red]{score_str}[/red]"
            row.append(score_str)

        table.add_row(*row)

    console.print(table)
    console.print(
        f"\n[bold]Total:[/bold] {total} IP(s)  "
        f"[{'red' if suspicious else 'green'}]{suspicious} suspicious[/{'red' if suspicious else 'green'}]\n"
        f"[bold]Output:[/bold] [cyan]{case_dir / 'ip_enrichment.json'}[/cyan]\n"
    )


# ---------------------------------------------------------------------------
# Enrich-domains command
# ---------------------------------------------------------------------------

@app.command("enrich-domains")
def enrich_domains(
    case_dir: Annotated[Path, typer.Argument(help="Path to the case folder to enrich.")],
) -> None:
    """
    Enrich domains from a collected case with RDAP registration age and DNS data.

    Extracts domain names from IOC flags in collector output (forwarding addresses,
    external email OTP addresses, SMTP forward targets) and queries each domain for:
      - Registration date and age via RDAP (no API key required)
      - MX records and whether mail routes to consumer providers (Gmail, Outlook, etc.)
      - SPF and DMARC presence

    Writes domain_enrichment.json to the case folder. A new "Domains" tab appears
    in the HTML report when you next run `cirrus analyze`.

    \\b
    Examples:
        cirrus enrich-domains ./investigations/CONTOSO_20260101_120000
    """
    _banner()

    if not case_dir.exists() or not case_dir.is_dir():
        console.print(f"[red]Case folder not found:[/red] {case_dir}")
        raise typer.Exit(1)

    from cirrus.analysis.domain_enrichment import run_domain_enrichment

    console.print(f"\n[bold]Enriching domains[/bold] in [cyan]{case_dir}[/cyan] [dim](RDAP + DNS)[/dim]\n")

    current: list[str] = []

    def _on_progress(domain: str) -> None:
        current.clear()
        current.append(domain)

    with console.status("[dim]Querying RDAP and DNS...[/dim]") as status:
        result = run_domain_enrichment(case_dir, on_progress=_on_progress)

    total = result.get("total_domains", 0)
    suspicious = result.get("suspicious_count", 0)
    domains_dict = result.get("domains") or {}

    if total == 0:
        console.print("[yellow]No external domains found in case files.[/yellow]")
        console.print("[dim]Domain enrichment extracts domains from FORWARDS_TO, EXTERNAL_SMTP_FORWARD, and EXTERNAL_EMAIL_OTP flags.[/dim]")
        return

    table = Table(
        title=f"Domain Enrichment — {total} domain(s)",
        border_style="bright_blue",
        header_style="bold",
        show_lines=False,
    )
    table.add_column("Domain", style="cyan", min_width=24)
    table.add_column("Age", width=10, justify="right")
    table.add_column("Registrar", max_width=24)
    table.add_column("MX", max_width=32)
    table.add_column("Threat Tags")

    for domain, data in sorted(domains_dict.items()):
        tags = data.get("threat_summary") or []
        age_days = data.get("age_days")
        age_str = f"{age_days}d" if age_days is not None else "—"
        if age_days is not None and age_days < 30:
            age_str = f"[red]{age_str}[/red]"
        elif age_days is not None and age_days < 90:
            age_str = f"[yellow]{age_str}[/yellow]"

        mx = data.get("mx_records") or []
        mx_str = mx[0][:30] if mx else "no MX"
        if data.get("routes_to_consumer_mail"):
            mx_str = f"[yellow]{mx_str}[/yellow]"

        tags_str = " ".join(tags)[:40] if tags else "[dim]clean[/dim]"
        registrar = (data.get("registrar") or "—")[:22]

        table.add_row(domain, age_str, registrar, mx_str, tags_str)

    console.print(table)
    console.print(
        f"\n[bold]Total:[/bold] {total} domain(s)  "
        f"[{'red' if suspicious else 'green'}]{suspicious} suspicious[/{'red' if suspicious else 'green'}]\n"
        f"[bold]Output:[/bold] [cyan]{case_dir / 'domain_enrichment.json'}[/cyan]\n"
    )


# ---------------------------------------------------------------------------
# Blast-radius command
# ---------------------------------------------------------------------------

@app.command("blast-radius")
def blast_radius(
    tenant: TenantOpt = None,
    user:   Annotated[Optional[str], typer.Option("--user",  help="UPN of the account to assess.")] = None,
    users:  Annotated[Optional[list[str]], typer.Option("--users", help="Multiple UPNs (repeat flag).")] = None,
    users_file: Annotated[Optional[Path], typer.Option("--users-file", help="File with one UPN per line.")] = None,
    case_dir: Annotated[Optional[Path], typer.Option("--case-dir", help="Save blast_radius.json to this case folder.")] = None,
) -> None:
    """
    Map the access dimensions of a potentially compromised account.

    Queries Microsoft Graph in parallel for all access dimensions associated
    with the account: directory roles, group memberships, app role assignments,
    owned objects (including app registrations), OAuth grants, and recent
    sign-in applications.

    Results display immediately in the terminal. If --case-dir is provided,
    blast_radius.json is also written to the case folder.

    \\b
    Examples:
        cirrus blast-radius --tenant contoso.com --user john@contoso.com
        cirrus blast-radius --tenant contoso.com --user john@contoso.com --case-dir ./investigations/CONTOSO_...
        cirrus blast-radius --tenant contoso.com --users-file suspects.txt
    """
    from rich.panel import Panel as RichPanel

    _banner()

    if tenant is None:
        tenant = _prompt_tenant()

    token, username = _authenticate(tenant)

    # ── Resolve user list ──────────────────────────────────────────────────
    target_users: list[str] = []
    if user:
        err = _validate_upn(user)
        if err:
            console.print(f"[red]Invalid UPN:[/red] {err}")
            raise typer.Exit(1)
        target_users.append(user)
    if users:
        for u in users:
            err = _validate_upn(u)
            if err:
                console.print(f"[red]Invalid UPN:[/red] {err}")
                raise typer.Exit(1)
            target_users.append(u)
    if users_file:
        if not users_file.exists():
            console.print(f"[red]File not found:[/red] {users_file}")
            raise typer.Exit(1)
        for line in users_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                err = _validate_upn(line)
                if err:
                    console.print(f"[yellow]Warning — skipping invalid UPN:[/yellow] {err}")
                    continue
                target_users.append(line)

    if not target_users:
        while True:
            upn = Prompt.ask(
                "\n[bold]Target user[/bold] [dim](account UPN, e.g. john@contoso.com)[/dim]"
            ).strip()
            err = _validate_upn(upn)
            if err:
                console.print(f"[red]Invalid UPN:[/red] {err}")
            else:
                target_users = [upn]
                break

    target_users = list(dict.fromkeys(target_users))

    # ── Run blast-radius for each user ─────────────────────────────────────
    from cirrus.analysis.blast_radius import run_blast_radius

    for upn in target_users:
        console.print(f"\n[bold]Blast-radius assessment:[/bold]  {upn}\n")

        with console.status("[dim]Running 6 checks in parallel...[/dim]"):
            report = run_blast_radius(
                token=token, upn=upn, tenant=tenant or "", case_dir=case_dir
            )

        _render_blast_radius_report(report)

        if case_dir:
            console.print(
                f"[dim]Written:[/dim] [cyan]{case_dir / 'blast_radius.json'}[/cyan]\n"
            )

        if len(target_users) > 1:
            console.print()


def _render_blast_radius_report(report: "BlastRadiusReport") -> None:
    """Render a blast-radius report to the terminal using Rich."""
    STATUS_ICON  = {"high": "[red]✗[/red]",   "warn": "[yellow]⚠[/yellow]",
                    "clean": "[green]✓[/green]", "error": "[dim]![/dim]",
                    "skipped": "[dim]–[/dim]"}
    STATUS_LABEL = {"high": "[red]HIGH[/red]",   "warn": "[yellow]WARN[/yellow]",
                    "clean": "[green]CLEAN[/green]", "error": "[dim]ERROR[/dim]",
                    "skipped": "[dim]SKIP[/dim]"}

    table = Table(
        show_header=True,
        header_style="bold",
        border_style="bright_blue",
        show_lines=False,
        box=None,
        pad_edge=True,
    )
    table.add_column("", width=3, no_wrap=True)
    table.add_column("Dimension", style="bold", min_width=24, no_wrap=True)
    table.add_column("Status", width=10, no_wrap=True)
    table.add_column("Summary")

    for dim in report.dimensions:
        icon  = STATUS_ICON.get(dim.status, "?")
        label = STATUS_LABEL.get(dim.status, dim.status)
        table.add_row(icon, dim.label, label, dim.summary)

    console.print(table)

    # Detail bullets for flagged dimensions
    for dim in report.dimensions:
        if dim.detail and dim.status in ("high", "warn"):
            console.print(f"\n  [bold]{dim.label}[/bold]")
            for line in dim.detail[:8]:
                color = "red" if line.startswith("[HIGH]") else "yellow"
                console.print(f"    [{color}]→[/{color}] {line}")

    # Verdict panel
    risk = report.risk_level
    flagged = report.flagged_count
    total   = len([d for d in report.dimensions if d.status != "skipped"])

    console.print()
    if risk == "high":
        risk_str = "[bold red]HIGH RISK[/bold red]"
    elif risk == "warn":
        risk_str = "[bold yellow]ELEVATED ACCESS[/bold yellow]"
    else:
        risk_str = "[bold green]STANDARD ACCESS[/bold green]"

    high_priv = report.high_privilege_summary
    priv_note = ""
    if high_priv:
        priv_note = (
            f"\n\n[dim]High-privilege indicators:[/dim]\n"
            + "\n".join(f"  [red]→[/red] {f}" for f in high_priv[:6])
        )

    console.print(
        Panel(
            f"[bold]User:[/bold] {report.user}   "
            f"[bold]Risk:[/bold] {risk_str}   "
            f"[dim]{flagged}/{total} dimensions flagged[/dim]"
            + priv_note,
            border_style="red" if risk == "high" else ("yellow" if risk == "warn" else "green"),
            expand=False,
        )
    )


# ---------------------------------------------------------------------------
# Hunt command
# ---------------------------------------------------------------------------

@app.command("hunt")
def hunt(
    tenant: TenantOpt = None,
    days: Annotated[int, typer.Option("--days", help="How many days back to scan (default 30).")] = 30,
    stale_days: Annotated[int, typer.Option("--stale-days", help="Days of inactivity before an account is considered stale (default 90).")] = 90,
) -> None:
    """
    Perform a proactive tenant-wide threat hunt without a known starting account.

    Scans all sign-in logs, directory roles, and OAuth consent grants to surface:
      - Accounts with suspicious auth patterns (device code, impossible travel,
        legacy auth, high Identity Protection risk)
      - Recently created accounts that hold a privileged directory role
      - OAuth apps with high-risk scopes consented by multiple users
      - IP addresses performing password spray attacks

    Results display in the terminal ranked by signal count. No case folder
    is created — use this for initial discovery before running a full workflow.

    \\b
    Examples:
        cirrus hunt --tenant contoso.com
        cirrus hunt --tenant contoso.com --days 14
    """
    _banner()

    if tenant is None:
        tenant = _prompt_tenant()

    token, username = _authenticate(tenant)

    console.print(
        f"\n[bold]Tenant-wide threat hunt[/bold]  "
        f"[dim]tenant: {tenant}  |  last {days} day(s)[/dim]\n"
    )

    from cirrus.analysis.hunt import run_hunt

    with console.status("[dim]Running 5 hunt checks in parallel...[/dim]"):
        report = run_hunt(token=token, days=days, tenant=tenant or "", stale_days=stale_days)

    # ── Errors ──────────────────────────────────────────────────────────────
    if report.errors:
        for err in report.errors:
            console.print(f"  [yellow]⚠[/yellow]  [dim]{err}[/dim]")
        console.print()

    # ── No findings ─────────────────────────────────────────────────────────
    if not report.targets:
        console.print(
            Panel(
                "[bold green]No suspicious targets found.[/bold green]\n"
                "[dim]All hunt checks returned clean for the specified window.[/dim]",
                border_style="green",
                expand=False,
            )
        )
        return

    # ── Results table ────────────────────────────────────────────────────────
    SEV_STYLE = {"high": "red", "medium": "yellow", "low": "dim"}

    table = Table(
        title=f"Hunt Results — {len(report.targets)} suspicious target(s)",
        border_style="bright_blue",
        header_style="bold",
        show_lines=True,
    )
    table.add_column("Severity", width=10, no_wrap=True)
    table.add_column("Type", width=8)
    table.add_column("Target", style="cyan", min_width=28)
    table.add_column("Signals", width=8, justify="right")
    table.add_column("Top Signal")

    for t in report.targets:
        sev = t.max_severity
        style = SEV_STYLE.get(sev, "white")
        top_signal = t.signals[0].detail if t.signals else ""
        table.add_row(
            f"[{style}]{sev.upper()}[/{style}]",
            t.target_type,
            t.name,
            str(t.signal_count),
            top_signal[:80],
        )

    console.print(table)

    # ── Per-target detail ────────────────────────────────────────────────────
    high_targets = report.high_targets
    if high_targets:
        console.print("\n[bold red]HIGH severity targets — all signals:[/bold red]")
        for t in high_targets[:10]:
            console.print(f"\n  [bold cyan]{t.name}[/bold cyan]  [dim]({t.target_type})[/dim]")
            for s in t.signals:
                sev_style = SEV_STYLE.get(s.severity, "white")
                console.print(
                    f"    [{sev_style}]→[/{sev_style}] [{s.check}] {s.detail}"
                )

    # ── Summary panel ────────────────────────────────────────────────────────
    high_count   = len(report.high_targets)
    medium_count = sum(1 for t in report.targets if t.max_severity == "medium")
    console.print()
    console.print(
        Panel(
            f"[bold]Targets found:[/bold] {len(report.targets)}   "
            f"[bold red]{high_count} HIGH[/bold red]   "
            f"[bold yellow]{medium_count} MEDIUM[/bold yellow]   "
            f"[dim]{report.total_signals} total signal(s)[/dim]\n\n"
            "[dim]Next step: run [bold]cirrus triage[/bold] on suspicious accounts, "
            "or [bold]cirrus run ato[/bold] to collect full evidence.[/dim]",
            border_style="red" if high_count else "yellow",
            expand=False,
        )
    )


# ---------------------------------------------------------------------------

@app.command("analyze")
def analyze(
    case_dir: Annotated[Path, typer.Argument(help="Path to the case folder to analyze.")],
) -> None:
    """
    Run the cross-collector correlation engine against an existing case folder.

    Reads the collector JSON output files already present in the case directory,
    links events across collectors, and writes ioc_correlation.json with
    consolidated findings.

    Useful when you want to re-run correlation after adding new collectors,
    or to analyse a case that was collected outside of a workflow run.
    """
    _banner()
    if not case_dir.exists() or not case_dir.is_dir():
        console.print(f"[red]Case folder not found:[/red] {case_dir}")
        raise typer.Exit(1)

    from cirrus.analysis.correlator import run_correlator
    from cirrus.workflows.base import render_findings
    console.print(f"\n[bold]Running correlation engine on:[/bold] {case_dir}\n")

    report = run_correlator(case_dir)

    loaded = ", ".join(report.get("collectors_loaded") or [])
    console.print(f"[dim]Collectors loaded:[/dim] {loaded or 'none'}\n")

    render_findings(report)

    # Always generate HTML report
    from cirrus.analysis.report import generate_report
    report_path = generate_report(case_dir)
    console.print(f"[bold]Report:[/bold] [cyan]{report_path}[/cyan]\n")


# ---------------------------------------------------------------------------
# Update command
# ---------------------------------------------------------------------------

@app.command("update")
def update(
    check_only: Annotated[bool, typer.Option("--check", help="Check for a new version without downloading.")] = False,
) -> None:
    """
    Check for a newer version of CIRRUS and optionally update.

    When run as a pre-built executable, downloads and replaces the binary
    in-place. On Windows the swap happens automatically after this window
    closes. On macOS/Linux the binary is replaced immediately.

    Example:
        cirrus update
        cirrus update --check
    """
    _banner(skip_update_check=True)

    console.print("[bold]Checking for updates...[/bold]")
    info = check_for_update()

    if info.error:
        console.print(f"[red]Could not reach GitHub:[/red] {info.error}")
        raise typer.Exit(1)

    console.print(f"  Current version : [cyan]{info.current_version}[/cyan]")
    console.print(f"  Latest release  : [cyan]{info.latest_version}[/cyan]")

    if not info.update_available:
        console.print("\n[green]You are running the latest version.[/green]")
        return

    console.print(f"\n[yellow]New version available:[/yellow] v{info.latest_version}")

    if info.release_notes:
        console.print(f"\n[bold]Release notes:[/bold]\n{info.release_notes}\n")

    if check_only:
        console.print(
            f"[dim]Run [bold]cirrus update[/bold] (without --check) to install.[/dim]"
        )
        return

    if not is_frozen():
        console.print(
            "\n[yellow]Running from source — update via git:[/yellow]\n"
            "  git pull && pip install -e ."
        )
        return

    if not info.download_url:
        console.print(
            f"\n[yellow]No pre-built binary found for this platform ({info.asset_name}).[/yellow]\n"
            "Download manually from: https://github.com/ctrlaltdean/cirrus/releases/latest"
        )
        raise typer.Exit(1)

    if not Confirm.ask(f"\nDownload and install v{info.latest_version}?", default=True):
        console.print("[dim]Cancelled.[/dim]")
        return

    from rich.progress import BarColumn, DownloadColumn, Progress, TransferSpeedColumn

    with Progress(
        "[progress.description]{task.description}",
        BarColumn(),
        DownloadColumn(),
        TransferSpeedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Downloading...", total=None)

        def _on_progress(downloaded: int, total: int) -> None:
            progress.update(task, completed=downloaded, total=total)

        ok, msg = apply_update(info.download_url, progress_callback=_on_progress)

    if ok:
        console.print(f"\n[green]✓[/green] {msg}")
    else:
        console.print(f"\n[red]✗ Update failed:[/red] {msg}")
        raise typer.Exit(1)


# ---------------------------------------------------------------------------
# Version command
# ---------------------------------------------------------------------------

@app.command()
def version() -> None:
    """Show CIRRUS version."""
    console.print(f"CIRRUS v{__version__}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    app()


if __name__ == "__main__":
    main()
