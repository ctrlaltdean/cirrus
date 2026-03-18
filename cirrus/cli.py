"""
CIRRUS CLI — main entry point.

Commands:
    cirrus auth login     — authenticate to a tenant
    cirrus auth logout    — clear cached credentials
    cirrus auth status    — show cached tenants

    cirrus run bec        — run BEC investigation workflow
    cirrus run full       — run full-tenant collection
    cirrus run ato        — run ATO investigation workflow
    cirrus run bec-ato    — run combined BEC+ATO full attack chain workflow

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
from dataclasses import dataclass
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
    AuthenticationError,
    get_token,
    list_cached_tenants,
    logout,
)
from cirrus.compliance.report import render_terminal, save_report
from cirrus.compliance.runner import ComplianceRunner
from cirrus.output.case import Case
from cirrus.utils.deps import (
    DepStatus,
    check_all,
    install_all_missing,
)
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
    console.print("\n[bold]No user target specified.[/bold]")
    console.print(
        "[dim]User Principal Name (UPN) — the user's sign-in address, "
        "e.g. john@contoso.com or john@contoso.onmicrosoft.com[/dim]\n"
    )
    console.print("[bold]How would you like to target users?[/bold]\n")
    console.print("  [cyan]1[/cyan]  Single user        [dim]e.g. john@contoso.com[/dim]")
    console.print("  [cyan]2[/cyan]  Multiple users     [dim]enter as a comma-separated list[/dim]")
    console.print("  [cyan]3[/cyan]  Load from file     [dim]text file, one UPN per line[/dim]")
    console.print("  [cyan]4[/cyan]  All users          [dim]no user filter — collects entire tenant[/dim]")
    console.print()
    choice = Prompt.ask("Choice", choices=["1", "2", "3", "4"])

    if choice == "1":
        while True:
            upn = Prompt.ask("Enter user UPN").strip()
            err = _validate_upn(upn)
            if err:
                console.print(f"[red]Invalid UPN:[/red] {err}")
            else:
                break
        return [upn]
    elif choice == "2":
        while True:
            raw = Prompt.ask("Enter UPNs (comma-separated)").strip()
            entries = [u.strip() for u in raw.split(",") if u.strip()]
            errors = [(u, _validate_upn(u)) for u in entries if _validate_upn(u)]
            if errors:
                for u, err in errors:
                    console.print(f"[red]Invalid UPN:[/red] {err}")
            else:
                break
        return entries
    elif choice == "3":
        path_str = Prompt.ask("Path to users file")
        p = Path(path_str)
        if not p.exists():
            console.print(f"[red]File not found:[/red] {p}")
            raise typer.Exit(1)
        lines = p.read_text().splitlines()
        file_entries = [line.strip() for line in lines if line.strip() and not line.startswith("#")]
        for entry in file_entries:
            err = _validate_upn(entry)
            if err:
                console.print(f"[yellow]Warning — invalid UPN in file:[/yellow] {err}")
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
            f"  End date   [bold](YYYY-MM-DD)[/bold]",
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
        cirrus run bec --tenant contoso.com --users-file targets.txt --days 14
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
        if not Confirm.ask("[yellow]No user filter — this will collect data for ALL users. Continue?[/yellow]"):
            raise typer.Exit(0)

    start_dt, end_dt = _resolve_date_range(days, start_date, end_date)

    if interactive and case_name is None:
        case_name_input = Prompt.ask(
            "Case name [dim](optional \u2014 leave blank for auto-generated)[/dim]",
            default="",
        ).strip()
        case_name = case_name_input or None

    _show_run_summary("bec", tenant, target_users, start_dt, end_dt, output_dir, case_name)

    token, _ = _authenticate(tenant, client_id)

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
    )

    render_summary(result)
    case.close()

    if result.errors:
        console.print(f"[yellow]⚠ {len(result.errors)} collector(s) encountered errors. Check case_audit.txt for details.[/yellow]")

    console.print("[bold green]BEC collection complete.[/bold green]")


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
        cirrus run ato --tenant contoso.com --users-file targets.txt --days 14
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
        if not Confirm.ask("[yellow]No user filter — this will collect data for ALL users. Continue?[/yellow]"):
            raise typer.Exit(0)

    start_dt, end_dt = _resolve_date_range(days, start_date, end_date)

    if interactive and case_name is None:
        case_name_input = Prompt.ask(
            "Case name [dim](optional \u2014 leave blank for auto-generated)[/dim]",
            default="",
        ).strip()
        case_name = case_name_input or None

    _show_run_summary("ato", tenant, target_users, start_dt, end_dt, output_dir, case_name)

    token, _ = _authenticate(tenant, client_id)

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
    )

    render_summary(result)
    case.close()

    if result.errors:
        console.print(f"[yellow]⚠ {len(result.errors)} collector(s) encountered errors. Check case_audit.txt for details.[/yellow]")

    console.print("[bold green]ATO collection complete.[/bold green]")


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
        cirrus run bec-ato --tenant contoso.com --users-file targets.txt --days 14
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
        if not Confirm.ask("[yellow]No user filter — this will collect data for ALL users. Continue?[/yellow]"):
            raise typer.Exit(0)

    start_dt, end_dt = _resolve_date_range(days, start_date, end_date)

    if interactive and case_name is None:
        case_name_input = Prompt.ask(
            "Case name [dim](optional \u2014 leave blank for auto-generated)[/dim]",
            default="",
        ).strip()
        case_name = case_name_input or None

    _show_run_summary("bec-ato", tenant, target_users, start_dt, end_dt, output_dir, case_name)

    token, _ = _authenticate(tenant, client_id)

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
    )

    render_summary(result)
    case.close()

    if result.errors:
        console.print(f"[yellow]⚠ {len(result.errors)} collector(s) encountered errors. Check case_audit.txt for details.[/yellow]")

    console.print("[bold green]BEC + ATO collection complete.[/bold green]")


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
) -> None:
    """
    [bold]Full Tenant Collection Workflow[/bold]

    Sweeps the entire tenant for all supported artifact types.
    Use when the compromised account is unknown, or for proactive threat hunting.

    Run without flags to launch the interactive wizard.

    Examples (scripted):
        cirrus run full --tenant contoso.com --all-users --days 90
        cirrus run full --tenant contoso.com --all-users --start-date 2026-03-01 --end-date 2026-03-18
        cirrus run full --tenant contoso.com --users-file targets.txt --days 30
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
        if not Confirm.ask("Collect for ALL users in the tenant. Continue?"):
            raise typer.Exit(0)

    start_dt, end_dt = _resolve_date_range(days, start_date, end_date)

    if interactive and case_name is None:
        case_name_input = Prompt.ask(
            "Case name [dim](optional \u2014 leave blank for auto-generated)[/dim]",
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
    )

    render_summary(result)
    case.close()

    if result.errors:
        console.print(f"[yellow]⚠ {len(result.errors)} collector(s) encountered errors.[/yellow]")

    console.print("[bold green]Full collection complete.[/bold green]")


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
                "Case name [dim](leave blank for auto-generated)[/dim]",
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
    console.print(f"\n[bold]Running correlation engine on:[/bold] {case_dir}\n")

    report = run_correlator(case_dir)
    summary = report["summary"]
    findings = report["findings"]

    loaded = ", ".join(report.get("collectors_loaded") or [])
    console.print(f"[dim]Collectors loaded:[/dim] {loaded or 'none'}\n")

    if not findings:
        console.print("[green]No cross-collector findings.[/green]")
    else:
        table = Table(
            title="Cross-Collector Findings",
            border_style="bright_blue",
            header_style="bold magenta",
        )
        table.add_column("ID", style="dim", width=10)
        table.add_column("Sev", width=8)
        table.add_column("User", style="cyan")
        table.add_column("Title")

        severity_style = {"high": "red", "medium": "yellow", "low": "dim"}
        for f in findings:
            sev = f["severity"]
            sev_label = f"[{severity_style.get(sev, 'white')}]{sev.upper()}[/{severity_style.get(sev, 'white')}]"
            table.add_row(f["id"], sev_label, f.get("user") or "—", f["title"])

        console.print(table)
        console.print(
            f"\n[bold]Total:[/bold] {summary['total_findings']} finding(s)  "
            f"[red]{summary.get('high', 0)} HIGH[/red]  "
            f"[yellow]{summary.get('medium', 0)} MEDIUM[/yellow]\n"
            f"[bold]JSON:[/bold]   {case_dir / 'ioc_correlation.json'}\n"
            f"[bold]Text:[/bold]   {case_dir / 'ioc_correlation.txt'}\n"
        )

    # Always generate HTML report
    from cirrus.analysis.report import generate_report
    report_path = generate_report(case_dir)
    console.print(f"[bold]Report:[/bold] [cyan]{report_path}[/cyan]\n")

        # Print details for each finding
        for f in findings:
            sev = f["severity"]
            color = severity_style.get(sev, "white")
            console.print(
                Panel(
                    f"[bold]{f['description']}[/bold]\n\n"
                    f"[dim]Recommendation:[/dim] {f['recommendation']}",
                    title=f"[{color}]{f['id']} — {f['title']}[/{color}]",
                    border_style=color,
                    expand=False,
                )
            )


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
