"""
CIRRUS CLI — main entry point.

Commands:
    cirrus auth login     — authenticate to a tenant
    cirrus auth logout    — clear cached credentials
    cirrus auth status    — show cached tenants

    cirrus run bec        — run BEC investigation workflow
    cirrus run full       — run full-tenant collection
    cirrus run ato        — (roadmap)

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

import sys
from dataclasses import dataclass
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
from cirrus.workflows.base import render_summary
from cirrus.workflows.bec import BECWorkflow
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
# Shared option types
# ---------------------------------------------------------------------------

TenantOpt = Annotated[str, typer.Option("--tenant", "-t", help="Tenant domain or GUID (e.g. contoso.com or <guid>)")]
OutputDirOpt = Annotated[Path, typer.Option("--output-dir", "-o", help="Directory to write case folders to.", show_default=True)]
CaseNameOpt = Annotated[Optional[str], typer.Option("--case-name", "-c", help="Custom case name prefix.")]
DaysOpt = Annotated[int, typer.Option("--days", "-d", help="How many days back to collect.", show_default=True)]
UserOpt = Annotated[Optional[str], typer.Option("--user", help="Single target user UPN.")]
UsersOpt = Annotated[Optional[list[str]], typer.Option("--users", help="Multiple target UPNs (repeat flag for each).")]
UsersFileOpt = Annotated[Optional[Path], typer.Option("--users-file", help="Text file with one UPN per line.")]
AllUsersOpt = Annotated[bool, typer.Option("--all-users", help="Target the entire tenant (no user filter).")]
ClientIdOpt = Annotated[Optional[str], typer.Option("--client-id", help="Override app registration client ID.")]
BenchmarkOpt = Annotated[Optional[str], typer.Option("--benchmark", "-b", help="Benchmark: cis-m365, cis-entra, or all. Omit to use the wizard.")]
LevelOpt = Annotated[Optional[str], typer.Option("--level", "-l", help="CIS levels: 1, 2, or all. Omit to use the wizard.")]
OptionalTenantOpt = Annotated[Optional[str], typer.Option("--tenant", "-t", help="Tenant domain or GUID. Prompted if omitted.")]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _banner() -> None:
    console.print(
        Panel.fit(
            f"[bold cyan]CIRRUS[/bold cyan] [dim]v{__version__}[/dim]\n"
            "[dim]Cloud Incident Response & Reconnaissance Utility Suite[/dim]",
            border_style="bright_blue",
        )
    )


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
    choice = Prompt.ask(
        "How would you like to target users?",
        choices=["1", "2", "3", "4"],
        default="1",
        show_choices=False,
    )
    console.print(
        "  [cyan]1[/cyan] Single user\n"
        "  [cyan]2[/cyan] Multiple users (comma-separated)\n"
        "  [cyan]3[/cyan] Load users from a file\n"
        "  [cyan]4[/cyan] All users in the tenant\n",
        highlight=False,
    )
    choice = Prompt.ask("Choice", choices=["1", "2", "3", "4"])

    if choice == "1":
        upn = Prompt.ask("Enter user UPN")
        return [upn.strip()]
    elif choice == "2":
        raw = Prompt.ask("Enter UPNs (comma-separated)")
        return [u.strip() for u in raw.split(",") if u.strip()]
    elif choice == "3":
        path_str = Prompt.ask("Path to users file")
        p = Path(path_str)
        if not p.exists():
            console.print(f"[red]File not found:[/red] {p}")
            raise typer.Exit(1)
        lines = p.read_text().splitlines()
        return [line.strip() for line in lines if line.strip() and not line.startswith("#")]
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
        console.print("[dim]A browser window will open. Sign in with an account that has the required roles.[/dim]\n")
        token = get_token(tenant, **kwargs)
        console.print("[green]✓ Authentication successful[/green]\n")
        return token, tenant
    except AuthenticationError as e:
        console.print(f"[red]Authentication failed:[/red] {e}")
        raise typer.Exit(1)


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
    tenant: TenantOpt,
    output_dir: OutputDirOpt = DEFAULT_OUTPUT_DIR,
    case_name: CaseNameOpt = None,
    days: DaysOpt = 30,
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

    Example:
        cirrus run bec --tenant contoso.com --user john@contoso.com --days 30
    """
    _banner()
    console.print(f"[bold magenta]Workflow:[/bold magenta] Business Email Compromise (BEC)")
    console.print(f"[bold]Tenant:[/bold]  [cyan]{tenant}[/cyan]")
    console.print(f"[bold]Days:[/bold]    {days}\n")

    target_users = _resolve_users(user, users, users_file, all_users)
    if target_users:
        console.print(f"[bold]Targets:[/bold] {', '.join(target_users)}\n")
    else:
        if not Confirm.ask("[yellow]No user filter — this will collect data for ALL users. Continue?[/yellow]"):
            raise typer.Exit(0)

    token, _ = _authenticate(tenant, client_id)

    output_dir.mkdir(parents=True, exist_ok=True)
    case = Case.create(tenant, output_dir, case_name)
    console.print(f"[bold]Case folder:[/bold] {case.case_dir}\n")

    case.audit.log_event("WORKFLOW_CONFIG", {
        "workflow": "bec",
        "tenant": tenant,
        "days": days,
        "users": target_users or "all",
    })

    workflow = BECWorkflow(token, case)
    result = workflow.run(users=target_users, days=days, tenant=tenant)

    render_summary(result)
    case.close()

    if result.errors:
        console.print(f"[yellow]⚠ {len(result.errors)} collector(s) encountered errors. Check case_audit.txt for details.[/yellow]")

    console.print("[bold green]BEC collection complete.[/bold green]")


@run_app.command("full")
def run_full(
    tenant: TenantOpt,
    output_dir: OutputDirOpt = DEFAULT_OUTPUT_DIR,
    case_name: CaseNameOpt = None,
    days: DaysOpt = 30,
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

    Example:
        cirrus run full --tenant contoso.com --all-users --days 90
    """
    _banner()
    console.print(f"[bold magenta]Workflow:[/bold magenta] Full Tenant Collection")
    console.print(f"[bold]Tenant:[/bold]  [cyan]{tenant}[/cyan]")
    console.print(f"[bold]Days:[/bold]    {days}\n")

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

    token, _ = _authenticate(tenant, client_id)

    output_dir.mkdir(parents=True, exist_ok=True)
    case = Case.create(tenant, output_dir, case_name)
    console.print(f"[bold]Case folder:[/bold] {case.case_dir}\n")

    case.audit.log_event("WORKFLOW_CONFIG", {
        "workflow": "full",
        "tenant": tenant,
        "days": days,
        "users": target_users or "all",
    })

    workflow = FullWorkflow(token, case)
    result = workflow.run(users=target_users, days=days, tenant=tenant)

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
        artifacts = len(list(c.glob("*.json"))) - 1  # exclude case_audit.jsonl... actually .jsonl
        artifacts = len(list(c.glob("*.json")))
        audit_ok = "✓" if (c / "case_audit.jsonl").exists() else "✗"
        table.add_row(c.name, str(artifacts), audit_ok)

    console.print(table)


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
