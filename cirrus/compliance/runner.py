"""
ComplianceRunner: orchestrates all CIS checks against a tenant.

Usage:
    runner = ComplianceRunner(token, benchmark="all", levels=[1, 2])
    results = runner.run()
"""

from __future__ import annotations

from typing import Literal

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from cirrus.compliance.base import BaseCheck, CheckResult, CheckStatus
from cirrus.compliance.checks.admin import ADMIN_CHECKS
from cirrus.compliance.checks.exchange import EXCHANGE_CHECKS
from cirrus.compliance.checks.identity import IDENTITY_CHECKS
from cirrus.compliance.checks.logging import LOGGING_CHECKS
from cirrus.compliance.checks.teams_sharepoint import SHAREPOINT_CHECKS, TEAMS_CHECKS
from cirrus.compliance.context import ContextBuilder, PolicyContext
from cirrus.utils.license import TenantLicenseProfile

Benchmark = Literal["cis-m365", "cis-entra", "all"]

console = Console()


def _render_license_banner(profile: TenantLicenseProfile) -> None:
    """Print a compact license tier summary inline with the compliance output."""
    parts: list[str] = []
    for label, available, skipped in profile.summary_rows():
        if available:
            parts.append(f"{label} [green]✓[/green]")
        else:
            parts.append(f"{label} [red]✗[/red]")

    console.print("  [bold]Tenant licenses:[/bold]  " + "   ".join(parts))

    for label, available, skipped in profile.summary_rows():
        if not available and skipped:
            console.print(
                f"  [dim]↳ {label} not licensed — some checks may show expected FAILs[/dim]"
            )
    console.print()

ALL_CHECKS: list[type[BaseCheck]] = (
    IDENTITY_CHECKS
    + ADMIN_CHECKS
    + EXCHANGE_CHECKS
    + TEAMS_CHECKS
    + SHAREPOINT_CHECKS
    + LOGGING_CHECKS
)


class ComplianceRunner:
    """Runs selected CIS checks against a pre-fetched PolicyContext."""

    def __init__(
        self,
        token: str,
        benchmark: Benchmark = "all",
        levels: list[int] | None = None,
        tenant: str | None = None,
        upn: str | None = None,
    ) -> None:
        self.token = token
        self.benchmark = benchmark
        self.levels = levels or [1, 2]
        self.tenant = tenant
        self.upn = upn

    def _select_checks(self) -> list[type[BaseCheck]]:
        selected = []
        for check_cls in ALL_CHECKS:
            # Level filter
            if check_cls.level not in self.levels:
                continue

            # Benchmark filter
            if self.benchmark == "cis-m365":
                if "M365" not in check_cls.benchmark and "CIS M365" not in check_cls.benchmark:
                    continue
            elif self.benchmark == "cis-entra":
                if "Entra" not in check_cls.benchmark:
                    continue
            # "all" — include everything

            selected.append(check_cls)
        return selected

    def run(self) -> "ComplianceReport":
        # Step 1: Build context
        console.print("\n[bold]Fetching tenant policy data...[/bold]")
        if self.tenant:
            console.print(
                "[dim]Exchange Online checks may open a browser window for authentication. "
                "This is normal — sign in with your Exchange admin account.[/dim]"
            )
        builder = ContextBuilder(self.token)

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task(
                "Collecting policy data (Graph API + DNS + Exchange Online PS)...",
                total=None,
            )
            ctx = builder.build(tenant=self.tenant, upn=self.upn)
            progress.update(task, completed=1, total=1)

        if ctx.fetch_errors:
            for key, err in ctx.fetch_errors.items():
                console.print(f"  [yellow]⚠ Could not fetch {key}:[/yellow] {err}")

        # License banner — uses already-fetched SKU data, no extra API call
        if ctx.license_profile:
            _render_license_banner(ctx.license_profile)

        # Report Exchange PS and DNS status
        if ctx.exchange_ps and ctx.exchange_ps.available:
            console.print(
                f"  [green]✓ Exchange Online PS connected[/green] "
                f"(EXO module v{ctx.exchange_ps.exa_version})"
            )
        elif ctx.exchange_ps and ctx.exchange_ps.error:
            console.print(
                f"  [yellow]⚠ Exchange Online PS unavailable:[/yellow] {ctx.exchange_ps.error}\n"
                "  [dim]Exchange checks will show as MANUAL. Run: cirrus deps install[/dim]"
            )
        if ctx.dns_results:
            console.print(
                f"  [green]✓ DNS checks completed[/green] for {len(ctx.dns_results)} domain(s): "
                + ", ".join(ctx.dns_results.keys())
            )
        elif "dns" in ctx.fetch_errors:
            console.print(
                f"  [yellow]⚠ DNS checks unavailable:[/yellow] {ctx.fetch_errors['dns']}"
            )
        if ctx.teams_ps and ctx.teams_ps.available:
            console.print(f"  [green]✓ Teams PS connected[/green] (MicrosoftTeams v{ctx.teams_ps.teams_version})")
        elif ctx.teams_ps and ctx.teams_ps.error:
            console.print(f"  [yellow]⚠ Teams PS unavailable:[/yellow] {ctx.teams_ps.error}")
        if ctx.sharepoint_ps and ctx.sharepoint_ps.available:
            console.print(f"  [green]✓ SharePoint Online PS connected[/green] (SPO module v{ctx.sharepoint_ps.spo_version})")
        elif ctx.sharepoint_ps and ctx.sharepoint_ps.error:
            console.print(f"  [yellow]⚠ SharePoint PS unavailable:[/yellow] {ctx.sharepoint_ps.error}")

        # Step 2: Run checks
        selected = self._select_checks()
        results: list[CheckResult] = []

        console.print(f"\n[bold]Running {len(selected)} compliance checks...[/bold]\n")

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description:<50}"),
            console=console,
            transient=False,
        ) as progress:
            for check_cls in selected:
                check = check_cls()
                task = progress.add_task(
                    f"[{check.level}] {check.control_id} — {check.title}",
                    total=1,
                )
                try:
                    result = check.run(ctx)
                except Exception as e:
                    from cirrus.compliance.base import CheckResult
                    result = CheckResult(
                        control_id=check.control_id,
                        title=check.title,
                        benchmark=check.benchmark,
                        level=check.level,
                        section=check.section,
                        status=CheckStatus.ERROR,
                        expected="",
                        actual=f"Check error: {e}",
                        rationale=check.rationale,
                        remediation=check.remediation,
                        manual_steps=check.manual_steps,
                        reference=check.reference,
                    )

                results.append(result)
                status_color = {
                    CheckStatus.PASS: "green",
                    CheckStatus.FAIL: "red",
                    CheckStatus.WARN: "yellow",
                    CheckStatus.MANUAL: "cyan",
                    CheckStatus.ERROR: "red",
                    CheckStatus.SKIP: "dim",
                }.get(result.status, "white")

                progress.update(
                    task,
                    completed=1,
                    description=f"[{status_color}][{result.status.value}][/{status_color}] "
                                f"[L{result.level}] {result.control_id} — {result.title}",
                )

        return ComplianceReport(results=results, context=ctx)


class ComplianceReport:
    """Holds all check results and provides summary statistics."""

    def __init__(self, results: list[CheckResult], context: PolicyContext) -> None:
        self.results = results
        self.context = context

    @property
    def passed(self) -> list[CheckResult]:
        return [r for r in self.results if r.status == CheckStatus.PASS]

    @property
    def failed(self) -> list[CheckResult]:
        return [r for r in self.results if r.status == CheckStatus.FAIL]

    @property
    def warned(self) -> list[CheckResult]:
        return [r for r in self.results if r.status == CheckStatus.WARN]

    @property
    def manual(self) -> list[CheckResult]:
        return [r for r in self.results if r.status == CheckStatus.MANUAL]

    @property
    def errors(self) -> list[CheckResult]:
        return [r for r in self.results if r.status == CheckStatus.ERROR]

    @property
    def score(self) -> tuple[int, int]:
        """Returns (passed, total_verifiable) — excludes MANUAL and SKIP."""
        verifiable = [r for r in self.results if r.status not in (CheckStatus.MANUAL, CheckStatus.SKIP)]
        return len(self.passed), len(verifiable)

    @property
    def score_pct(self) -> float:
        passed, total = self.score
        return round(passed / total * 100, 1) if total else 0.0

    def by_section(self) -> dict[str, list[CheckResult]]:
        sections: dict[str, list[CheckResult]] = {}
        for r in self.results:
            sections.setdefault(r.section, []).append(r)
        return sections
