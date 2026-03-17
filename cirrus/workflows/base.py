"""
Base workflow orchestrator.

Workflows coordinate multiple collectors, write output, update the audit log,
and render progress to the terminal via Rich.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
from rich.table import Table

from cirrus.collectors.base import CollectorError, GraphCollector
from cirrus.output.case import Case
from cirrus.output.writer import save_collection
from cirrus.utils.license import TenantLicenseProfile

console = Console()


@dataclass
class CollectionResult:
    """Result of one collector run."""
    collector_name: str
    record_count: int
    json_path: Path
    csv_path: Path
    json_hash: str
    csv_hash: str
    ioc_count: int = 0
    error: str | None = None


@dataclass
class WorkflowResult:
    """Aggregate result of a complete workflow run."""
    workflow_name: str
    tenant: str
    case_dir: Path
    results: list[CollectionResult] = field(default_factory=list)

    @property
    def total_records(self) -> int:
        return sum(r.record_count for r in self.results)

    @property
    def total_iocs(self) -> int:
        return sum(r.ioc_count for r in self.results)

    @property
    def errors(self) -> list[CollectionResult]:
        return [r for r in self.results if r.error]


class BaseWorkflow:
    """
    Base class for all CIRRUS workflows.

    Subclasses define `steps` — an ordered list of (collector_class, kwargs) tuples.
    """

    name: str = "base"
    description: str = ""

    def __init__(self, token: str, case: Case) -> None:
        self.token = token
        self.case = case

    def run(
        self,
        users: list[str] | None,
        days: int,
        tenant: str,
        extra_params: dict[str, Any] | None = None,
    ) -> WorkflowResult:
        """
        Execute the workflow.

        Args:
            users:       Target users (None = all).
            days:        Days back to collect.
            tenant:      Tenant identifier (for display/logging).
            extra_params: Additional params passed to collectors.

        Returns WorkflowResult with per-collector results.
        """
        params = extra_params or {}
        result = WorkflowResult(
            workflow_name=self.name,
            tenant=tenant,
            case_dir=self.case.case_dir,
        )

        self.case.audit.log_workflow_start(
            self.name,
            {"tenant": tenant, "users": users or "all", "days": days},
        )

        # ------------------------------------------------------------------ #
        # License pre-check — fetch once, inject into every collector         #
        # ------------------------------------------------------------------ #
        import requests as _requests
        _probe_session = _requests.Session()
        _probe_session.headers.update(
            {"Authorization": f"Bearer {self.token}", "Accept": "application/json"}
        )
        license_profile = TenantLicenseProfile.fetch(_probe_session)
        _render_license_banner(license_profile)

        steps = self._build_steps(users=users, days=days, **params)

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description:<40}"),
            BarColumn(bar_width=30),
            TaskProgressColumn(),
            console=console,
            transient=False,
        ) as progress:
            for collector_cls, collector_kwargs, display_name in steps:
                task = progress.add_task(display_name, total=None)
                collector: GraphCollector = collector_cls(self.token)
                collector.license_profile = license_profile

                self.case.audit.log_collection_start(
                    collector.name,
                    {k: str(v) for k, v in collector_kwargs.items()},
                )

                try:
                    records = collector.collect(**collector_kwargs)
                    json_path, csv_path, json_hash, csv_hash = save_collection(
                        records, self.case.case_dir, collector.name
                    )
                    ioc_count = sum(
                        len(r.get("_iocFlags", [])) for r in records
                    )

                    self.case.audit.log_collection_complete(
                        collector.name,
                        len(records),
                        json_path,
                        json_hash,
                    )

                    cr = CollectionResult(
                        collector_name=collector.name,
                        record_count=len(records),
                        json_path=json_path,
                        csv_path=csv_path,
                        json_hash=json_hash,
                        csv_hash=csv_hash,
                        ioc_count=ioc_count,
                    )
                    result.results.append(cr)
                    progress.update(task, completed=len(records), total=len(records))

                except CollectorError as e:
                    self.case.audit.log_collection_error(collector.name, str(e))
                    cr = CollectionResult(
                        collector_name=collector.name,
                        record_count=0,
                        json_path=Path(),
                        csv_path=Path(),
                        json_hash="",
                        csv_hash="",
                        error=str(e),
                    )
                    result.results.append(cr)
                    progress.update(task, completed=0, total=1, description=f"[red]{display_name} (FAILED)")

        self.case.audit.log_workflow_complete(self.name, result.total_records)
        return result

    def _build_steps(
        self, users: list[str] | None, days: int, **kwargs
    ) -> list[tuple]:
        """
        Override in subclasses.
        Return list of (CollectorClass, kwargs_dict, display_name).
        """
        raise NotImplementedError


def _render_license_banner(profile: TenantLicenseProfile) -> None:
    """Print a compact license profile banner before collection starts."""
    parts: list[str] = []
    for label, available, skipped in profile.summary_rows():
        if available:
            parts.append(f"{label} [green]✓[/green]")
        else:
            parts.append(f"{label} [red]✗[/red]")

    console.print("\n[bold]Tenant license profile:[/bold]  " + "   ".join(parts))

    for label, available, skipped in profile.summary_rows():
        if not available and skipped:
            names = ", ".join(skipped)
            console.print(
                f"  [dim]↳ {label} not found — {names} will be skipped[/dim]"
            )

    console.print()


def render_summary(result: WorkflowResult) -> None:
    """Print a Rich summary table after workflow completion."""
    table = Table(
        title=f"\n[bold]CIRRUS — {result.workflow_name.upper()} Collection Summary[/bold]",
        show_header=True,
        header_style="bold magenta",
        border_style="bright_blue",
    )
    table.add_column("Collector", style="cyan", min_width=30)
    table.add_column("Records", justify="right", style="white")
    table.add_column("IOC Flags", justify="right")
    table.add_column("Status", justify="center")

    for r in result.results:
        if r.error and r.error.startswith("Skipped:"):
            status = "[yellow]SKIPPED[/yellow]"
            records_str = "-"
            ioc_str = "-"
        elif r.error:
            status = "[red]FAILED[/red]"
            records_str = "-"
            ioc_str = "-"
        elif r.ioc_count > 0:
            status = "[yellow]⚠ REVIEW[/yellow]"
            records_str = str(r.record_count)
            ioc_str = f"[yellow]{r.ioc_count}[/yellow]"
        else:
            status = "[green]✓[/green]"
            records_str = str(r.record_count)
            ioc_str = "0"

        table.add_row(r.collector_name, records_str, ioc_str, status)

    console.print(table)
    console.print(
        f"\n[bold]Total records:[/bold] {result.total_records}  "
        f"[bold]Total IOC flags:[/bold] [yellow]{result.total_iocs}[/yellow]\n"
        f"[bold]Case folder:[/bold] {result.case_dir}\n"
    )
