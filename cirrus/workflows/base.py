"""
Base workflow orchestrator.

Workflows coordinate multiple collectors, write output, update the audit log,
and render progress to the terminal via Rich.
"""

from __future__ import annotations

import json as _json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
from rich.table import Table

from cirrus.collectors.base import CollectorError, GraphCollector
from cirrus.output.case import Case
from cirrus.output.writer import save_collection
from cirrus.utils.helpers import file_sha256
from cirrus.utils.license import TenantLicenseProfile

console = Console()


@dataclass
class CollectionResult:
    """Result of one collector run."""
    collector_name: str
    record_count: int
    json_path: Path
    csv_path: Path
    ndjson_path: Path
    json_hash: str
    csv_hash: str
    ndjson_hash: str
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

    def __init__(self, token: str, case: Case, token_provider: Callable[[], str] | None = None) -> None:
        self.token = token
        self.case = case
        self.token_provider = token_provider

    def run(
        self,
        users: list[str] | None,
        tenant: str,
        start_dt: datetime,
        end_dt: datetime,
        extra_params: dict[str, Any] | None = None,
        run_analysis: bool = True,
    ) -> WorkflowResult:
        """
        Execute the workflow.

        Args:
            users:        Target users (None = all).
            tenant:       Tenant identifier (for display/logging).
            start_dt:     Collection window start (UTC).
            end_dt:       Collection window end (UTC).
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
            {
                "tenant": tenant,
                "users": users or "all",
                "start_date": start_dt.strftime("%Y-%m-%d"),
                "end_date": end_dt.strftime("%Y-%m-%d"),
            },
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

        steps = self._build_steps(users=users, start_dt=start_dt, end_dt=end_dt, **params)

        with Progress(
            SpinnerColumn(),
            TextColumn("{task.description}"),
            BarColumn(bar_width=20),
            TaskProgressColumn(),
            console=console,
            transient=False,
        ) as progress:
            # Factory kept outside the loop so it doesn't capture loop variables.
            def _make_status_cb(
                prog: Progress, t: Any, name: str
            ) -> Callable[[str], None]:
                def _cb(msg: str) -> None:
                    prog.update(
                        t,
                        description=f"[bold blue]{name}[/bold blue]  [dim]{msg}[/dim]",
                    )
                return _cb

            def _make_page_cb(
                f: Any, col: GraphCollector
            ) -> Callable[[list[dict]], None]:
                """Write each page of raw records to the open NDJSON file handle."""
                def _cb(page_records: list[dict]) -> None:
                    for record in col.sofelk_transform(page_records):
                        f.write(
                            _json.dumps(record, ensure_ascii=False, default=str) + "\n"
                        )
                    f.flush()
                return _cb

            for collector_cls, collector_kwargs, display_name in steps:
                task = progress.add_task(
                    f"[bold blue]{display_name}[/bold blue]", total=None
                )
                collector: GraphCollector = collector_cls(self.token)
                collector.license_profile = license_profile
                collector.token_provider = self.token_provider
                collector.on_status = _make_status_cb(progress, task, display_name)

                # Open the NDJSON file before collection starts so records are
                # streamed to disk page-by-page as they arrive.
                ndjson_path = self.case.collection_dir / "json" / f"{collector.name}.ndjson"
                ndjson_path.parent.mkdir(parents=True, exist_ok=True)

                self.case.audit.log_collection_start(
                    collector.name,
                    {k: str(v) for k, v in collector_kwargs.items()},
                )

                with open(ndjson_path, "w", encoding="utf-8") as _ndjson_fh:
                    collector.on_page = _make_page_cb(_ndjson_fh, collector)

                    try:
                        records = collector.collect(**collector_kwargs)
                    except CollectorError as e:
                        # File is closed by the 'with' block on continue.
                        self.case.audit.log_collection_error(collector.name, str(e))
                        cr = CollectionResult(
                            collector_name=collector.name,
                            record_count=0,
                            json_path=Path(),
                            csv_path=Path(),
                            ndjson_path=ndjson_path,
                            json_hash="",
                            csv_hash="",
                            ndjson_hash="",
                            error=str(e),
                        )
                        result.results.append(cr)
                        progress.update(
                            task, completed=0, total=1,
                            description=f"[red]{display_name} (FAILED)",
                        )
                        continue

                # NDJSON file is now closed and complete — hash it.
                ndjson_hash = file_sha256(ndjson_path)

                json_path, csv_path, _, json_hash, csv_hash, _ = save_collection(
                    records, self.case.collection_dir, collector.name,
                    prewritten_ndjson=ndjson_path,
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
                    ndjson_path=ndjson_path,
                    json_hash=json_hash,
                    csv_hash=csv_hash,
                    ndjson_hash=ndjson_hash,
                    ioc_count=ioc_count,
                )
                result.results.append(cr)
                progress.update(task, completed=len(records), total=len(records))

        self.case.audit.log_workflow_complete(self.name, result.total_records)

        # ------------------------------------------------------------------ #
        # Post-collection: cross-collector correlation + HTML report          #
        # Skipped when run_analysis=False (CLI handles it separately so it   #
        # can prompt the analyst or respect --collect-only).                 #
        # ------------------------------------------------------------------ #
        if run_analysis:
            _run_correlation(self.case.case_dir, result, self.case)

        return result

    def _build_steps(
        self,
        users: list[str] | None,
        start_dt: datetime,
        end_dt: datetime,
        **kwargs,
    ) -> list[tuple]:
        """
        Override in subclasses.
        Return list of (CollectorClass, kwargs_dict, display_name).
        """
        raise NotImplementedError


def render_findings(report: dict) -> None:
    """
    Print correlation findings to the terminal.

    Shows a table of all findings (ID, severity, user, title) and expands
    HIGH-severity findings with their description and evidence summary.
    Called by both _run_correlation (end of workflow) and cirrus analyze.
    """
    from rich.panel import Panel

    findings = report.get("findings") or []
    summary  = report.get("summary") or {}

    if not findings:
        console.print("[bold]Correlation:[/bold] [green]No cross-collector findings.[/green]")
        return

    high_count   = summary.get("high", 0)
    medium_count = summary.get("medium", 0)
    total        = summary.get("total_findings", len(findings))

    severity_style = {"high": "red", "medium": "yellow", "low": "dim"}

    table = Table(
        title=f"\n[bold]Cross-Collector Findings[/bold]",
        border_style="bright_blue",
        header_style="bold magenta",
        show_lines=False,
    )
    table.add_column("ID",       style="dim",   width=10, no_wrap=True)
    table.add_column("Sev",      width=8,       no_wrap=True)
    table.add_column("User",     style="cyan",  min_width=24)
    table.add_column("Title")

    for f in findings:
        sev = f.get("severity", "")
        sty = severity_style.get(sev, "white")
        table.add_row(
            f.get("id", "")[:10],
            f"[{sty}]{sev.upper()}[/{sty}]",
            f.get("user") or "—",
            f.get("title", ""),
        )

    console.print(table)

    # Expand HIGH findings with description + evidence
    high_findings = [f for f in findings if f.get("severity") == "high"]
    if high_findings:
        console.print("\n[bold red]HIGH findings — detail:[/bold red]")
        for f in high_findings:
            console.print(f"\n  [bold cyan]{f.get('id','')}[/bold cyan]  {f.get('title','')}")
            desc = f.get("description", "")
            if desc:
                # Print up to 3 sentences of description
                sentences = desc.replace("\n", " ").split(". ")
                console.print(f"  [dim]{'. '.join(sentences[:3]).strip()}[/dim]")
            evidence = f.get("evidence") or []
            for ev in evidence[:3]:
                ev_desc = ev.get("description", "")
                ev_ts   = ev.get("timestamp", "")[:19]
                if ev_desc:
                    console.print(f"    [red]→[/red] {ev_desc}" + (f"  [dim]{ev_ts}[/dim]" if ev_ts else ""))
            techniques = f.get("mitre_techniques") or []
            if techniques:
                console.print(f"    [dim]ATT&CK: {', '.join(techniques[:3])}[/dim]")

    console.print(
        f"\n[bold]Total:[/bold] {total} finding(s)  "
        f"[red]{high_count} HIGH[/red]  "
        f"[yellow]{medium_count} MEDIUM[/yellow]\n"
        f"[dim]Full detail: ioc_correlation.txt[/dim]"
    )


def _run_correlation(case_dir: Path, result: "WorkflowResult", case: "Case") -> None:
    """
    Run the cross-collector correlation engine and log the result.
    Import is deferred to keep startup fast and avoid circular imports.
    """
    try:
        from cirrus.analysis.correlator import run_correlator
        report = run_correlator(case_dir)
        finding_count = report["summary"]["total_findings"]
        high_count = report["summary"].get("high", 0)

        # Log to case audit
        case.audit.log_event(
            "correlation_complete",
            {
                "findings": finding_count,
                "high": high_count,
                "medium": report["summary"].get("medium", 0),
                "output": str(case_dir / "ioc_correlation.json"),
            },
        )

        console.print()
        render_findings(report)

        # HTML report
        try:
            from cirrus.analysis.report import generate_report
            report_path = generate_report(case_dir)
            console.print(f"[bold]Report:[/bold]  [cyan]{report_path}[/cyan]\n")
        except Exception as exc:
            console.print(f"[dim]HTML report skipped: {exc}[/dim]")

        # Excel workbook
        try:
            from cirrus.output.excel import generate_workbook
            wb_path = generate_workbook(case_dir)
            if wb_path:
                console.print(f"[bold]Workbook:[/bold] [cyan]{wb_path}[/cyan]\n")
        except Exception as exc:
            console.print(f"[dim]Excel workbook skipped: {exc}[/dim]")

    except Exception as exc:
        console.print(f"\n[dim]Correlation skipped: {exc}[/dim]")


def _render_license_banner(profile: TenantLicenseProfile) -> None:
    """Print a compact license profile banner before collection starts."""
    parts: list[str] = []
    for label, available, skipped, note in profile.summary_rows():
        if available:
            parts.append(f"{label} [green]✓[/green]")
        else:
            parts.append(f"{label} [red]✗[/red]")

    console.print("\n[bold]Tenant license profile:[/bold]  " + "   ".join(parts))

    for label, available, skipped, note in profile.summary_rows():
        if not available and skipped:
            names = ", ".join(skipped)
            console.print(
                f"  [dim]↳ {label} not found — {names} will be skipped[/dim]"
            )
        elif not available and note:
            console.print(f"  [dim]↳ {note}[/dim]")

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
