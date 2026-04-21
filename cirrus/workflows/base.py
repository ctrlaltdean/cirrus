"""
Base workflow orchestrator.

Workflows coordinate multiple collectors, write output, update the audit log,
and render progress to the terminal via Rich.
"""

from __future__ import annotations

import json as _json
import time as _time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from threading import Lock
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
        self.case._workflow_token = token  # stored for post-run auto blast-radius
        self.token_provider = token_provider

    def run(
        self,
        users: list[str] | None,
        tenant: str,
        start_dt: datetime,
        end_dt: datetime,
        extra_params: dict[str, Any] | None = None,
        run_analysis: bool = True,
        sensitivity: str = "auto",
    ) -> WorkflowResult:
        """
        Execute the workflow.

        Args:
            users:        Target users (None = all).
            tenant:       Tenant identifier (for display/logging).
            start_dt:     Collection window start (UTC).
            end_dt:       Collection window end (UTC).
            extra_params: Additional params passed to collectors.
            sensitivity:  Correlation sensitivity: "auto" (default), "low",
                          "medium", or "high". "auto" detects tenant size
                          and picks the appropriate level.

        Returns WorkflowResult with per-collector results.
        """
        params = extra_params or {}
        self._sensitivity = sensitivity  # resolved later, after license probe
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

        # Resolve "auto" sensitivity using tenant user count.
        if self._sensitivity == "auto":
            self._sensitivity = _detect_sensitivity(_probe_session)
            console.print(
                f"[dim]Sensitivity: {self._sensitivity} (auto-detected)[/dim]\n"
            )

        steps = self._build_steps(users=users, start_dt=start_dt, end_dt=end_dt, **params)

        # ── Group steps for parallel execution ───────────────────────────
        # Each step is (cls, kwargs, name) or (cls, kwargs, name, group).
        # Steps with the same group number run concurrently; groups execute
        # sequentially (lower numbers first).  Steps without a group number
        # are auto-assigned to sequential singleton groups.
        grouped: dict[int, list[tuple]] = defaultdict(list)
        auto_group = 0
        for step in steps:
            if len(step) >= 4:
                grouped[step[3]].append(step[:3])
            else:
                grouped[auto_group].append(step[:3])
            auto_group += 1

        result_lock = Lock()

        # ── Checkpoint: skip already-completed collectors on resume ────────
        checkpoint_path = self.case.case_dir / ".collector_checkpoint.json"
        completed_collectors: set[str] = set()
        if checkpoint_path.exists():
            try:
                completed_collectors = set(
                    _json.loads(checkpoint_path.read_text(encoding="utf-8"))
                )
                if completed_collectors:
                    console.print(
                        f"[dim]Resuming: {len(completed_collectors)} collector(s) "
                        f"already completed — skipping.[/dim]\n"
                    )
            except Exception:
                pass

        def _save_checkpoint(collector_name: str) -> None:
            """Append a collector to the checkpoint file (thread-safe)."""
            with result_lock:
                completed_collectors.add(collector_name)
                try:
                    checkpoint_path.write_text(
                        _json.dumps(sorted(completed_collectors), indent=2),
                        encoding="utf-8",
                    )
                except Exception:
                    pass

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
                prog: Progress, t: Any, name: str, t0: float
            ) -> Callable[[str], None]:
                def _cb(msg: str) -> None:
                    elapsed = _time.monotonic() - t0
                    if elapsed < 60:
                        ts = f"{elapsed:.0f}s"
                    else:
                        ts = f"{elapsed / 60:.0f}m {elapsed % 60:.0f}s"
                    prog.update(
                        t,
                        description=(
                            f"[bold blue]{name}[/bold blue]  "
                            f"[dim]{ts} · {msg}[/dim]"
                        ),
                    )
                return _cb

            def _make_page_cb(
                f: Any, col: GraphCollector, write_lock: Lock
            ) -> Callable[[list[dict]], None]:
                """Write each page of raw records to the open NDJSON file handle."""
                def _cb(page_records: list[dict]) -> None:
                    lines = [
                        _json.dumps(record, ensure_ascii=False, default=str) + "\n"
                        for record in col.sofelk_transform(page_records)
                    ]
                    with write_lock:
                        f.writelines(lines)
                        f.flush()
                return _cb

            def _run_single_collector(
                collector_cls: type,
                collector_kwargs: dict,
                display_name: str,
            ) -> CollectionResult | None:
                """Execute one collector — safe to call from a thread."""
                # Check if already completed from a previous run
                temp_collector = collector_cls.__new__(collector_cls)
                coll_name = getattr(temp_collector, "name", collector_cls.__name__)
                if coll_name in completed_collectors:
                    task = progress.add_task(
                        f"[dim]{display_name} (cached)[/dim]", total=1, completed=1
                    )
                    return None  # signal: skip

                task = progress.add_task(
                    f"[bold blue]{display_name}[/bold blue]", total=None
                )
                collector_t0 = _time.monotonic()
                collector: GraphCollector = collector_cls(self.token)
                collector.license_profile = license_profile
                collector.token_provider = self.token_provider
                collector.on_status = _make_status_cb(
                    progress, task, display_name, collector_t0
                )

                ndjson_path = self.case.collection_dir / "json" / f"{collector.name}.ndjson"
                ndjson_path.parent.mkdir(parents=True, exist_ok=True)

                self.case.audit.log_collection_start(
                    collector.name,
                    {k: str(v) for k, v in collector_kwargs.items()},
                )

                file_lock = Lock()
                with open(ndjson_path, "w", encoding="utf-8") as _ndjson_fh:
                    collector.on_page = _make_page_cb(_ndjson_fh, collector, file_lock)

                    try:
                        records = collector.collect(**collector_kwargs)
                    except CollectorError as e:
                        self.case.audit.log_collection_error(collector.name, str(e))
                        fail_elapsed = _time.monotonic() - collector_t0
                        if fail_elapsed < 60:
                            fail_ts = f"{fail_elapsed:.0f}s"
                        else:
                            fail_ts = f"{fail_elapsed / 60:.0f}m {fail_elapsed % 60:.0f}s"
                        progress.update(
                            task, completed=0, total=1,
                            description=(
                                f"[red]{display_name} (FAILED)[/red]  "
                                f"[dim]{fail_ts}[/dim]"
                            ),
                        )
                        return CollectionResult(
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

                elapsed = _time.monotonic() - collector_t0
                if elapsed < 60:
                    ts = f"{elapsed:.0f}s"
                else:
                    ts = f"{elapsed / 60:.0f}m {elapsed % 60:.0f}s"
                progress.update(
                    task, completed=len(records), total=len(records),
                    description=(
                        f"[bold blue]{display_name}[/bold blue]  "
                        f"[dim]{ts} · {len(records)} records[/dim]"
                    ),
                )
                _save_checkpoint(collector.name)
                return CollectionResult(
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

            # ── Execute groups sequentially; steps within a group in parallel ─
            for group_key in sorted(grouped):
                group_steps = grouped[group_key]
                if len(group_steps) == 1:
                    # Single step — run directly (no thread overhead).
                    cls, kw, name = group_steps[0]
                    cr = _run_single_collector(cls, kw, name)
                    if cr is not None:
                        result.results.append(cr)
                else:
                    # Multiple steps — run in parallel threads.
                    with ThreadPoolExecutor(max_workers=len(group_steps)) as executor:
                        futures = {
                            executor.submit(_run_single_collector, cls, kw, name): name
                            for cls, kw, name in group_steps
                        }
                        for future in as_completed(futures):
                            cr = future.result()
                            if cr is not None:
                                with result_lock:
                                    result.results.append(cr)

        self.case.audit.log_workflow_complete(self.name, result.total_records)

        # ------------------------------------------------------------------ #
        # Post-collection: cross-collector correlation + HTML report          #
        # Skipped when run_analysis=False (CLI handles it separately so it   #
        # can prompt the analyst or respect --collect-only).                 #
        # ------------------------------------------------------------------ #
        if run_analysis:
            _run_correlation(
                self.case.case_dir, result, self.case,
                sensitivity=self._sensitivity,
            )

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


def _run_correlation(
    case_dir: Path,
    result: "WorkflowResult",
    case: "Case",
    sensitivity: str = "medium",
) -> None:
    """
    Run the cross-collector correlation engine and log the result.
    Import is deferred to keep startup fast and avoid circular imports.
    """
    try:
        from cirrus.analysis.correlator import run_correlator
        report = run_correlator(case_dir, sensitivity=sensitivity)
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

        # Auto blast-radius for HIGH-finding users
        high_users = sorted({
            f.get("user", "") for f in report.get("findings", [])
            if f.get("severity") == "high" and f.get("user")
        })
        if high_users:
            _run_auto_blast_radius(high_users, result, case, case_dir)

        # Remediation script — only surface it when there are actionable findings
        ps_path = case_dir / "remediation_commands.ps1"
        if ps_path.exists():
            try:
                if "Invoke-Remediation" in ps_path.read_text(encoding="utf-8"):
                    console.print(
                        f"[bold]Remediation:[/bold] [cyan]{ps_path}[/cyan]\n"
                        f"  [dim]Connect-ExchangeOnline + Connect-MgGraph first. "
                        f"Set $DryRun = $false to execute.[/dim]\n"
                    )
            except Exception:
                pass

    except Exception as exc:
        console.print(f"\n[yellow]Correlation failed: {exc}[/yellow]")
        try:
            import traceback
            case.audit.log_event(
                "correlation_error",
                {"error": str(exc), "traceback": traceback.format_exc()},
            )
        except Exception:
            pass


def _run_auto_blast_radius(
    users: list[str],
    result: "WorkflowResult",
    case: "Case",
    case_dir: Path,
) -> None:
    """
    Auto-run blast-radius assessment for users that appear in HIGH findings.

    Uses the same bearer token that was used for collection.  Results are
    written to blast_radius_<user>.json inside the case directory and a
    summary is printed to the terminal.
    """
    try:
        from cirrus.analysis.blast_radius import run_blast_radius

        # Recover the token from the case audit (written at workflow start).
        # The workflow stores self.token but _run_correlation is a standalone
        # function — we recover the token from the session headers that the
        # workflow's probe_session used.  Alternatively, read the first
        # collector's token from the result.  We'll use a fresh silent fetch
        # if possible, otherwise skip.
        token = case._meta.get("_bearer_token") if hasattr(case, "_meta") else None
        if not token:
            # Attempt to read token from the case audit log entry
            try:
                import re
                audit_path = case_dir / "case_audit.txt"
                if audit_path.exists():
                    text = audit_path.read_text(encoding="utf-8")
                    # The token is NOT stored in audit (sensitive) — we need
                    # another approach.  Store it on the case object during run.
                    pass
            except Exception:
                pass

        # Use the stored token from workflow run
        token = getattr(case, "_workflow_token", None)
        if not token:
            console.print("[dim]  Blast-radius skipped: no token available for re-use.[/dim]")
            return

        console.print(
            f"\n[bold]Auto blast-radius:[/bold] assessing {len(users)} HIGH-finding user(s)..."
        )

        for upn in users[:10]:  # cap at 10 to avoid excessive API calls
            try:
                br_report = run_blast_radius(
                    token=token,
                    upn=upn,
                    case_dir=case_dir,
                    on_progress=lambda msg: None,  # silent
                )
                risk = br_report.overall_risk
                risk_style = {"high": "red", "warn": "yellow"}.get(risk, "green")
                dim_count = len(br_report.dimensions)
                high_dims = [d for d in br_report.dimensions if d.status == "high"]
                console.print(
                    f"  [{risk_style}]{risk.upper():5s}[/{risk_style}]  "
                    f"{upn}  "
                    f"[dim]({dim_count} dimensions, {len(high_dims)} high-privilege)[/dim]"
                )
                case.audit.log_event("auto_blast_radius", {
                    "user": upn,
                    "overall_risk": risk,
                    "high_dimensions": len(high_dims),
                })
            except Exception as exc:
                console.print(f"  [dim]ERROR  {upn}: {exc}[/dim]")

        console.print()

    except Exception as exc:
        console.print(f"[dim]Auto blast-radius skipped: {exc}[/dim]")


def _detect_sensitivity(session: Any) -> str:
    """
    Auto-detect correlation sensitivity based on tenant user count.

    Returns "high" for small tenants (<500 users), "low" for large
    tenants (>5000), and "medium" for everything in between.
    """
    try:
        resp = session.get(
            "https://graph.microsoft.com/v1.0/users/$count",
            headers={"ConsistencyLevel": "eventual"},
            timeout=10,
        )
        if resp.status_code == 200:
            count = int(resp.text.strip())
            if count < 500:
                return "high"
            if count > 5000:
                return "low"
            return "medium"
    except Exception:
        pass
    return "medium"


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
