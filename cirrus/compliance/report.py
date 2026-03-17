"""
Compliance report renderer.

Produces:
  1. A Rich terminal table grouped by CIS section
  2. compliance_audit.json  — all results as structured data
  3. compliance_audit.csv   — flattened for spreadsheet analysis
  4. compliance_audit.txt   — human-readable report with remediation guidance
"""

from __future__ import annotations

import csv
import json
import textwrap
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from cirrus.compliance.base import CheckStatus
from cirrus.compliance.runner import ComplianceReport
from cirrus.utils.helpers import file_sha256, utc_now

console = Console()

STATUS_STYLE = {
    CheckStatus.PASS: ("green", "✓ PASS"),
    CheckStatus.FAIL: ("red", "✗ FAIL"),
    CheckStatus.WARN: ("yellow", "⚠ WARN"),
    CheckStatus.MANUAL: ("cyan", "☐ MANUAL"),
    CheckStatus.ERROR: ("red", "! ERROR"),
    CheckStatus.SKIP: ("dim", "– SKIP"),
}

LEVEL_STYLE = {1: "white", 2: "dim white"}


def render_terminal(report: ComplianceReport, tenant: str) -> None:
    """Print the full compliance report to the terminal, grouped by section."""

    passed, total = report.score

    # Header panel
    score_color = "green" if report.score_pct >= 70 else ("yellow" if report.score_pct >= 40 else "red")
    console.print(
        Panel.fit(
            f"[bold]CIS M365 & Entra Compliance Audit[/bold]\n"
            f"Tenant: [cyan]{tenant}[/cyan]\n"
            f"Automated score: [{score_color}]{passed}/{total} ({report.score_pct}%)[/{score_color}] verifiable controls passing\n"
            f"Manual checks: [cyan]{len(report.manual)}[/cyan] require manual verification\n"
            f"Generated: {utc_now()}",
            border_style="bright_blue",
            title="[bold cyan]CIRRUS — Compliance Report[/bold cyan]",
        )
    )

    for section, results in report.by_section().items():
        table = Table(
            title=f"\n[bold]{section}[/bold]",
            show_header=True,
            header_style="bold magenta",
            border_style="bright_blue",
            show_lines=False,
            expand=True,
        )
        table.add_column("Control", style="dim", width=14, no_wrap=True)
        table.add_column("L", justify="center", width=3)
        table.add_column("Title", min_width=35)
        table.add_column("Expected", min_width=20)
        table.add_column("Actual", min_width=20)
        table.add_column("Status", justify="center", width=12)

        for r in sorted(results, key=lambda x: x.control_id):
            color, label = STATUS_STYLE.get(r.status, ("white", r.status.value))
            status_text = Text(label, style=color)
            level_style = LEVEL_STYLE.get(r.level, "white")

            table.add_row(
                r.control_id,
                Text(str(r.level), style=level_style),
                r.title,
                _truncate(r.expected, 40),
                _truncate(r.actual, 40),
                status_text,
            )

        console.print(table)

    # Summary footer
    console.print(
        f"\n[bold]Summary:[/bold]  "
        f"[green]{len(report.passed)} PASS[/green]  "
        f"[red]{len(report.failed)} FAIL[/red]  "
        f"[yellow]{len(report.warned)} WARN[/yellow]  "
        f"[cyan]{len(report.manual)} MANUAL[/cyan]  "
        f"[red]{len(report.errors)} ERROR[/red]\n"
    )

    # Print FAIL + WARN remediation guidance
    actionable = report.failed + report.warned
    if actionable:
        console.print("[bold red]Action Required:[/bold red]")
        for r in actionable:
            color, label = STATUS_STYLE[r.status]
            console.print(f"\n  [{color}]{label}[/{color}] [bold]{r.control_id}[/bold] — {r.title}")
            console.print(f"  [dim]Actual:[/dim] {r.actual}")
            if r.remediation:
                for line in textwrap.wrap(r.remediation, width=90):
                    console.print(f"  [dim]Fix:[/dim] {line}")

    # Print MANUAL checks with instructions
    if report.manual:
        console.print("\n[bold cyan]Manual Verification Required:[/bold cyan]")
        for r in report.manual:
            console.print(f"\n  [cyan]☐[/cyan] [bold]{r.control_id}[/bold] — {r.title}")
            if r.manual_steps:
                for line in r.manual_steps.splitlines():
                    console.print(f"    {line}")


def save_report(report: ComplianceReport, case_dir: Path, tenant: str) -> tuple[Path, Path, Path]:
    """
    Write compliance_audit.json, compliance_audit.csv, and compliance_audit.txt.
    Returns (json_path, csv_path, txt_path).
    """
    records = [r.to_dict() for r in report.results]

    # --- JSON ---
    json_path = case_dir / "compliance_audit.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "tenant": tenant,
                "generated_at": utc_now(),
                "score_passed": report.score[0],
                "score_total": report.score[1],
                "score_pct": report.score_pct,
                "results": records,
            },
            f,
            indent=2,
            ensure_ascii=False,
        )

    # --- CSV ---
    csv_path = case_dir / "compliance_audit.csv"
    if records:
        fieldnames = list(records[0].keys())
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(records)
    else:
        csv_path.write_text("")

    # --- Human-readable TXT ---
    txt_path = case_dir / "compliance_audit.txt"
    _write_text_report(report, txt_path, tenant)

    return json_path, csv_path, txt_path


def _write_text_report(report: ComplianceReport, path: Path, tenant: str) -> None:
    passed, total = report.score
    lines = [
        "=" * 80,
        "CIRRUS — CIS M365 & Entra Compliance Audit Report",
        f"Tenant:    {tenant}",
        f"Generated: {utc_now()}",
        f"Score:     {passed}/{total} ({report.score_pct}%) automated controls passing",
        f"Manual:    {len(report.manual)} checks require manual verification",
        "=" * 80,
        "",
    ]

    for section, results in report.by_section().items():
        lines.append(f"\n{'─' * 80}")
        lines.append(f"  {section}")
        lines.append(f"{'─' * 80}")
        lines.append(f"  {'Control':<14} {'L':<3} {'Status':<10} {'Title'}")
        lines.append(f"  {'-'*14} {'-'*3} {'-'*10} {'-'*40}")

        for r in sorted(results, key=lambda x: x.control_id):
            _, label = STATUS_STYLE.get(r.status, ("", r.status.value))
            lines.append(f"  {r.control_id:<14} {r.level:<3} {label:<10} {r.title}")

    lines.extend(["", "=" * 80, "FAILED / WARN — Remediation Guidance", "=" * 80, ""])
    for r in report.failed + report.warned:
        _, label = STATUS_STYLE[r.status]
        lines.append(f"\n[{label}] {r.control_id} — {r.title}")
        lines.append(f"  Expected: {r.expected}")
        lines.append(f"  Actual:   {r.actual}")
        if r.notes:
            lines.append(f"  Notes:    {r.notes}")
        if r.remediation:
            lines.append(f"  Fix:      {r.remediation}")
        if r.reference:
            lines.append(f"  Ref:      {r.reference}")

    lines.extend(["", "=" * 80, "MANUAL — Verification Required", "=" * 80, ""])
    for r in report.manual:
        lines.append(f"\n[MANUAL] {r.control_id} — {r.title}")
        lines.append(f"  Expected: {r.expected}")
        if r.manual_steps:
            lines.append("  Steps:")
            for step_line in r.manual_steps.splitlines():
                lines.append(f"    {step_line}")

    path.write_text("\n".join(lines), encoding="utf-8")


def _truncate(text: str, max_len: int) -> str:
    return text if len(text) <= max_len else text[: max_len - 3] + "..."
