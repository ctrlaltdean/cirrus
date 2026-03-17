"""
Compliance check primitives.

Every CIS control is represented as a BaseCheck subclass.
Checks return a CheckResult describing the current state of the control.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Literal


class CheckStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    MANUAL = "MANUAL"   # Cannot be verified via API — instructions provided
    ERROR = "ERROR"     # Check encountered an unexpected API error
    SKIP = "SKIP"       # Not applicable (e.g., missing license)


@dataclass
class CheckResult:
    """The outcome of running one CIS control check."""

    # Identity
    control_id: str           # e.g., "M365-1.2.1"
    title: str                # Short human-readable title
    benchmark: str            # "CIS M365" | "CIS Entra" | "CIS M365 & Entra"
    level: int                # 1 or 2
    section: str              # e.g., "1 - Identity & Access Management"

    # Result
    status: CheckStatus
    expected: str             # What a compliant configuration looks like
    actual: str               # What we found (or "N/A" for MANUAL)
    notes: str = ""           # Additional context

    # Guidance
    rationale: str = ""       # Why this control matters
    remediation: str = ""     # How to fix a FAIL
    manual_steps: str = ""    # Step-by-step manual verification (MANUAL checks)
    reference: str = ""       # CIS benchmark reference URL / section

    # Computed
    @property
    def status_icon(self) -> str:
        icons = {
            CheckStatus.PASS: "[green]✓ PASS[/green]",
            CheckStatus.FAIL: "[red]✗ FAIL[/red]",
            CheckStatus.WARN: "[yellow]⚠ WARN[/yellow]",
            CheckStatus.MANUAL: "[cyan]☐ MANUAL[/cyan]",
            CheckStatus.ERROR: "[red]! ERROR[/red]",
            CheckStatus.SKIP: "[dim]– SKIP[/dim]",
        }
        return icons.get(self.status, self.status.value)

    def to_dict(self) -> dict:
        return {
            "control_id": self.control_id,
            "title": self.title,
            "benchmark": self.benchmark,
            "level": self.level,
            "section": self.section,
            "status": self.status.value,
            "expected": self.expected,
            "actual": self.actual,
            "notes": self.notes,
            "rationale": self.rationale,
            "remediation": self.remediation,
            "manual_steps": self.manual_steps,
            "reference": self.reference,
        }


class BaseCheck:
    """
    Base class for all CIS compliance checks.

    Subclasses implement `run(ctx)` which inspects pre-fetched policy data
    and returns a CheckResult.
    """

    control_id: str = ""
    title: str = ""
    benchmark: str = ""
    level: int = 1
    section: str = ""
    rationale: str = ""
    remediation: str = ""
    manual_steps: str = ""
    reference: str = ""

    def run(self, ctx: "PolicyContext") -> CheckResult:  # noqa: F821
        raise NotImplementedError

    def _result(
        self,
        status: CheckStatus,
        expected: str,
        actual: str,
        notes: str = "",
        remediation: str | None = None,
    ) -> CheckResult:
        return CheckResult(
            control_id=self.control_id,
            title=self.title,
            benchmark=self.benchmark,
            level=self.level,
            section=self.section,
            status=status,
            expected=expected,
            actual=actual,
            notes=notes,
            rationale=self.rationale,
            remediation=remediation if remediation is not None else self.remediation,
            manual_steps=self.manual_steps,
            reference=self.reference,
        )


class ManualCheck(BaseCheck):
    """
    A check that cannot be performed via the Graph API.
    Always returns MANUAL with step-by-step verification instructions.
    """

    expected: str = ""

    def run(self, ctx: "PolicyContext") -> CheckResult:  # noqa: F821
        return self._result(
            status=CheckStatus.MANUAL,
            expected=self.expected,
            actual="Manual verification required",
            notes="This control cannot be verified via the Graph API.",
        )
