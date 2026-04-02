"""
Investigation case management.

A "case" is a timestamped folder under the output directory that contains
all artifacts from one investigation run.

Folder structure:
    investigations/
    └── CONTOSO_20260317_143022/
        ├── case_audit.jsonl            ← chain-of-custody log (JSONL)
        ├── case_audit.txt              ← human-readable audit log
        ├── ioc_correlation.json        ← cross-collector findings
        ├── investigation_report.html   ← HTML report
        ├── analysis.xlsx               ← master Excel workbook
        ├── triage/                     ← quick-triage check outputs
        │   ├── sign_ins.{json,csv,ndjson}
        │   └── ...
        └── collection/                 ← workflow collector outputs
            ├── signin_logs.{json,csv,ndjson}
            └── ...
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from cirrus.audit.logger import AuditLogger
from cirrus.utils.helpers import slugify


class Case:
    """Represents a single investigation case."""

    def __init__(self, case_dir: Path) -> None:
        self.case_dir = case_dir
        self.case_dir.mkdir(parents=True, exist_ok=True)
        self.audit = AuditLogger(case_dir)

    @classmethod
    def create(
        cls,
        tenant: str,
        output_dir: Path,
        case_name: str | None = None,
    ) -> "Case":
        """
        Create a new case folder.

        Folder is named: {tenant_slug}_{YYYYMMDD_HHMMSS}
        or {case_name}_{YYYYMMDD_HHMMSS} if case_name is provided.
        """
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        prefix = slugify(case_name) if case_name else slugify(tenant.split(".")[0].upper())
        folder_name = f"{prefix}_{ts}"
        case_dir = output_dir / folder_name
        return cls(case_dir)

    @classmethod
    def open_existing(cls, case_dir: Path) -> "Case":
        """Open an existing case folder to append to it."""
        if not case_dir.exists():
            raise FileNotFoundError(f"Case directory does not exist: {case_dir}")
        return cls(case_dir)

    @property
    def triage_dir(self) -> Path:
        """Subfolder for quick-triage check outputs. Created on first access."""
        p = self.case_dir / "triage"
        p.mkdir(exist_ok=True)
        return p

    @property
    def collection_dir(self) -> Path:
        """Subfolder for workflow collector outputs. Created on first access."""
        p = self.case_dir / "collection"
        p.mkdir(exist_ok=True)
        return p

    def artifact_path(self, name: str) -> Path:
        """Return the full path for a named artifact file inside the case folder."""
        return self.case_dir / name

    def close(self) -> None:
        """Finalize the case (writes SESSION_CLOSE to audit log)."""
        self.audit.close()

    def verify_integrity(self) -> tuple[bool, list[str]]:
        """Verify the chain-of-custody audit log integrity."""
        return self.audit.verify_chain()

    def __repr__(self) -> str:
        return f"Case(path={self.case_dir})"
