"""
Chain-of-custody audit logger.

Every action CIRRUS takes is recorded to a JSONL file inside the case folder.
Each entry is immutable (append-only) and includes a SHA-256 hash of the
previous entry to form a tamper-evident chain.

Log entries are also written to a human-readable text log for easy review.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import socket
from pathlib import Path
from typing import Any

from cirrus.utils.helpers import utc_now


class AuditLogger:
    """
    Append-only audit log for a single investigation case.

    Each entry in the JSONL file contains:
      - timestamp (UTC ISO-8601)
      - analyst (OS username)
      - hostname
      - platform
      - action (verb describing what CIRRUS did)
      - details (free-form dict)
      - record_count (optional, set when data is collected)
      - output_file (optional, path to the output artifact)
      - file_hash (optional, SHA-256 of the output artifact)
      - prev_hash (SHA-256 of the previous log entry, for chain integrity)
      - entry_hash (SHA-256 of this entry, computed at write time)
    """

    def __init__(self, case_dir: Path) -> None:
        self.case_dir = case_dir
        self.jsonl_path = case_dir / "case_audit.jsonl"
        self.text_path = case_dir / "case_audit.txt"
        self._prev_hash = self._load_last_hash()

        # Write session-open entry
        self._write(
            action="SESSION_OPEN",
            details={
                "pid": os.getpid(),
                "cwd": str(Path.cwd()),
            },
        )

    def _load_last_hash(self) -> str:
        """Return the hash of the last entry in the log, or the zero hash if empty."""
        if not self.jsonl_path.exists():
            return "0" * 64
        last_line = ""
        with open(self.jsonl_path, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    last_line = line
        if not last_line:
            return "0" * 64
        try:
            entry = json.loads(last_line)
            return entry.get("entry_hash", "0" * 64)
        except json.JSONDecodeError:
            return "0" * 64

    def _write(
        self,
        action: str,
        details: dict[str, Any] | None = None,
        record_count: int | None = None,
        output_file: Path | None = None,
        file_hash: str | None = None,
    ) -> None:
        entry: dict[str, Any] = {
            "timestamp": utc_now(),
            "analyst": os.getlogin() if hasattr(os, "getlogin") else os.environ.get("USERNAME", os.environ.get("USER", "unknown")),
            "hostname": socket.gethostname(),
            "platform": platform.platform(),
            "action": action,
            "details": details or {},
            "prev_hash": self._prev_hash,
        }
        if record_count is not None:
            entry["record_count"] = record_count
        if output_file is not None:
            entry["output_file"] = str(output_file)
        if file_hash is not None:
            entry["file_hash"] = file_hash

        # Compute entry hash (everything except entry_hash itself)
        entry_bytes = json.dumps(entry, sort_keys=True).encode()
        entry["entry_hash"] = hashlib.sha256(entry_bytes).hexdigest()
        self._prev_hash = entry["entry_hash"]

        # Append to JSONL
        with open(self.jsonl_path, "a") as f:
            f.write(json.dumps(entry) + "\n")

        # Append to human-readable text log
        record_info = f"  records={record_count}" if record_count is not None else ""
        file_info = f"  file={output_file}" if output_file else ""
        detail_str = ""
        if details:
            detail_str = "  " + "  ".join(f"{k}={v}" for k, v in details.items())
        with open(self.text_path, "a") as f:
            f.write(
                f"[{entry['timestamp']}] {entry['analyst']}@{entry['hostname']}"
                f"  ACTION={action}{record_info}{file_info}{detail_str}\n"
            )

    def log_auth(self, tenant_id: str, username: str) -> None:
        self._write(
            action="AUTH_SUCCESS",
            details={"tenant_id": tenant_id, "username": username},
        )

    def log_collection_start(self, collector: str, params: dict[str, Any]) -> None:
        self._write(
            action="COLLECTION_START",
            details={"collector": collector, **params},
        )

    def log_collection_complete(
        self,
        collector: str,
        record_count: int,
        output_file: Path,
        file_hash: str,
    ) -> None:
        self._write(
            action="COLLECTION_COMPLETE",
            details={"collector": collector},
            record_count=record_count,
            output_file=output_file,
            file_hash=file_hash,
        )

    def log_collection_error(self, collector: str, error: str) -> None:
        self._write(
            action="COLLECTION_ERROR",
            details={"collector": collector, "error": error},
        )

    def log_workflow_start(self, workflow: str, params: dict[str, Any]) -> None:
        self._write(
            action="WORKFLOW_START",
            details={"workflow": workflow, **params},
        )

    def log_workflow_complete(self, workflow: str, total_records: int) -> None:
        self._write(
            action="WORKFLOW_COMPLETE",
            details={"workflow": workflow, "total_records": total_records},
        )

    def log_event(self, action: str, details: dict[str, Any] | None = None) -> None:
        """Generic event log for anything not covered above."""
        self._write(action=action, details=details)

    def close(self) -> None:
        self._write(action="SESSION_CLOSE", details={})

    def verify_chain(self) -> tuple[bool, list[str]]:
        """
        Verify the integrity of the audit chain.
        Returns (is_valid, list_of_errors).
        """
        errors: list[str] = []
        if not self.jsonl_path.exists():
            return True, []

        prev_hash = "0" * 64
        with open(self.jsonl_path, "r") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    errors.append(f"Line {line_num}: invalid JSON")
                    continue

                stored_hash = entry.pop("entry_hash", None)
                if entry.get("prev_hash") != prev_hash:
                    errors.append(f"Line {line_num}: prev_hash mismatch")

                entry_bytes = json.dumps(entry, sort_keys=True).encode()
                computed_hash = hashlib.sha256(entry_bytes).hexdigest()
                if stored_hash != computed_hash:
                    errors.append(f"Line {line_num}: entry_hash mismatch (possible tampering)")

                prev_hash = stored_hash or computed_hash

        return len(errors) == 0, errors
