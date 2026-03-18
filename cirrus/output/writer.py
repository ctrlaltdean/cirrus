"""
Output writers: JSON, CSV, and NDJSON.

Every collector returns a list of dicts. The writer saves them to:
  - <name>.json    (pretty-printed, UTF-8)
  - <name>.csv     (flattened, with a header row)
  - <name>.ndjson  (one JSON object per line — SOF-ELK / JSON Lines format)

All files are written atomically and their SHA-256 hash is recorded
in the audit log for chain-of-custody.

SOF-ELK ingestion paths (copy .ndjson files to the SOF-ELK VM):
  - Unified Audit Log  →  /logstash/microsoft365/
  - Sign-in / Entra    →  /logstash/azure/
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from cirrus.utils.helpers import file_sha256


def flatten(obj: Any, prefix: str = "", sep: str = ".") -> dict[str, Any]:
    """
    Recursively flatten a nested dict/list into a single-level dict.

    Nested keys are joined with `sep`. Lists are serialized as JSON strings
    to keep CSV rows simple.

    Examples:
        {"a": {"b": 1}}          → {"a.b": 1}
        {"a": [1, 2]}            → {"a": "[1, 2]"}
    """
    items: dict[str, Any] = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            new_key = f"{prefix}{sep}{k}" if prefix else k
            if isinstance(v, dict):
                items.update(flatten(v, new_key, sep))
            elif isinstance(v, list):
                items[new_key] = json.dumps(v, ensure_ascii=False)
            else:
                items[new_key] = v
    else:
        items[prefix] = obj
    return items


def write_json(records: list[dict], path: Path) -> str:
    """Write records as a pretty-printed JSON array. Returns SHA-256."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2, ensure_ascii=False, default=str)
    return file_sha256(path)


def write_ndjson(records: list[dict], path: Path) -> str:
    """
    Write records as NDJSON (JSON Lines) — one JSON object per line.
    This is the format expected by SOF-ELK's Logstash pipelines.
    Returns SHA-256.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
    return file_sha256(path)


def write_csv(records: list[dict], path: Path) -> str:
    """
    Write records as a CSV file with a header row.
    Nested fields are flattened. Returns SHA-256.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    if not records:
        path.write_text("", encoding="utf-8")
        return file_sha256(path)

    flat_records = [flatten(r) for r in records]

    # Union of all keys across all records to handle sparse fields
    all_keys: list[str] = []
    seen: set[str] = set()
    for rec in flat_records:
        for k in rec:
            if k not in seen:
                all_keys.append(k)
                seen.add(k)

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=all_keys, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(flat_records)

    return file_sha256(path)


def save_collection(
    records: list[dict],
    case_dir: Path,
    base_name: str,
    ndjson_records: list[dict] | None = None,
) -> tuple[Path, Path, Path, str, str, str]:
    """
    Save a collection to JSON, CSV, and NDJSON.

    Args:
        records:       Raw records written to .json and .csv.
        case_dir:      Case output directory.
        base_name:     File stem (e.g. "unified_audit_log").
        ndjson_records: SOF-ELK normalized records for .ndjson output.
                        If None, the raw records are used as-is.

    Returns (json_path, csv_path, ndjson_path, json_sha256, csv_sha256, ndjson_sha256).
    """
    json_path = case_dir / f"{base_name}.json"
    csv_path = case_dir / f"{base_name}.csv"
    ndjson_path = case_dir / f"{base_name}.ndjson"
    json_hash = write_json(records, json_path)
    csv_hash = write_csv(records, csv_path)
    ndjson_hash = write_ndjson(
        ndjson_records if ndjson_records is not None else records, ndjson_path
    )
    return json_path, csv_path, ndjson_path, json_hash, csv_hash, ndjson_hash
