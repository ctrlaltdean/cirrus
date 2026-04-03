"""
Excel workbook generator.

Reads all CSV files from the triage/ and collection/ subdirectories of a
case folder and combines them into a single analysis.xlsx workbook at the
case root.  One sheet per CSV, with frozen headers, bold styling, and
auto-sized columns.

openpyxl is a core dependency (listed in pyproject.toml).  If it is somehow
unavailable the function returns None and the caller should ignore the result
rather than raising.
"""

from __future__ import annotations

import csv
from pathlib import Path


# Sheet name → colour (hex, no #) for the header fill.
# Triage sheets get a teal header; collection sheets get navy.
_TRIAGE_COLOUR     = "0D7377"   # teal
_COLLECTION_COLOUR = "1F4E79"   # navy
_HEADER_TEXT       = "FFFFFF"   # white text on both


def _sheet_name(stem: str, existing: set[str]) -> str:
    """
    Produce a unique Excel sheet name (≤31 chars) from a file stem.
    Converts underscores to spaces and title-cases for readability.
    """
    name = stem.replace("_", " ").title()[:31]
    if name not in existing:
        return name
    # Deduplicate by appending a counter
    for i in range(2, 100):
        candidate = f"{name[:28]} {i}"
        if candidate not in existing:
            return candidate
    return name  # give up — openpyxl will raise if truly duplicate


def generate_workbook(case_dir: Path) -> Path | None:
    """
    Generate ``analysis.xlsx`` in *case_dir* from all CSV files in the
    ``triage/`` and ``collection/`` subdirectories.

    Sheet order: triage sheets first, then collection sheets, each group
    sorted alphabetically.

    Returns the path to the written workbook, or ``None`` if openpyxl is
    unavailable or there are no CSV files to include.
    """
    try:
        import openpyxl
        from openpyxl.styles import Alignment, Font, PatternFill
        from openpyxl.utils import get_column_letter
    except ImportError:
        return None

    # Gather (sheet_label, csv_path, header_colour) in display order
    entries: list[tuple[str, Path, str]] = []
    seen_names: set[str] = set()

    for subdir, colour in (("triage", _TRIAGE_COLOUR), ("collection", _COLLECTION_COLOUR)):
        d = case_dir / subdir
        if not d.exists():
            continue
        for csv_path in sorted(d.glob("*.csv")):
            name = _sheet_name(csv_path.stem, seen_names)
            seen_names.add(name)
            entries.append((name, csv_path, colour))

    if not entries:
        return None

    wb = openpyxl.Workbook()
    wb.remove(wb.active)  # discard the default empty sheet

    for sheet_name, csv_path, hdr_colour in entries:
        try:
            with open(csv_path, encoding="utf-8", newline="") as fh:
                rows = list(csv.reader(fh))
        except Exception:
            continue

        ws = wb.create_sheet(title=sheet_name)

        if not rows:
            # Check ran but returned no records — show a placeholder so the
            # analyst knows the check executed and was clean.
            header_font = Font(bold=True, color=_HEADER_TEXT)
            header_fill = PatternFill("solid", fgColor=hdr_colour)
            header_align = Alignment(horizontal="center", vertical="center", wrap_text=False)
            cell = ws.cell(row=1, column=1, value="(no records)")
            cell.font = header_font
            cell.fill = header_fill
            cell.alignment = header_align
            ws.column_dimensions["A"].width = 20
            ws.row_dimensions[1].height = 18
            continue
        ws.freeze_panes = "A2"

        header_font = Font(bold=True, color=_HEADER_TEXT)
        header_fill = PatternFill("solid", fgColor=hdr_colour)
        header_align = Alignment(horizontal="center", vertical="center", wrap_text=False)

        col_widths: list[int] = [0] * len(rows[0])

        for row_idx, row in enumerate(rows, start=1):
            for col_idx, value in enumerate(row, start=1):
                cell = ws.cell(row=row_idx, column=col_idx, value=value)
                val_len = len(str(value))
                if col_idx <= len(col_widths):
                    col_widths[col_idx - 1] = max(col_widths[col_idx - 1], val_len)
                if row_idx == 1:
                    cell.font = header_font
                    cell.fill = header_fill
                    cell.alignment = header_align

        # Apply column widths (capped at 60, minimum 8)
        for col_idx, width in enumerate(col_widths, start=1):
            ws.column_dimensions[get_column_letter(col_idx)].width = max(min(width + 2, 60), 8)

        # Set header row height
        ws.row_dimensions[1].height = 18

    if not wb.sheetnames:
        return None

    output_path = case_dir / "analysis.xlsx"
    wb.save(output_path)
    return output_path
