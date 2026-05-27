from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

from trailscan.engine.models import Finding


def export_json(findings: list[Finding], path: str | None = None) -> None:
    """
    Export findings as JSON.
    Writes to *path* if given, otherwise prints to stdout.
    """
    data = [f.to_dict() for f in findings]
    output = json.dumps(data, indent=2, default=str)

    if path:
        Path(path).write_text(output, encoding="utf-8")
        print(f"JSON report written to {path}")
    else:
        print(output)


def export_csv(findings: list[Finding], path: str | None = None) -> None:
    """
    Export findings as CSV.
    Writes to *path* if given, otherwise prints to stdout.
    """
    if not findings:
        return

    fieldnames = ["check_id", "control_id", "title", "status", "severity",
                  "resource_arn", "region", "evidence", "remediation"]

    rows = []
    for f in findings:
        d = f.to_dict()
        d["evidence"] = json.dumps(d.get("evidence", {}), default=str)
        rows.append(d)

    if path:
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        print(f"CSV report written to {path}")
    else:
        writer = csv.DictWriter(sys.stdout, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
