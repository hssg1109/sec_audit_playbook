#!/usr/bin/env python3
"""Convert a CSV of findings into SARIF.

Expected headers (case-sensitive):
- rule_id (required)
- message (required)
- uri (required)
- severity (optional; critical/high/medium/low/info)
- line (optional)
- column (optional)

Usage:
  python tools/scripts/sarif_from_csv.py --in findings.csv --out results.sarif --tool-name "asm-dast"
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path


def to_level(severity: str | None) -> str:
    if not severity:
        return "note"
    s = severity.strip().lower()
    if s in {"critical", "high"}:
        return "error"
    if s == "medium":
        return "warning"
    if s in {"low", "info", "informational"}:
        return "note"
    return "note"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="input_path", required=True)
    ap.add_argument("--out", dest="output_path", required=True)
    ap.add_argument("--tool-name", default="asm-dast")
    ap.add_argument("--delimiter", default=",")
    args = ap.parse_args()

    input_path = Path(args.input_path)
    output_path = Path(args.output_path)

    rules = {}
    results = []

    with input_path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f, delimiter=args.delimiter)
        for row in reader:
            rule_id = (row.get("rule_id") or "UNSPECIFIED").strip()
            message = (row.get("message") or "").strip()
            uri = (row.get("uri") or "").strip()
            severity = (row.get("severity") or "").strip()
            line = row.get("line")
            column = row.get("column")

            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": rule_id,
                    "shortDescription": {"text": rule_id},
                    "fullDescription": {"text": rule_id},
                    "defaultConfiguration": {"level": to_level(severity)},
                }

            location = {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri}
                }
            }
            if line:
                region = {"startLine": int(line)}
                if column:
                    region["startColumn"] = int(column)
                location["physicalLocation"]["region"] = region

            results.append(
                {
                    "ruleId": rule_id,
                    "level": to_level(severity),
                    "message": {"text": message or rule_id},
                    "locations": [location],
                    "properties": {"severity": severity.lower() if severity else "info"},
                }
            )

    sarif = {
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": args.tool_name,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(sarif, f, ensure_ascii=True, indent=2)
        f.write("\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
