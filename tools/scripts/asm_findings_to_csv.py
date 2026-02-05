#!/usr/bin/env python3
"""Extract findings-like data from ASM run outputs into a CSV.

Currently supports:
- httpx live results (heuristic) from a text file to CSV targets

Usage:
  python tools/scripts/asm_findings_to_csv.py --httpx data/outputs/httpx_full.txt --out data/outputs/findings.csv
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path


def parse_httpx_line(line: str) -> tuple[str, str] | None:
    line = line.strip()
    if not line:
        return None
    # httpx output often starts with URL
    parts = line.split()
    if not parts:
        return None
    url = parts[0]
    message = "httpx live target"
    return url, message


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--httpx", dest="httpx_path")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    rows = []
    if args.httpx_path:
        httpx_path = Path(args.httpx_path)
        if httpx_path.exists():
            for line in httpx_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                parsed = parse_httpx_line(line)
                if parsed:
                    url, message = parsed
                    rows.append({
                        "rule_id": "HTTPX-LIVE",
                        "message": message,
                        "uri": url,
                        "severity": "info",
                        "line": "",
                        "column": "",
                    })

    with out_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["rule_id", "message", "uri", "severity", "line", "column"])
        writer.writeheader()
        writer.writerows(rows)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
