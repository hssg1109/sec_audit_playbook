#!/usr/bin/env python3
"""Generate a cross-skill reporting summary JSON index.

Usage:
  python tools/scripts/generate_reporting_summary.py --config path/to/summary_config.json --out state/reporting_summary.json
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path


SEVERITY_KEYS = ["critical", "high", "medium", "low", "info"]


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def now_utc() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def normalize_severity(value: str | None) -> str:
    if not value:
        return "info"
    v = value.strip().lower()
    if v in SEVERITY_KEYS:
        return v
    if v in {"informational"}:
        return "info"
    if v in {"moderate"}:
        return "medium"
    if v in {"warn", "warning"}:
        return "medium"
    return "info"


def empty_counts() -> dict:
    return {k: 0 for k in SEVERITY_KEYS}


def add_counts(a: dict, b: dict) -> dict:
    out = empty_counts()
    for k in SEVERITY_KEYS:
        out[k] = int(a.get(k, 0)) + int(b.get(k, 0))
    return out


def count_from_findings(findings: list[dict]) -> dict:
    counts = empty_counts()
    for item in findings:
        sev = normalize_severity(item.get("severity") or item.get("level"))
        counts[sev] += 1
    return counts


def count_from_sarif(sarif: dict, level_map: dict | None) -> dict:
    counts = empty_counts()
    level_map = level_map or {
        "error": "high",
        "warning": "medium",
        "note": "low",
        "none": "info",
    }
    runs = sarif.get("runs", [])
    for run in runs:
        for result in run.get("results", []) or []:
            sev = None
            props = result.get("properties") or {}
            sev = props.get("severity") or props.get("risk")
            if not sev:
                level = result.get("level")
                sev = level_map.get(str(level).lower(), "info") if level else "info"
            sev = normalize_severity(sev)
            counts[sev] += 1
    return counts


def ensure_counts(counts: dict | None) -> dict:
    if not counts:
        return empty_counts()
    out = empty_counts()
    for k in SEVERITY_KEYS:
        out[k] = int(counts.get(k, 0))
    return out


def load_analysis_counts(analysis: dict) -> tuple[int, dict]:
    fmt = analysis.get("format")
    report_path = analysis.get("report_path")
    if analysis.get("severity_counts"):
        counts = ensure_counts(analysis["severity_counts"])
        return sum(counts.values()), counts

    if not report_path:
        return 0, empty_counts()

    path = Path(report_path)
    if not path.exists():
        print(f"[warn] report not found: {report_path}", file=sys.stderr)
        return 0, empty_counts()

    if fmt == "json":
        data = load_json(path)
        if isinstance(data, dict) and "summary" in data:
            summary = data.get("summary") or {}
            counts = ensure_counts(summary)
            return sum(counts.values()), counts
        if isinstance(data, dict) and "findings" in data:
            counts = count_from_findings(data.get("findings") or [])
            return sum(counts.values()), counts
        return 0, empty_counts()

    if fmt == "sarif":
        data = load_json(path)
        counts = count_from_sarif(data, analysis.get("level_map"))
        return sum(counts.values()), counts

    if fmt == "markdown":
        print(f"[warn] markdown report requires severity_counts in config: {report_path}", file=sys.stderr)
        return 0, empty_counts()

    print(f"[warn] unsupported format: {fmt}", file=sys.stderr)
    return 0, empty_counts()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    cfg = load_json(Path(args.config))

    summary_counts = empty_counts()
    analyses = []

    for analysis in cfg.get("analyses", []):
        count, counts = load_analysis_counts(analysis)
        summary_counts = add_counts(summary_counts, counts)
        entry = dict(analysis)
        entry["findings_count"] = count
        entry["severity_counts"] = counts
        analyses.append(entry)

    output = {
        "report_id": cfg.get("report_id", "reporting-summary"),
        "generated_at": cfg.get("generated_at") or now_utc(),
        "owner": cfg.get("owner", ""),
        "severity_scheme": cfg.get("severity_scheme", "grade-5-to-1"),
        "summary": {
            "total_findings": sum(summary_counts.values()),
            **summary_counts,
        },
        "analyses": analyses,
    }

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=True, indent=2)
        f.write("\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
