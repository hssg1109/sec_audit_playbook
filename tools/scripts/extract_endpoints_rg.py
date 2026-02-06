#!/usr/bin/env python3
"""Extract Spring/Kotlin endpoints via lightweight regex (rg-style parsing).

Outputs Task 2-1 JSON with findings list.
"""
from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path

ANNOTATION_METHODS = {
    "GetMapping": "GET",
    "PostMapping": "POST",
    "PutMapping": "PUT",
    "DeleteMapping": "DELETE",
    "PatchMapping": "PATCH",
}

REQ_METHOD_RE = re.compile(r"RequestMethod\.(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)")
QUOTED_RE = re.compile(r"\"([^\"]+)\"")

REQ_PARAM_RE = re.compile(r"@RequestParam\(([^)]*)\)")
PATH_VAR_RE = re.compile(r"@PathVariable\(([^)]*)\)")


def normalize_path(base: str, sub: str) -> str:
    if not base:
        return sub or "/"
    if not sub:
        return base
    if base.endswith("/") and sub.startswith("/"):
        return base[:-1] + sub
    if not base.endswith("/") and not sub.startswith("/"):
        return base + "/" + sub
    return base + sub


def extract_paths(text: str) -> list[str]:
    # Collect all quoted strings in annotation args
    paths = QUOTED_RE.findall(text)
    return [p for p in paths if p.startswith("/")] or ([paths[0]] if paths else [])


def extract_params(lines: list[str], start: int, max_lines: int = 8) -> list[str]:
    params: list[str] = []
    for i in range(start, min(len(lines), start + max_lines)):
        line = lines[i]
        for m in REQ_PARAM_RE.findall(line):
            names = QUOTED_RE.findall(m)
            if names:
                params.extend(names)
        for m in PATH_VAR_RE.findall(line):
            names = QUOTED_RE.findall(m)
            if names:
                params.extend(names)
    return sorted(set(params))


def scan_file(path: Path) -> list[dict]:
    findings: list[dict] = []
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()

    class_base = ""
    pending_base = ""

    for idx, line in enumerate(lines):
        stripped = line.strip()

        # class-level base mapping
        if stripped.startswith("@RequestMapping"):
            paths = extract_paths(stripped)
            if paths:
                pending_base = paths[0]

        if pending_base and ("class " in stripped or "interface " in stripped):
            class_base = pending_base
            pending_base = ""

        # method-level mappings
        for anno, method in ANNOTATION_METHODS.items():
            if stripped.startswith(f"@{anno}"):
                paths = extract_paths(stripped) or [""]
                params = extract_params(lines, idx + 1)
                for p in paths:
                    api = normalize_path(class_base, p)
                    findings.append({
                        "api": api,
                        "method": method,
                        "file": f"{path}:{idx + 1}",
                        "auth_required": "unknown",
                        "parameters": params,
                    })

        if stripped.startswith("@RequestMapping") and "method" in stripped:
            paths = extract_paths(stripped) or [""]
            methods = REQ_METHOD_RE.findall(stripped) or ["UNKNOWN"]
            params = extract_params(lines, idx + 1)
            for m in methods:
                for p in paths:
                    api = normalize_path(class_base, p)
                    findings.append({
                        "api": api,
                        "method": m,
                        "file": f"{path}:{idx + 1}",
                        "auth_required": "unknown",
                        "parameters": params,
                    })

    return findings


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True, help="Source repo root")
    ap.add_argument("--out", required=True, help="Output JSON path")
    ap.add_argument(
        "--source-repo-url",
        required=True,
        help="진단 대상 레포 URL",
    )
    ap.add_argument(
        "--source-repo-path",
        required=True,
        help="로컬 레포 경로",
    )
    ap.add_argument(
        "--source-modules",
        required=True,
        help="진단 대상 모듈/서브프로젝트 (comma-separated)",
    )
    args = ap.parse_args()

    root = Path(args.repo)
    files = list(root.rglob("*.kt")) + list(root.rglob("*.java"))

    findings: list[dict] = []
    for f in files:
        # skip build output
        if "//target/" in f.as_posix() or "/build/" in f.as_posix():
            continue
        findings.extend(scan_file(f))

    modules = [m.strip() for m in args.source_modules.split(",") if m.strip()]
    if not modules:
        raise SystemExit("Error: --source-modules 값이 비어 있습니다.")

    out = {
        "task_id": "2-1",
        "status": "completed",
        "findings": findings,
        "executed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "metadata": {
            "source_repo_url": args.source_repo_url,
            "source_repo_path": args.source_repo_path,
            "source_modules": modules,
            "tool": "extract_endpoints_rg",
            "files_scanned": len(files),
            "notes": "regex-based extraction; auth_required defaults to unknown",
        },
    }

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
