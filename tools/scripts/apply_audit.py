#!/usr/bin/env python3
"""
apply_audit.py — LLM 수동분석 패치를 마스터 스캔 JSON에 적용

두 가지 패치 입력 형식을 자동 감지합니다:

  [형식 A] 패치 배열 (신규 포맷 — manual_review_prompt.md 출력):
      [ { "finding_id": "DATA-SEC-001", "result": "취약", ... },
        { "api_path": "POST /api/v1/search", "result": "양호", ... } ]

  [형식 B] 보완 파일 (기존 포맷 — task22_llm.json 등):
      { "task_id": "2-5", "findings": [...], "xss_endpoint_review": {...}, ... }

패치 대상별 동작:
  finding_id  → master.findings 배열에서 ID 매칭 후 필드 병합 (없으면 append)
  api_path    → master.endpoint_diagnoses 배열에서 경로 매칭 후 진단 필드 업데이트
  --replace-categories 지정 시 → 해당 카테고리 원본 findings 전체 삭제 후 패치로 교체

사용 예:
    # Task 2-5: 병합 결과로 원본 교체 (222건 → 10건)
    python3 tools/scripts/apply_audit.py \\
        state/0312_ocb_sugar_task25.json \\
        state/0312_ocb_sugar_task25_llm.json \\
        --replace-categories HARDCODED_SECRET SENSITIVE_LOGGING \\
        --backup

    # Task 2-3: LLM findings를 xss.json에 추가
    python3 tools/scripts/apply_audit.py \\
        state/0312_ocb_sugar_xss.json \\
        state/0312_ocb_sugar_task23_llm.json

    # 패치 배열 (신규 포맷) 적용
    python3 tools/scripts/apply_audit.py \\
        state/0312_ocb_sugar_xss.json patch_array.json

    # dry-run (변경 내용 미리보기, 파일 미수정)
    python3 tools/scripts/apply_audit.py \\
        state/task25.json state/task25_llm.json --dry-run

    # 원본 보존 후 새 파일로 출력
    python3 tools/scripts/apply_audit.py \\
        state/task25.json state/task25_llm.json \\
        --output state/task25_patched.json
"""

import argparse
import copy
import json
import shutil
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path


# ---------------------------------------------------------------------------
# 상수
# ---------------------------------------------------------------------------

# endpoint_diagnoses에서 패치 허용 필드 (자동스캔 원본 구조 필드는 보존)
ENDPOINT_PATCHABLE_FIELDS = {
    "result", "severity", "needs_review",
    "diagnosis_type", "diagnosis_detail", "diagnosis_method",
    "manual_review_note",
}

# findings 병합 시 LLM 전용 필드 (마스터에 없던 필드는 추가)
FINDING_MERGE_FIELDS = {
    "result", "severity", "needs_review",
    "diagnosis_type", "diagnosis_detail", "diagnosis_method",
    "manual_review_note", "title", "description", "recommendation",
    "category", "cwe_id", "owasp_category",
    "affected_endpoint", "evidence",
}

HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}


# ---------------------------------------------------------------------------
# 유틸리티
# ---------------------------------------------------------------------------

def get_finding_id(obj: dict) -> str | None:
    """finding 객체에서 ID 추출: finding_id 우선, 없으면 id"""
    return obj.get("finding_id") or obj.get("id") or None


def normalize_finding(patch_item: dict) -> dict:
    """LLM finding의 id → finding_id로 정규화 (마스터 스키마 통일)"""
    norm = dict(patch_item)
    if "id" in norm and "finding_id" not in norm:
        norm["finding_id"] = norm.pop("id")
    return norm


def parse_api_path(api_path_str: str) -> tuple[str | None, str]:
    """
    'GET /api/v1/search' → (method, path)
    '/api/v1/search'     → (None, path)
    """
    parts = api_path_str.strip().split(None, 1)
    if len(parts) == 2 and parts[0].upper() in HTTP_METHODS:
        return parts[0].upper(), parts[1].strip()
    return None, api_path_str.strip()


def normalize_path(path: str) -> str:
    """선행 슬래시 정규화"""
    path = path.strip()
    return path if path.startswith("/") else "/" + path


def endpoint_matches(ep: dict, api_path_str: str) -> bool:
    """
    endpoint_diagnoses 항목이 api_path 문자열과 일치하는지 확인.
    HTTP 메서드가 생략된 경우 경로만 비교.
    """
    method, path = parse_api_path(api_path_str)
    ep_method = (ep.get("http_method") or "").upper()
    ep_path = normalize_path(ep.get("request_mapping") or "")
    target_path = normalize_path(path)

    path_match = (ep_path == target_path)
    method_match = (method is None) or (ep_method == method)
    return path_match and method_match


def detect_format(patch_data) -> str:
    """패치 데이터 형식 자동 감지: 'array' 또는 'supplemental'"""
    if isinstance(patch_data, list):
        return "array"
    if isinstance(patch_data, dict):
        return "supplemental"
    raise ValueError(f"지원하지 않는 패치 데이터 타입: {type(patch_data)}")


# ---------------------------------------------------------------------------
# findings 패치 엔진
# ---------------------------------------------------------------------------

def apply_findings_patches(
    master_findings: list,
    patch_findings: list,
    replace_categories: list | None,
    stats: dict,
) -> list:
    """
    master_findings 배열에 patch_findings를 적용합니다.

    replace_categories 지정 시:
      - 해당 카테고리에 속하는 원본 findings 전체 삭제
      - 패치 findings로 교체 (ID 상관없이 insert)

    그 외:
      - finding_id 기준 upsert:
          - 일치하는 ID가 있으면 FINDING_MERGE_FIELDS 병합
          - 없으면 append
    """
    patch_findings_norm = [normalize_finding(pf) for pf in patch_findings]

    # ── 1. replace_categories 처리 ──────────────────────────────────────────
    if replace_categories:
        cats_upper = {c.upper() for c in replace_categories}

        # 패치에 실제로 해당 카테고리 데이터가 있는지 확인
        patch_cats = {
            (pf.get("category") or "").upper()
            for pf in patch_findings_norm
        }
        effective_replace = cats_upper & patch_cats

        if effective_replace:
            # 카테고리별 제거 건수 계산 (표기용)
            per_cat_count = Counter(
                (fi.get("category") or "").upper()
                for fi in master_findings
                if (fi.get("category") or "").upper() in effective_replace
            )
            master_findings = [
                fi for fi in master_findings
                if (fi.get("category") or "").upper() not in effective_replace
            ]
            for cat in effective_replace:
                stats["replaced_categories"].append((cat, per_cat_count.get(cat, 0)))

    # ── 2. ID 인덱스 맵 생성 ────────────────────────────────────────────────
    id_to_idx: dict[str, int] = {}
    for i, fi in enumerate(master_findings):
        fid = get_finding_id(fi)
        if fid:
            id_to_idx[fid] = i

    # ── 3. 패치 적용 (upsert) ───────────────────────────────────────────────
    for patch_norm in patch_findings_norm:
        fid = get_finding_id(patch_norm)

        if fid is None:
            stats["skipped"] += 1
            continue

        if fid in id_to_idx:
            # 기존 finding 업데이트 — FINDING_MERGE_FIELDS만 덮어씀
            idx = id_to_idx[fid]
            for field in FINDING_MERGE_FIELDS:
                if field in patch_norm:
                    master_findings[idx][field] = patch_norm[field]
            # LLM 메타 필드 추가
            if "manual_review_note" in patch_norm:
                master_findings[idx]["manual_review_note"] = patch_norm["manual_review_note"]
            master_findings[idx]["_patched"] = True
            stats["updated"] += 1
        else:
            # 신규 finding 추가
            patch_norm["_patched"] = True
            master_findings.append(patch_norm)
            id_to_idx[fid] = len(master_findings) - 1
            stats["added"] += 1

    return master_findings


# ---------------------------------------------------------------------------
# endpoint_diagnoses 패치 엔진
# ---------------------------------------------------------------------------

def apply_endpoint_patches(
    endpoint_diagnoses: list,
    endpoint_patches: list,
    stats: dict,
) -> list:
    """
    endpoint_diagnoses 배열에 api_path 기반 패치를 적용합니다.
    매칭 전략: 경로 완전 일치 + (HTTP 메서드 일치 또는 메서드 생략)
    """
    for patch_item in endpoint_patches:
        api_path = patch_item.get("api_path", "")
        if not api_path:
            stats["skipped"] += 1
            continue

        matched = False
        for ep in endpoint_diagnoses:
            if endpoint_matches(ep, api_path):
                # 패치 허용 필드만 업데이트
                for field in ENDPOINT_PATCHABLE_FIELDS:
                    if field in patch_item:
                        ep[field] = patch_item[field]
                ep["_patched"] = True
                ep["_patched_at"] = datetime.now().isoformat()
                stats["ep_updated"] += 1
                matched = True
                # 동일 경로에 복수 매칭 가능(GET/POST 분리) → break 하지 않음
                # 단, 메서드 명시 시 하나만 매칭

        if not matched:
            stats["ep_not_found"].append(api_path)

    return endpoint_diagnoses


# ---------------------------------------------------------------------------
# 요약 통계 재계산
# ---------------------------------------------------------------------------

def recalculate_summary(master: dict) -> dict:
    """
    findings 배열 변경 후 master.summary 블록을 재계산합니다.
    task_id에 따라 적합한 통계 필드를 업데이트합니다.
    """
    findings = master.get("findings", [])
    if not findings:
        return master

    result_counts = Counter(fi.get("result", "") for fi in findings)
    severity_counts = Counter(fi.get("severity", "") for fi in findings)
    category_counts = Counter(fi.get("category", "") for fi in findings)

    summary = master.get("summary", {})
    summary["findings_total"] = len(findings)
    summary["findings_by_result"] = dict(result_counts)
    summary["findings_by_severity"] = dict(severity_counts)
    summary["findings_by_category"] = dict(category_counts)
    summary["_recalculated_at"] = datetime.now().isoformat()
    master["summary"] = summary

    return master


# ---------------------------------------------------------------------------
# 보완 파일 형식 적용 (기존 *_llm.json)
# ---------------------------------------------------------------------------

def apply_supplemental(
    master: dict,
    patch_data: dict,
    replace_categories: list | None,
    stats: dict,
) -> dict:
    """
    task22_llm.json / task23_llm.json / task25_llm.json 형식의 보완 파일을
    마스터 JSON에 적용합니다.

    처리 대상:
      - findings 배열: upsert (replace_categories 지원)
      - xss_filter_assessment, data_protection_assessment: master에 병합
      - sqli_endpoint_review, xss_endpoint_review: master에 _llm_review로 저장
    """
    # ── findings 패치 ───────────────────────────────────────────────────────
    patch_findings = patch_data.get("findings", [])
    if patch_findings:
        master_findings = master.get("findings", [])
        master["findings"] = apply_findings_patches(
            master_findings, patch_findings, replace_categories, stats
        )

    # ── endpoint_review 메타 보존 ───────────────────────────────────────────
    for review_key in ("sqli_endpoint_review", "xss_endpoint_review"):
        if review_key in patch_data:
            master[f"_llm_{review_key}"] = patch_data[review_key]

    # ── assessment 블록 병합 ────────────────────────────────────────────────
    for assess_key in ("xss_filter_assessment", "data_protection_assessment"):
        if assess_key in patch_data:
            master[assess_key] = patch_data[assess_key]

    # ── 패치 출처 기록 ──────────────────────────────────────────────────────
    master["_patched_at"] = datetime.now().isoformat()
    master["_patch_format"] = "supplemental"

    return master


# ---------------------------------------------------------------------------
# 배열 형식 적용 (신규 패치 배열)
# ---------------------------------------------------------------------------

def apply_array_patch(
    master: dict,
    patch_data: list,
    replace_categories: list | None,
    stats: dict,
) -> dict:
    """
    패치 배열 형식 [ { "finding_id": ... }, { "api_path": ... } ]을
    마스터 JSON에 적용합니다.
    """
    finding_patches = [p for p in patch_data if "finding_id" in p or "id" in p]
    endpoint_patches = [p for p in patch_data if "api_path" in p]
    other = [p for p in patch_data if "finding_id" not in p and "id" not in p and "api_path" not in p]

    stats["skipped"] += len(other)

    # ── findings 패치 ───────────────────────────────────────────────────────
    if finding_patches:
        master_findings = master.get("findings", [])
        master["findings"] = apply_findings_patches(
            master_findings, finding_patches, replace_categories, stats
        )

    # ── endpoint_diagnoses 패치 ─────────────────────────────────────────────
    if endpoint_patches:
        eps = master.get("endpoint_diagnoses", [])
        master["endpoint_diagnoses"] = apply_endpoint_patches(
            eps, endpoint_patches, stats
        )

    master["_patched_at"] = datetime.now().isoformat()
    master["_patch_format"] = "array"

    return master


# ---------------------------------------------------------------------------
# 통계 출력
# ---------------------------------------------------------------------------

def print_stats(stats: dict, master_path: Path, patch_path: Path, dry_run: bool):
    tag = "[DRY-RUN] " if dry_run else ""
    print(f"\n{'='*62}")
    print(f"{tag}apply_audit.py 완료")
    print(f"  마스터  : {master_path}")
    print(f"  패치    : {patch_path}")
    print(f"  형식    : {stats['format']}")
    print(f"{'─'*62}")

    if stats["replaced_categories"]:
        for cat, cnt in stats["replaced_categories"]:
            print(f"  [교체] {cat} — 원본 {cnt}건 삭제 후 패치로 대체")
    if stats["updated"]:
        print(f"  [업데이트] finding {stats['updated']}건")
    if stats["added"]:
        print(f"  [추가]     finding {stats['added']}건 (신규)")
    if stats["ep_updated"]:
        print(f"  [업데이트] endpoint {stats['ep_updated']}건")
    if stats["ep_not_found"]:
        print(f"  [미매칭]   endpoint {len(stats['ep_not_found'])}건")
        for ep in stats["ep_not_found"][:5]:
            print(f"             - {ep}")
        if len(stats["ep_not_found"]) > 5:
            print(f"             ... 외 {len(stats['ep_not_found']) - 5}건")
    if stats["skipped"]:
        print(f"  [건너뜀]   {stats['skipped']}건 (식별자 없음)")

    print(f"{'='*62}\n")


def print_findings_diff(before: int, after: int):
    arrow = "→"
    change = after - before
    sign = f"+{change}" if change > 0 else str(change)
    print(f"  findings 변화: {before}건 {arrow} {after}건 ({sign})")


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="LLM 수동분석 패치를 마스터 스캔 JSON에 적용합니다.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "master",
        help="패치 대상 마스터 JSON (task25.json, injection.json, xss.json 등)",
    )
    parser.add_argument(
        "patch",
        help="LLM 패치 파일 (패치 배열 또는 보완 파일 형식 자동 감지)",
    )
    parser.add_argument(
        "--output", "-o",
        metavar="FILE",
        help="결과 출력 파일 (생략 시 마스터 파일을 in-place 수정)",
    )
    parser.add_argument(
        "--replace-categories",
        nargs="+",
        metavar="CATEGORY",
        help=(
            "해당 카테고리의 원본 findings를 패치 결과로 전부 교체.\n"
            "예: --replace-categories SENSITIVE_LOGGING HARDCODED_SECRET\n"
            "    (LLM 병합 결과로 대량 원본을 축소할 때 사용)"
        ),
    )
    parser.add_argument(
        "--backup",
        action="store_true",
        help="마스터 파일을 수정 전 .bak으로 백업 (--output 없을 때만 적용)",
    )
    parser.add_argument(
        "--recalculate-summary",
        action="store_true",
        help="패치 후 master.summary 통계 블록 재계산",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="변경 내용만 출력, 파일 미수정",
    )
    args = parser.parse_args()

    # ── 파일 로드 ────────────────────────────────────────────────────────────
    master_path = Path(args.master)
    patch_path = Path(args.patch)

    if not master_path.exists():
        print(f"[ERROR] 마스터 파일 없음: {master_path}", file=sys.stderr)
        sys.exit(1)
    if not patch_path.exists():
        print(f"[ERROR] 패치 파일 없음: {patch_path}", file=sys.stderr)
        sys.exit(1)

    with open(master_path, encoding="utf-8") as f:
        master = json.load(f)
    with open(patch_path, encoding="utf-8") as f:
        patch_data = json.load(f)

    # ── 원본 findings 건수 기록 ──────────────────────────────────────────────
    before_count = len(master.get("findings", []))
    before_ep_patched = sum(
        1 for ep in master.get("endpoint_diagnoses", []) if ep.get("_patched")
    )

    # ── 패치 형식 감지 ───────────────────────────────────────────────────────
    fmt = detect_format(patch_data)

    stats = {
        "format": fmt,
        "updated": 0,
        "added": 0,
        "replaced_categories": [],  # list of (category, count)
        "ep_updated": 0,
        "ep_not_found": [],
        "skipped": 0,
    }

    # ── 적용 (dry-run이면 복사본에 적용) ────────────────────────────────────
    work = copy.deepcopy(master) if args.dry_run else master

    if fmt == "array":
        work = apply_array_patch(work, patch_data, args.replace_categories, stats)
    else:
        work = apply_supplemental(work, patch_data, args.replace_categories, stats)

    # ── 요약 재계산 ──────────────────────────────────────────────────────────
    if args.recalculate_summary:
        work = recalculate_summary(work)

    # ── 통계 출력 ────────────────────────────────────────────────────────────
    print_stats(stats, master_path, patch_path, args.dry_run)

    after_count = len(work.get("findings", []))
    if before_count != after_count or stats["added"] or stats["updated"]:
        print_findings_diff(before_count, after_count)

    if args.dry_run:
        print("[DRY-RUN] 파일 변경 없음.\n")
        return

    # ── 백업 ─────────────────────────────────────────────────────────────────
    if args.backup and not args.output:
        bak_path = master_path.with_suffix(master_path.suffix + ".bak")
        shutil.copy2(master_path, bak_path)
        print(f"[백업] {bak_path}")

    # ── 저장 ─────────────────────────────────────────────────────────────────
    output_path = Path(args.output) if args.output else master_path
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(work, f, ensure_ascii=False, indent=2)

    print(f"[저장] {output_path}  ({after_count}건 findings)\n")


if __name__ == "__main__":
    main()
