#!/usr/bin/env python3
"""
scan_file_processing.py v1.0.0
================================================================================
Spring Boot (Java/Kotlin) 파일 업로드/다운로드 & LFI/RFI 취약점 자동 진단.

진단 항목:
  [U] 파일 업로드    : UUID 난수화, Tika MIME 검증, 확장자 Whitelist, 크기 제한
  [D] 다운로드 / LFI : HTTP 파라미터 → 파일 API Taint Tracking, Path Traversal 필터
  [R] RFI / SSRF     : 사용자 입력 → 외부 요청 API Taint Tracking, URL Whitelist
  [C] 설정 파일      : max-file-size, multipart 전역 설정

사용법:
  python scan_file_processing.py <source_dir> [-o output.json]
  python scan_file_processing.py <source_dir> --api-inventory state/api.json -o state/task24.json
"""

import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

VERSION = "1.0.0"

# ── 업로드 탐지 패턴 ──────────────────────────────────────────────────────────

# 업로드 어노테이션 (PostMapping / PutMapping / RequestMapping)
_UPLOAD_ANN_RE = re.compile(r'@(?:PostMapping|PutMapping|RequestMapping)\b')

# MultipartFile 파라미터명 추출
_MULTIPART_PARAM_RE = re.compile(r'MultipartFile\s+(\w+)')

# UUID 파일명 난수화
_UUID_RENAME_RE = re.compile(r'UUID\.randomUUID\s*\(\s*\)')

# Apache Tika MIME 검증
_TIKA_DETECT_RE = re.compile(
    r'(?:new\s+Tika\s*\(\s*\)|tika\.detect\s*\(|TikaConfig\b|'
    r'MimeTypes\.getDefaultMimeTypes\s*\(\s*\))',
    re.IGNORECASE,
)

# 확장자 Whitelist 검증
_EXT_WHITELIST_RE = re.compile(
    r'(?:'
    r'ALLOWED_EXT\w*\b|allowedExtension\w*\b|extensionWhitelist\b|'
    r'\.endsWith\s*\(\s*["\']\.(?:jpg|jpeg|png|gif|bmp|pdf|xlsx?|docx?|zip|hwp)["\']|'
    r'extension.*\.contains\b|\.contains\s*\(\s*ext\w*\b'
    r')',
    re.IGNORECASE,
)

# 파일 크기 제한 (코드 레벨)
_SIZE_LIMIT_CODE_RE = re.compile(
    r'(?:\.getSize\s*\(\s*\)|\.length\s*\(\s*\))\s*[><=!]|'
    r'@Size\b|MAX_FILE_SIZE\b|maxFileSize\b',
    re.IGNORECASE,
)

# 업로드 저장 절대경로 설정 패턴
_ABS_PATH_STORE_RE = re.compile(
    r'@Value\s*\(["\'].*(?:upload|file\.path|storage)[^"\']*["\']|'
    r'System\.getenv\s*\(["\'][^"\']*(?:upload|storage)',
    re.IGNORECASE,
)

# ── 다운로드 / LFI 탐지 패턴 ─────────────────────────────────────────────────

# 다운로드 어노테이션
_DOWNLOAD_ANN_RE = re.compile(r'@(?:GetMapping|RequestMapping)\b')

# 파일 API 직접 사용
_FILE_API_RE = re.compile(
    r'(?:'
    r'new\s+File\s*\(|new\s+FileInputStream\s*\(|new\s+FileReader\s*\(|'
    r'Paths\.get\s*\(|'
    r'Files\.(?:readAllBytes|newInputStream|copy|write|newBufferedReader)\s*\('
    r')'
)

# HTTP 파라미터 (타입 포함) — 타입이 Long/int 이면 안전
_HTTP_PARAM_RE = re.compile(
    r'@(?:RequestParam|PathVariable)\s*'
    r'(?:\([^)]*\)\s*)?'
    r'(String|Long|Integer|int|long|Object)\s+(\w+)'
)

# Path Traversal 필터링 패턴
_PATH_FILTER_RE = re.compile(
    r'(?:'
    r'\.replace\s*\(\s*["\']\.\.[\\/]|'         # str.replace("../", "")
    r'\.contains\s*\(\s*["\']\.\.[\\/]|'         # str.contains("../")
    r'\.indexOf\s*\(\s*["\']\.\.[\\/]|'          # str.indexOf("../")
    r'\.getCanonicalPath\s*\(\s*\)|'             # File.getCanonicalPath()
    r'\.toRealPath\s*\(\s*\)|'                   # Path.toRealPath()
    r'\.normalize\s*\(\s*\)|'                    # Path.normalize()
    r'\.matches\s*\(\s*["\'][^"\']*\.\.'         # str.matches(".*\.\.")
    r')'
)

# DB 기반 파일 조회 (파일 ID → Repository)
_DB_FILE_LOOKUP_RE = re.compile(
    r'(?:repository|service|dao|mapper|store)\s*\.\s*'
    r'(?:findById|findByFileId|getFile|selectFile|findFile)\b',
    re.IGNORECASE,
)

# ── RFI / SSRF 탐지 패턴 ─────────────────────────────────────────────────────

# 외부 요청 API
_EXTERNAL_REQ_RE = re.compile(
    r'(?:'
    r'new\s+URL\s*\(|'
    r'restTemplate\.(?:getForEntity|postForEntity|exchange|getForObject|execute)\s*\(|'
    r'WebClient\.(?:create|builder)\s*\(|'
    r'HttpClient\.newBuilder\s*\(\s*\)|'
    r'HttpRequest\.newBuilder\s*\(\s*\)|'
    r'new\s+OkHttpClient\b'
    r')'
)

# URL Whitelist 검증
_URL_WHITELIST_RE = re.compile(
    r'(?:'
    r'allowedDomain\w*\b|urlWhitelist\b|whitelistUrl\b|'
    r'\.startsWith\s*\(\s*["\']https?://|'
    r'\.contains\s*\(\s*\w*[Dd]omain'
    r')',
    re.IGNORECASE,
)

# RFI용 HTTP String 파라미터
_RFI_STRING_PARAM_RE = re.compile(
    r'@(?:RequestParam|PathVariable)\s*'
    r'(?:\([^)]*\)\s*)?'
    r'String\s+(\w+)'
)

# ── 설정 파일 패턴 ────────────────────────────────────────────────────────────

_PROP_MAX_FILE_RE = re.compile(
    r'spring\.servlet\.multipart\.max-file-size\s*=\s*(\S+)', re.IGNORECASE
)
_PROP_MAX_REQ_RE = re.compile(
    r'spring\.servlet\.multipart\.max-request-size\s*=\s*(\S+)', re.IGNORECASE
)
_YAML_MAX_FILE_RE = re.compile(r'max-file-size\s*:\s*(\S+)', re.IGNORECASE)
_YAML_MAX_REQ_RE = re.compile(r'max-request-size\s*:\s*(\S+)', re.IGNORECASE)

# ── 헬퍼 함수 ─────────────────────────────────────────────────────────────────

def _read_file(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def _line_of(content: str, pos: int) -> int:
    return content[:pos].count("\n") + 1


def _extract_method_body(content: str, ann_pos: int) -> tuple[int, str]:
    """어노테이션 위치에서 가장 가까운 메서드 바디를 중괄호 균형으로 추출.

    Returns:
        (method_line, body_text)  — body_text 가 빈 문자열이면 추출 실패.
    """
    # 어노테이션 이후 메서드 시그니처 탐색 (최대 600자)
    segment_start = content.find("\n", ann_pos)
    if segment_start == -1:
        return 0, ""
    segment = content[segment_start : segment_start + 600]

    # public/protected/private + 반환타입 + 메서드명(
    sig_m = re.search(
        r'(?:public|protected|private)\s+(?:static\s+)?'
        r'(?:[\w<>\[\]?,\s]+\s+)+(\w+)\s*\(',
        segment,
    )
    if not sig_m:
        return 0, ""

    method_abs = segment_start + sig_m.start()
    method_line = _line_of(content, method_abs)

    # 첫 번째 { 위치
    brace_start = content.find("{", method_abs)
    if brace_start == -1:
        return method_line, ""

    depth = 0
    for i, ch in enumerate(content[brace_start:], brace_start):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return method_line, content[brace_start : i + 1]
    return method_line, ""


def _find_param_section(content: str, ann_pos: int) -> str:
    """어노테이션 이후 메서드 파라미터 목록 문자열 반환 ( ... ) 안."""
    seg = content[ann_pos : ann_pos + 800]
    m = re.search(r'\(([^{]*)\)', seg, re.DOTALL)
    return m.group(1) if m else ""


def _relative(path: Path, base: Path) -> str:
    try:
        return str(path.relative_to(base))
    except ValueError:
        return str(path)


# ── 업로드 스캔 ────────────────────────────────────────────────────────────────

def scan_uploads(source_dir: Path) -> list[dict]:
    """MultipartFile 파라미터를 받는 업로드 엔드포인트 탐지 및 보안 체크."""
    results = []

    for fpath in sorted(source_dir.rglob("*.java")):
        content = _read_file(fpath)
        if "MultipartFile" not in content:
            continue

        for ann_m in _UPLOAD_ANN_RE.finditer(content):
            ann_pos = ann_m.start()
            param_section = _find_param_section(content, ann_pos)

            mp_m = _MULTIPART_PARAM_RE.search(param_section)
            if not mp_m:
                continue

            param_name = mp_m.group(1)
            method_line, body = _extract_method_body(content, ann_pos)
            if not body:
                continue

            # 보안 체크 — 메서드 바디 + 전체 파일(설정 상수 등) 모두 검사
            has_uuid = bool(_UUID_RENAME_RE.search(body))
            has_tika = bool(_TIKA_DETECT_RE.search(body) or _TIKA_DETECT_RE.search(content))
            has_ext_wl = bool(_EXT_WHITELIST_RE.search(body) or _EXT_WHITELIST_RE.search(content))
            has_size = bool(
                _SIZE_LIMIT_CODE_RE.search(body) or _SIZE_LIMIT_CODE_RE.search(content)
            )

            # 판정
            missing = []
            if not has_uuid:
                missing.append("UUID 파일명 난수화 미확인")
            if not has_ext_wl:
                missing.append("확장자 Whitelist 미확인")
            if not has_tika:
                missing.append("MIME 타입(Tika) 검증 미확인")
            if not has_size:
                missing.append("파일 크기 제한 미확인")

            if not has_uuid and not has_ext_wl:
                result, severity = "vulnerable", "High"
                detail = "웹쉘 업로드 위험: " + " / ".join(missing)
            elif missing:
                result, severity = "info", "Low"
                detail = "보안 보완 권고: " + " / ".join(missing)
            else:
                result, severity = "safe", "Info"
                detail = "UUID 난수화 + 확장자 Whitelist + Tika MIME 검증 + 크기 제한 적용됨"

            results.append(
                {
                    "type": "upload",
                    "controller_file": _relative(fpath, source_dir),
                    "controller_line": method_line,
                    "multipart_param": param_name,
                    "checks": {
                        "has_uuid_rename": has_uuid,
                        "has_tika_mime_check": has_tika,
                        "has_ext_whitelist": has_ext_wl,
                        "has_size_limit": has_size,
                    },
                    "result": result,
                    "severity": severity,
                    "detail": detail,
                    "needs_review": result != "safe",
                }
            )

    return results


# ── 다운로드 / LFI 스캔 ────────────────────────────────────────────────────────

def scan_downloads(source_dir: Path) -> list[dict]:
    """HTTP 파라미터 → 파일 API Taint Tracking으로 다운로드/LFI 탐지."""
    results = []

    for fpath in sorted(source_dir.rglob("*.java")):
        content = _read_file(fpath)

        # 파일 API 사용 여부 빠른 사전 필터
        if not _FILE_API_RE.search(content):
            continue

        for ann_m in _DOWNLOAD_ANN_RE.finditer(content):
            ann_pos = ann_m.start()
            param_section = _find_param_section(content, ann_pos)
            method_line, body = _extract_method_body(content, ann_pos)
            if not body:
                continue

            # 파일 API가 메서드 바디에 있는지 확인
            file_api_m = _FILE_API_RE.search(body)
            if not file_api_m:
                continue

            # HTTP 파라미터 탐지
            params = list(_HTTP_PARAM_RE.finditer(param_section))
            if not params:
                # 파라미터 없이 고정 경로 → 양호
                results.append(
                    {
                        "type": "download",
                        "controller_file": _relative(fpath, source_dir),
                        "controller_line": method_line,
                        "param_name": "(없음)",
                        "param_type": "(없음)",
                        "checks": {
                            "is_id_type": True,
                            "has_path_traversal_filter": True,
                            "has_db_lookup": bool(_DB_FILE_LOOKUP_RE.search(body)),
                        },
                        "result": "safe",
                        "severity": "Info",
                        "detail": "HTTP 파라미터 없이 고정 경로에서만 파일 접근",
                        "needs_review": False,
                    }
                )
                continue

            for p in params:
                param_type = p.group(1)
                param_name = p.group(2)

                # 타입 기반 안전성 판단
                is_id_type = param_type in ("Long", "Integer", "int", "long")

                # 파라미터명이 메서드 바디에서 파일 API 직전 컨텍스트에 등장하는지 확인
                # (단순 문자열 포함 여부로 1차 taint 확인)
                param_in_body = param_name in body

                has_path_filter = bool(_PATH_FILTER_RE.search(body))
                has_db_lookup = bool(_DB_FILE_LOOKUP_RE.search(body))

                if is_id_type or has_db_lookup:
                    result, severity = "safe", "Info"
                    detail = (
                        f"숫자 타입({param_type}) 파일 ID 또는 DB 조회 기반 다운로드 — Taint 차단됨"
                    )
                    needs_review = False
                elif not param_in_body:
                    result, severity = "safe", "Info"
                    detail = f"파라미터 '{param_name}'이 파일 API 호출 경로에 미전달 (추적 불가)"
                    needs_review = True
                elif param_type == "String" and has_path_filter:
                    result, severity = "safe", "Info"
                    detail = f"String 파라미터 '{param_name}' 사용이지만 Path Traversal 필터 적용 확인"
                    needs_review = False
                else:
                    result, severity = "vulnerable", "High"
                    detail = (
                        f"String 파라미터 '{param_name}' → 파일 API 직접 전달 "
                        f"/ Path Traversal 필터 미확인 → LFI/Path Traversal 취약"
                    )
                    needs_review = False

                results.append(
                    {
                        "type": "download",
                        "controller_file": _relative(fpath, source_dir),
                        "controller_line": method_line,
                        "param_name": param_name,
                        "param_type": param_type,
                        "checks": {
                            "is_id_type": is_id_type,
                            "has_path_traversal_filter": has_path_filter,
                            "has_db_lookup": has_db_lookup,
                        },
                        "result": result,
                        "severity": severity,
                        "detail": detail,
                        "needs_review": needs_review,
                    }
                )

    return results


# ── RFI / SSRF 스캔 ────────────────────────────────────────────────────────────

def scan_rfi(source_dir: Path) -> list[dict]:
    """HTTP String 파라미터 → 외부 요청 API Taint Tracking으로 RFI/SSRF 탐지."""
    results = []

    for fpath in sorted(source_dir.rglob("*.java")):
        content = _read_file(fpath)

        if not _EXTERNAL_REQ_RE.search(content):
            continue

        # 외부 요청 API가 있는 메서드를 모두 탐색
        for ext_m in _EXTERNAL_REQ_RE.finditer(content):
            ext_pos = ext_m.start()
            ext_api = ext_m.group(0).strip()

            # ext_pos 이전에 가장 가까운 메서드 어노테이션(@GetMapping 등) 탐색
            # 단순화: 이전 500자 안에서 어노테이션 + 파라미터 검사
            pre_ctx = content[max(0, ext_pos - 2000) : ext_pos]

            # HTTP String 파라미터 존재 여부
            string_params = list(_RFI_STRING_PARAM_RE.finditer(pre_ctx))
            if not string_params:
                continue

            # 메서드 바디에서 URL Whitelist 검증 여부
            # ext_pos 이전 메서드 바디 시작 탐색 (최대 2000자 내 { 위치)
            body_start = pre_ctx.rfind("{")
            body_candidate = pre_ctx[body_start:] if body_start != -1 else pre_ctx
            has_whitelist = bool(
                _URL_WHITELIST_RE.search(body_candidate)
                or _URL_WHITELIST_RE.search(content[ext_pos : ext_pos + 400])
            )

            for p in string_params:
                param_name = p.group(1)

                if has_whitelist:
                    result, severity = "safe", "Info"
                    detail = f"URL Whitelist 검증 확인됨 — '{param_name}' → {ext_api}"
                    needs_review = False
                else:
                    result, severity = "vulnerable", "High"
                    detail = (
                        f"String 파라미터 '{param_name}' → {ext_api} 직접 전달 "
                        f"/ URL Whitelist 검증 미확인 → RFI/SSRF 취약"
                    )
                    needs_review = False

                # 중복 제거: 동일 파일+라인+파라미터
                line_no = _line_of(content, ext_pos)
                key = (str(fpath), line_no, param_name)
                if any(
                    r["controller_file"] == _relative(fpath, source_dir)
                    and r["controller_line"] == line_no
                    and r["param_name"] == param_name
                    for r in results
                ):
                    continue

                results.append(
                    {
                        "type": "rfi",
                        "controller_file": _relative(fpath, source_dir),
                        "controller_line": line_no,
                        "param_name": param_name,
                        "external_api": ext_api,
                        "checks": {
                            "has_url_whitelist": has_whitelist,
                        },
                        "result": result,
                        "severity": severity,
                        "detail": detail,
                        "needs_review": needs_review,
                    }
                )

    return results


# ── 설정 파일 스캔 ─────────────────────────────────────────────────────────────

def scan_config(source_dir: Path) -> dict:
    """application.properties / application.yml 에서 multipart 설정 추출."""
    findings: dict = {
        "max_file_size": None,
        "max_request_size": None,
        "config_files_found": [],
        "has_size_limit": False,
        "detail": "",
    }

    for pattern in ("**/*.properties", "**/*.yml", "**/*.yaml"):
        for fpath in sorted(source_dir.rglob(pattern.replace("**/", ""))):
            content = _read_file(fpath)
            rel = _relative(fpath, source_dir)

            # .properties
            m = _PROP_MAX_FILE_RE.search(content)
            if m:
                findings["max_file_size"] = m.group(1)
                findings["config_files_found"].append(rel)
            m = _PROP_MAX_REQ_RE.search(content)
            if m:
                findings["max_request_size"] = m.group(1)
                if rel not in findings["config_files_found"]:
                    findings["config_files_found"].append(rel)

            # .yml / .yaml
            m = _YAML_MAX_FILE_RE.search(content)
            if m and not findings["max_file_size"]:
                findings["max_file_size"] = m.group(1)
                if rel not in findings["config_files_found"]:
                    findings["config_files_found"].append(rel)
            m = _YAML_MAX_REQ_RE.search(content)
            if m and not findings["max_request_size"]:
                findings["max_request_size"] = m.group(1)
                if rel not in findings["config_files_found"]:
                    findings["config_files_found"].append(rel)

    if findings["max_file_size"]:
        findings["has_size_limit"] = True
        findings["detail"] = (
            f"max-file-size: {findings['max_file_size']}"
            + (
                f" / max-request-size: {findings['max_request_size']}"
                if findings["max_request_size"]
                else ""
            )
        )
    else:
        findings["detail"] = (
            "spring.servlet.multipart.max-file-size 설정 미발견 — 업로드 크기 제한 없음 (기본 1MB)"
        )

    return findings


# ── 요약 계산 ──────────────────────────────────────────────────────────────────

def _summarize(uploads: list, downloads: list, rfis: list, config: dict) -> dict:
    def counts(lst: list) -> dict:
        c = {"safe": 0, "vulnerable": 0, "info": 0, "needs_review": 0, "total": len(lst)}
        for item in lst:
            r = item.get("result", "")
            if r in c:
                c[r] += 1
            if item.get("needs_review"):
                c["needs_review"] += 1
        return c

    return {
        "upload": counts(uploads),
        "download": counts(downloads),
        "rfi": counts(rfis),
        "config": {
            "has_size_limit": config.get("has_size_limit", False),
            "max_file_size": config.get("max_file_size"),
        },
        "total_vulnerable": sum(
            1 for lst in (uploads, downloads, rfis) for i in lst if i["result"] == "vulnerable"
        ),
        "total_needs_review": sum(
            1 for lst in (uploads, downloads, rfis) for i in lst if i.get("needs_review")
        ),
    }


# ── 메인 ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="File Upload/Download & LFI/RFI vulnerability scanner for Spring Boot"
    )
    parser.add_argument("source_dir", help="Scan target source directory")
    parser.add_argument("-o", "--output", default=None, help="Output JSON file path")
    parser.add_argument(
        "--api-inventory",
        default=None,
        help="Optional: scan_api.py output JSON for endpoint filtering",
    )
    args = parser.parse_args()

    source_dir = Path(args.source_dir).resolve()
    if not source_dir.is_dir():
        print(f"[ERROR] 소스 디렉토리가 존재하지 않습니다: {source_dir}", file=sys.stderr)
        sys.exit(1)

    print(f"[INFO] Scanning: {source_dir}")

    uploads = scan_uploads(source_dir)
    downloads = scan_downloads(source_dir)
    rfis = scan_rfi(source_dir)
    config = scan_config(source_dir)

    summary = _summarize(uploads, downloads, rfis, config)

    output = {
        "scan_metadata": {
            "version": VERSION,
            "source_dir": str(source_dir),
            "scanned_at": datetime.now().isoformat(timespec="seconds"),
            "total_upload_endpoints": len(uploads),
            "total_download_endpoints": len(downloads),
            "total_rfi_endpoints": len(rfis),
        },
        "upload_diagnoses": uploads,
        "download_diagnoses": downloads,
        "rfi_diagnoses": rfis,
        "config_findings": config,
        "summary": summary,
    }

    # 출력
    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[DONE] 결과 저장: {out_path}")
    else:
        print(json.dumps(output, ensure_ascii=False, indent=2))

    # 콘솔 요약
    s = summary
    print(
        f"\n[요약] 업로드: 취약 {s['upload']['vulnerable']} / 정보 {s['upload']['info']} / 양호 {s['upload']['safe']}"
        f"  |  다운로드: 취약 {s['download']['vulnerable']} / 정보 {s['download']['info']} / 양호 {s['download']['safe']}"
        f"  |  RFI: 취약 {s['rfi']['vulnerable']} / 양호 {s['rfi']['safe']}"
        f"  |  수동검토 필요: {s['total_needs_review']}건"
        f"  |  설정 크기제한: {'Y' if s['config']['has_size_limit'] else 'N'}"
    )


if __name__ == "__main__":
    main()
