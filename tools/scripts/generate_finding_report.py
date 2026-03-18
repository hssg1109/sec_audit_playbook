#!/usr/bin/env python3
"""
취약점 진단 결과 상세 보고서 생성 스크립트

각 Task 결과를 개발자 친화적인 Markdown 보고서로 변환합니다.
취약점별로 영향받는 코드 증적(evidence)을 포함하여 조치가 용이하도록 합니다.

사용법:
    python generate_finding_report.py <source_dir> <finding_results...> --output <report.md>
    python generate_finding_report.py testbed/3-pcona/pcona-env-dev@afd19907e2c/ \
        state/pcona_task_22_result.json state/pcona_task_23_result.json \
        --service "PCoNA 관리콘솔" --output state/pcona_진단보고서.md

출력 형식:
    - 서비스 개요 및 진단 범위
    - 진단 결과 요약 표
    - 카테고리별 취약점 상세 (코드 증적 포함)
"""

import json
import re
import sys
import argparse
from pathlib import Path
from datetime import date
from dataclasses import dataclass, field
from typing import Optional


# =============================================================================
#  상수 정의
# =============================================================================

# Task ID → 카테고리 매핑
CATEGORY_INFO = {
    "injection": {
        "name": "인젝션",
        "number": "1",
        "threat": "DB/서버 침투, 정보 탈취",
        "items": {
            "sql": "SQL 인젝션",
            "os_command": "OS Command 인젝션",
            "ssi": "SSI/SSTI 인젝션",
            "ssti": "SSI/SSTI 인젝션",
        }
    },
    "xss": {
        "name": "XSS",
        "number": "2",
        "threat": "세션 탈취, 피싱, 악성코드 배포",
        "items": {
            "xss_filter": "XSS 필터 결함",
            "persistent": "Persistent XSS",
            "reflected": "Reflected XSS",
            "dom": "DOM-based XSS",
            "redirect": "Open Redirect",
        }
    },
    "file_handling": {
        "name": "파일 처리",
        "number": "3",
        "threat": "웹쉘 업로드, 서버 파일 노출",
        "items": {
            "upload": "파일 업로드",
            "download": "파일 다운로드",
            "lfi": "로컬 파일 인클루전",
            "path_traversal": "경로 탐색",
        }
    },
    "data_protection": {
        "name": "데이터 보호",
        "number": "4",
        "threat": "정보 노출, 계정 탈취",
        "items": {
            "info_leak":    "정보 누출",           # fallback 기본값 (첫 번째 항목)
            "log_exposure": "로그 내 정보 노출",
            "hardcoded":    "하드코딩된 비밀정보",
            "weak_crypto":  "취약한 암호화 알고리즘",
            "dto_exposure": "응답 DTO 민감 필드 노출",
            "admin_api":    "관리자 API 접근 통제",
            "cors":         "CORS 설정 미흡",
            "jwt":          "JWT 취약점",
            "csrf":         "CSRF 보호 미흡",
        }
    },
}

# severity 내부값 → (결과, 위험도) 매핑
# 근거: 전자금융감독규정 제37조의3, 주요 정보통신기반시설 보호지침 제2021-28호
# 결과: 취약/정보/양호  |  위험도: 1~5 (5=즉각조치, 4=우선조치, 3=검토후조치, 2=통과, 1=참고)
# 보고서에 Critical/High 등 영문 등급은 표시하지 않고 위험도 숫자만 노출함
RISK_MAP = {
    # 표준 포맷 (scan_xss, scan_data_protection, scan_file_processing)
    "critical": ("취약", 5),
    "high":     ("취약", 4),
    "medium":   ("정보", 3),
    "low":      ("양호", 2),
    "info":     ("정보", 1),
    # Injection 스캔 포맷 (scan_injection_enhanced: "Risk N" 형식)
    "risk 5":   ("취약", 5),
    "risk 4":   ("취약", 4),
    "risk 3":   ("정보", 3),
    "risk 2":   ("양호", 2),
    "risk 1":   ("정보", 1),
}

ANCHOR_STYLE = "confluence"

# LLM 출력 category 문자열용 추가 키워드 → item_key 매핑
# (영문/한국어 혼용, 슬래시 구분 포맷 등 대응)
# 검색 순서: 긴 패턴 우선 (os command > command 등)
SUBCATEGORY_EXTRA_KEYWORDS: dict[str, list[tuple[str, str]]] = {
    "injection": [
        ("os command", "os_command"),
        (" command",   "os_command"),
        ("groovy",     "os_command"),
        ("rce",        "os_command"),
        ("stored rce", "os_command"),
        ("ssti",       "ssti"),
        ("ssi",        "ssi"),
        ("sql",        "sql"),
    ],
    "xss": [
        ("open redirect",    "redirect"),
        ("filter misconfig", "xss_filter"),
        ("filter bypass",    "xss_filter"),
        ("xss / filter",     "xss_filter"),
        ("xss/filter",       "xss_filter"),
        ("filter",           "xss_filter"),
        ("persistent",       "persistent"),
        ("stored",           "persistent"),
        ("reflected",        "reflected"),
        ("dom-based",        "dom"),
        ("dom based",        "dom"),
        ("dom xss",          "dom"),
        ("redirect",         "redirect"),
    ],
    "file_handling": [
        ("path traversal", "path_traversal"),
        ("경로 탐색",        "path_traversal"),
        ("lfi",         "lfi"),
        ("rfi",         "lfi"),
        ("upload",      "upload"),
        ("download",    "download"),
    ],
    "data_protection": [
        ("하드코딩",      "hardcoded"),
        ("시크릿",        "hardcoded"),
        ("자격증명",      "hardcoded"),
        ("hardcoded",  "hardcoded"),
        ("secret",     "hardcoded"),
        ("credential", "hardcoded"),
        # SENSITIVE_LOGGING — 로그 내 정보 노출 (민감정보/개인정보 로깅)
        # 주의: "민감정보" 단독 키워드는 DTO/기타 finding 오탐 방지를 위해 제외
        ("sensitive_logging",  "log_exposure"),
        ("로그 내 정보 노출",   "log_exposure"),
        ("로그 내 정보",        "log_exposure"),
        ("운영 로그",           "log_exposure"),
        ("개발 로그",           "log_exposure"),
        ("민감정보 로깅",        "log_exposure"),
        ("민감정보 로그",        "log_exposure"),
        ("민감정보 노출",        "log_exposure"),  # 로그 노출 (단독은 DTO와 겹치므로 "노출"까지 포함)
        ("로깅",               "log_exposure"),
        ("logging",            "log_exposure"),
        # DTO_EXPOSURE → 응답 DTO 민감 필드 노출
        ("dto_exposure",            "dto_exposure"),
        ("응답 dto 민감 필드",       "dto_exposure"),
        ("dto 민감 필드",           "dto_exposure"),
        ("dto",                     "dto_exposure"),
        ("jsonignore",              "dto_exposure"),
        ("@jsonignore",             "dto_exposure"),
        # ADMIN_SEPARATION → 관리자 API 접근 통제
        ("admin_separation",        "admin_api"),
        ("관리자 api 분리",          "admin_api"),
        ("관리자 api 접근",          "admin_api"),
        ("관리자 api",              "admin_api"),
        # pii 단독: DTO 키워드 미매칭 시에만 도달 (위 dto/dto_exposure 후순위)
        ("pii",                "log_exposure"),
        # WEAK_CRYPTO — 취약한 암호화 알고리즘 (PasswordEncoder, MD5, SHA-1 등)
        ("weak_crypto",       "weak_crypto"),
        ("weak crypto",       "weak_crypto"),
        ("취약한 암호화",      "weak_crypto"),
        ("취약 암호화",        "weak_crypto"),
        ("passwordencoder",   "weak_crypto"),
        ("암호화 알고리즘",    "weak_crypto"),
        ("암호 알고리즘",      "weak_crypto"),
        ("cors",       "cors"),
        ("jwt",        "jwt"),
        ("csrf",       "csrf"),
    ],
}


# 스캔 JSON summary → 통계 매트릭스 양호/취약/정보 추출 매핑
# 형식: (category_id, subtype_display_name) -> callable(summary_dict) -> {"vuln":int,"info":int,"safe":int}
def _pt(summary: dict, key: str) -> dict[str, int]:
    """per_type 하위 항목 카운트 추출"""
    pt = summary.get("per_type", {}).get(key, {})
    if not isinstance(pt, dict):
        return {"vuln": 0, "info": 0, "safe": 0}
    return {"vuln": pt.get("취약", 0), "info": pt.get("정보", 0), "safe": pt.get("양호", 0)}

_SCAN_SUMMARY_STATS: dict[tuple[str, str], object] = {
    ("injection", "SQL 인젝션"): lambda s: {
        "vuln": s.get("sqli", {}).get("취약", 0),
        "info": s.get("sqli", {}).get("정보", 0),
        "safe": s.get("sqli", {}).get("양호", 0),
    },
    # OS Command: 전역 패턴 스캔 — total=0이면 스캔 후 양호 확인
    ("injection", "OS Command 인젝션"): lambda s: {
        "vuln": 0,
        "info": s.get("os_command", {}).get("total", 0),
        "safe": 1 if s.get("os_command", {}).get("total", 0) == 0 else 0,
    },
    # SSI/SSTI: 전역 패턴 스캔 — total=0이면 1회 스캔 수행 결과 양호
    ("injection", "SSI/SSTI 인젝션"): lambda s: {
        "vuln": 0,
        "info": s.get("ssi", {}).get("total", 0),
        "safe": 1 if s.get("ssi", {}).get("total", 0) == 0 else 0,
    },
    ("xss", "Persistent XSS"):  lambda s: _pt(s, "persistent_xss"),
    ("xss", "Reflected XSS"):   lambda s: _pt(s, "reflected_xss"),
    ("xss", "Open Redirect"):   lambda s: _pt(s, "redirect_xss"),
    ("xss", "DOM-based XSS"):   lambda s: {
        "vuln": 0,
        "info": s.get("_scan_metadata", {}).get("dom_xss_scan", {}).get("findings_count", 0),
        "safe": 0,
    },
    # File Handling (task24): upload_diagnoses/download_diagnoses/rfi_diagnoses 기반
    # 파일 업로드는 LLM supplemental이 최종 판정 (extractor 없음 — LLM finding 집계 사용)
    ("file_handling", "파일 다운로드"): lambda s: {
        "vuln": s.get("download", {}).get("vulnerable", 0),
        "info": s.get("download", {}).get("info", 0),
        "safe": 1 if s.get("download", {}).get("total", 0) == 0 else s.get("download", {}).get("safe", 0),
    },
    ("file_handling", "로컬 파일 인클루전"): lambda s: {
        "vuln": s.get("rfi", {}).get("vulnerable", 0),
        "info": s.get("rfi", {}).get("info", 0),
        "safe": 1 if s.get("rfi", {}).get("total", 0) == 0 else s.get("rfi", {}).get("safe", 0),
    },
    ("file_handling", "경로 탐색"): lambda s: {"vuln": 0, "info": 0, "safe": 1},
}


# Task 순서 정의 (트리 + 매트릭스 공유)
_TASK_ORDER: list[tuple[str, str, str]] = [
    ("Task 2-2", "인젝션 (Injection)",         "injection"),
    ("Task 2-3", "XSS (Cross-Site Scripting)", "xss"),
    ("Task 2-4", "파일 처리 (File Handling)",   "file_handling"),
    ("Task 2-5", "데이터 보호 (Data Protection)", "data_protection"),
]


def _anchor(name: str) -> str:
    if ANCHOR_STYLE == "html":
        return ""
    return f"[[ANCHOR:{name}]]"


_RESULT_COLORS = {
    "취약": "#cc0000",   # 빨간색
    "정보": "#0055cc",   # 파란색
    "양호": "#007700",   # 초록색
}


def _colored_result(result: str) -> str:
    """md2cf 모드에서 결과 텍스트에 색상 적용. 다른 모드는 원문 반환."""
    color = _RESULT_COLORS.get(result)
    if color and ANCHOR_STYLE == "md2cf":
        return f'<span style="color:{color};font-weight:bold">{result}</span>'
    return result


def _html_table(headers: list[str], rows: list[list[str]]) -> str:
    def td(val: str) -> str:
        return f"<td>{val}</td>"
    def th(val: str) -> str:
        return f"<th>{val}</th>"
    lines = ["<table><tbody>"]
    lines.append("<tr>" + "".join(th(h) for h in headers) + "</tr>")
    for row in rows:
        lines.append("<tr>" + "".join(td(c) for c in row) + "</tr>")
    lines.append("</tbody></table>")
    return "\n".join(lines)


def _anchor_link(name: str, text: str) -> str:
    if ANCHOR_STYLE == "md2cf":
        return f"[{text}](#{name})"
    return f"[{text}](#{name})"


# =============================================================================
#  데이터 클래스
# =============================================================================

@dataclass
class Finding:
    """취약점 항목"""
    id: str
    title: str
    severity: str
    category: str
    subcategory: str
    description: str
    file: str
    line: int
    endpoint: str
    code_snippet: str
    context_before: list
    context_after: list
    recommendation: str
    evidence_type: str  # code, config, api, etc.
    flow: list
    instances: list = field(default_factory=list)
    affected_endpoints: list = field(default_factory=list)  # [{method, path, controller, description}] — 명시적 영향 API 목록
    is_supplemental: bool = False  # LLM 수동분석 보완 finding 여부
    from_ep_group: bool = False    # endpoint_diagnoses 기반 그룹 finding 여부
    original_id: str = ""          # 원본 JSON id (supplemental override 매칭용, e.g. "INJ-001")
    scan_category: str = ""        # 원본 JSON category 값 (auto-scan 카테고리 — category-replace 매칭용)
    log_instances: list = field(default_factory=list)  # SENSITIVE_LOGGING 파일별 노출 민감정보 [{file, file_path, sensitive_data, snippet}]
    ep_expansion: dict = field(default_factory=dict)   # EP별 행 분리 데이터 {"vuln_instances": [...], "info_instances": [...]}


@dataclass
class CategoryResult:
    """카테고리별 결과"""
    category_id: str
    category_name: str
    findings: list
    vuln_count: int
    info_count: int
    safe_count: int


# =============================================================================
#  파일 파싱
# =============================================================================

def detect_category(filepath: Path, task_id: str) -> str:
    """파일명/task_id에서 카테고리 추출"""
    fname = filepath.name.lower()
    tid = task_id.lower()

    if "22" in fname or "22" in tid or "injection" in fname:
        return "injection"
    elif "23" in fname or "23" in tid or "xss" in fname:
        return "xss"
    elif "24" in fname or "24" in tid or "file" in fname:
        return "file_handling"
    elif "25" in fname or "25" in tid or "data" in fname:
        return "data_protection"
    return "injection"


def extract_code_evidence(source_dir: Path, file_path: str, line: int,
                          context_lines: int = 5,
                          keyword: str = "") -> tuple[str, list, list]:
    """소스 파일에서 코드 증적 추출"""
    if not file_path or not source_dir:
        return "", [], []

    # 파일 경로 정규화
    if file_path.startswith(str(source_dir)):
        full_path = Path(file_path)
    else:
        full_path = source_dir / file_path

    if not full_path.exists():
        # 부분 경로로 검색
        for f in source_dir.rglob("*.kt"):
            if file_path in str(f) or f.name in file_path:
                full_path = f
                break
        if not full_path.exists():
            for f in source_dir.rglob("*.java"):
                if file_path in str(f) or f.name in file_path:
                    full_path = f
                    break

    if not full_path.exists():
        return "", [], []

    try:
        lines = full_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except:
        return "", [], []

    if line <= 0 or line > len(lines):
        # 키워드로 라인 검색 (코드 파일, line=0인 경우)
        if keyword and keyword.strip():
            kw_lower = keyword.lower()
            for i, ln in enumerate(lines):
                if kw_lower in ln.lower():
                    idx = i
                    code_line = lines[idx]
                    before = lines[max(0, idx - context_lines):idx]
                    after = lines[idx + 1:min(len(lines), idx + 1 + context_lines)]
                    return code_line, before, after
        # line=0인 config/properties 파일은 첫 30줄을 전체 표시
        _config_exts = ('.properties', '.yml', '.yaml', '.json', '.xml', '.conf', '.env')
        if any(file_path.endswith(ext) for ext in _config_exts):
            preview = lines[:30]
            if not preview:
                return "", [], []
            return preview[0], [], preview[1:]
        return "", [], []

    idx = line - 1
    code_line = lines[idx]
    before = lines[max(0, idx - context_lines):idx]
    after = lines[idx + 1:min(len(lines), idx + 1 + context_lines)]

    return code_line, before, after


def load_findings(filepath: Path, source_dir: Path,
                  is_supplemental: bool = False) -> tuple[str, list[Finding]]:
    """진단 결과 파일 로드"""
    with open(filepath, encoding="utf-8") as f:
        data = json.load(f)

    task_id = data.get("task_id", "")
    category = detect_category(filepath, task_id)
    cat_info = CATEGORY_INFO[category]

    findings = []
    for idx, f in enumerate(data.get("findings", []), 1):
        # 위치 정보 추출
        location = f.get("location", {})
        if isinstance(location, str):
            # 문자열인 경우 파싱
            file_match = re.search(r'([^\s:]+\.(kt|java|js|ts|xml))(?::(\d+))?', location)
            file_path = file_match.group(1) if file_match else ""
            line_num = int(file_match.group(3)) if file_match and file_match.group(3) else 0
            endpoint = ""
        else:
            file_path = location.get("file", f.get("file", ""))
            line_num = location.get("line", f.get("line", 0))
            endpoint = location.get("endpoint", location.get("api", ""))

        # affected_files에서 추가 정보
        af_files: list[str] = []  # 문자열 형태 affected_files 수집 (표 표시용)
        for af in f.get("affected_files", []):
            if isinstance(af, dict):
                if not file_path:
                    file_path = af.get("file", "")
                if not line_num:
                    line_num = af.get("line", 0)
                if not endpoint:
                    endpoint = af.get("api", af.get("endpoint", ""))
            elif isinstance(af, str) and af.strip():
                # "path/to/file.java (line N: reason)" 형식에서 파일 경로 추출
                af_path_match = re.match(r'^([^\s(]+)', af.strip())
                if af_path_match:
                    af_files.append(af_path_match.group(1))

        # evidence.file / evidence.files 보완 (LLM 결과 등 location이 없는 경우)
        evidence_pre = f.get("evidence", {})
        if isinstance(evidence_pre, dict):
            if not file_path:
                ev_file = evidence_pre.get("file", "")
                if isinstance(ev_file, str) and ev_file and ev_file not in ("-", ""):
                    file_path = ev_file
                elif isinstance(evidence_pre.get("files"), list):
                    ev_files = [x for x in evidence_pre["files"] if isinstance(x, str) and x]
                    if ev_files:
                        file_path = ev_files[0]
                        if not af_files:
                            af_files = ev_files

        # 기존 evidence 우선 사용 (민감정보는 redacted evidence를 우선 반영)
        code_snippet = ""
        ctx_before = []
        ctx_after = []
        evidence = f.get("evidence", {})
        if isinstance(evidence, dict):
            code_snippet = evidence.get("code_snippet", evidence.get("code", ""))
            ctx_before = evidence.get("context_before", [])
            ctx_after = evidence.get("context_after", [])

        # evidence.files[].code / evidence.sample_code 추가 파싱 (LLM 결과 등)
        if not code_snippet and isinstance(evidence, dict):
            # files 배열의 첫 번째 항목 code 필드
            ev_files = evidence.get("files", [])
            if isinstance(ev_files, list):
                combined_codes = []
                for ef in ev_files:
                    if isinstance(ef, dict) and ef.get("code"):
                        line_hint = f"# {ef.get('file', '')} line {ef.get('line', '')}" if ef.get("file") else ""
                        combined_codes.append(f"{line_hint}\n{ef['code']}".strip())
                        if not file_path and ef.get("file"):
                            file_path = ef["file"]
                        if not line_num and ef.get("line"):
                            line_num = int(ef["line"]) if str(ef["line"]).isdigit() else 0
                if combined_codes:
                    code_snippet = "\n\n".join(combined_codes)
            # evidence.sample_code 필드
            if not code_snippet:
                sample = evidence.get("sample_code", "")
                if isinstance(sample, str) and sample.strip():
                    code_snippet = sample

        # evidence.instances 처리 (LLM 분석 결과 포맷 — {file, lines, code_snippet, method, taint_path})
        if not code_snippet and isinstance(evidence, dict):
            inst_list = evidence.get("instances", [])
            if isinstance(inst_list, list) and inst_list:
                combined_parts = []
                for inst in inst_list:
                    if not isinstance(inst, dict):
                        continue
                    inst_file  = inst.get("file", "")
                    inst_lines = inst.get("lines", "")
                    inst_code  = inst.get("code_snippet", "")
                    inst_method = inst.get("method", "")
                    if not file_path and inst_file:
                        file_path = inst_file
                    if inst_code:
                        header = f"// {inst_file}" if inst_file else ""
                        if inst_lines:
                            header += f" (L{inst_lines})"
                        if inst_method:
                            header += f" — {inst_method}"
                        combined_parts.append(f"{header}\n{inst_code}".strip())
                if combined_parts:
                    code_snippet = "\n\n".join(combined_parts)

        # file_path 조기 설정 (af_files 기반) — extract_code_evidence() 호출 전에 설정
        if not file_path and af_files:
            file_path = af_files[0]

        # 코드 증적 추출 (evidence가 없을 때만 — source 파일 직접 읽기)
        if not code_snippet:
            # 키워드 기반 라인 검색: line=0이고 코드 파일일 때 title/description 키워드로 위치 탐색
            search_keyword = ""
            if line_num == 0 and file_path:
                _code_exts = ('.kt', '.java', '.js', '.ts', '.py', '.groovy', '.scala')
                if any(file_path.endswith(ext) for ext in _code_exts):
                    # 제목/설명에서 검색 키워드 추출 (첫 번째 의미있는 단어)
                    title_kw = f.get("title", "")
                    desc_kw = f.get("description", "")
                    # 알려진 암호화/취약 패턴 키워드 우선
                    _known_kws = ["MD5", "SHA1", "SHA-1", "DES", "RC4", "AES", "Base64", "password", "secret", "token"]
                    for kw in _known_kws:
                        if kw.lower() in (title_kw + desc_kw).lower():
                            search_keyword = kw
                            break
                    if not search_keyword and title_kw:
                        # 제목의 괄호 안 첫 단어 (예: "MD5 취약 해시")
                        words = re.findall(r'\b[A-Za-z0-9_]{3,}\b', title_kw)
                        if words:
                            search_keyword = words[0]
            code_snippet, ctx_before, ctx_after = extract_code_evidence(
                source_dir, file_path, line_num, keyword=search_keyword
            )

        # 인스턴스 정보 (패턴 기반 다중 위치)
        instances = []
        metadata = f.get("metadata", {})
        meta_instances = metadata.get("instances") if isinstance(metadata, dict) else None
        if isinstance(meta_instances, list):
            for inst in meta_instances:
                if isinstance(inst, dict):
                    inst_file = inst.get("file", "")
                    inst_line = inst.get("line", 0)
                    inst_endpoint = inst.get("endpoint", inst.get("api", ""))
                    instances.append({
                        "file": inst_file,
                        "line": inst_line,
                        "endpoint": inst_endpoint,
                    })
                elif isinstance(inst, str):
                    file_match = re.search(r'([^\s:]+\.(kt|java|js|ts|xml))(?::(\d+))?', inst)
                    inst_file = file_match.group(1) if file_match else ""
                    inst_line = int(file_match.group(3)) if file_match and file_match.group(3) else 0
                    instances.append({
                        "file": inst_file,
                        "line": inst_line,
                        "endpoint": "",
                    })

        # evidence.instances → instances list (LLM 포맷)
        if not instances and isinstance(evidence, dict):
            inst_list = evidence.get("instances", [])
            if isinstance(inst_list, list) and inst_list:
                for inst in inst_list:
                    if not isinstance(inst, dict):
                        continue
                    inst_file = inst.get("file", "")
                    inst_lines_str = str(inst.get("lines", ""))
                    inst_line_n = 0
                    if inst_lines_str:
                        _lm = re.match(r'^(\d+)', inst_lines_str)
                        if _lm:
                            inst_line_n = int(_lm.group(1))
                    instances.append({
                        "file": inst_file,
                        "line": inst_line_n,
                        "endpoint": inst.get("taint_path", inst.get("method", "")),
                    })

        if not instances and af_files:
            # affected_files 문자열에서 수집한 파일 목록으로 instances 구성
            instances = [{"file": fp, "line": 0, "endpoint": endpoint} for fp in af_files]
        if not instances and (file_path or line_num or endpoint):
            instances = [{
                "file": file_path,
                "line": line_num,
                "endpoint": endpoint,
            }]

        # affected_endpoints 파싱 — [{method, path, controller, description}] 구조화 목록
        # JSON 필드 우선순위: affected_endpoints(배열) > affected_endpoint(단수 문자열 — 하위호환)
        _METHOD_RE = re.compile(
            r'^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(.+)', re.IGNORECASE
        )

        def _parse_ep_entry(raw) -> dict:
            """단일 엔드포인트 항목을 정규화된 dict로 변환."""
            if isinstance(raw, dict):
                return {
                    "method":      raw.get("method", "").upper() if raw.get("method") else "",
                    "path":        raw.get("path", raw.get("endpoint", "")),
                    "controller":  raw.get("controller", ""),
                    "description": raw.get("description", ""),
                }
            if isinstance(raw, str) and raw.strip():
                m = _METHOD_RE.match(raw.strip())
                if m:
                    return {"method": m.group(1).upper(), "path": m.group(2).strip(),
                            "controller": "", "description": ""}
                return {"method": "", "path": raw.strip(), "controller": "", "description": ""}
            return {}

        affected_endpoints: list[dict] = []
        _ae_raw = f.get("affected_endpoints", [])
        if isinstance(_ae_raw, list) and _ae_raw:
            for _ae in _ae_raw:
                _entry = _parse_ep_entry(_ae)
                if _entry.get("path"):
                    affected_endpoints.append(_entry)
        elif not affected_endpoints:
            # 하위호환: 단수 문자열 affected_endpoint → 1-entry 배열로 승격
            _ae_str = f.get("affected_endpoint", "")
            if isinstance(_ae_str, str) and _ae_str.strip() and _ae_str not in ("-", "서비스 전반", "전역"):
                _entry = _parse_ep_entry(_ae_str)
                if _entry.get("path"):
                    affected_endpoints.append(_entry)

        # 서브카테고리 추출
        title_lower = f.get("title", "").lower()
        cat_lower = f.get("category", "").lower()
        subcategory = ""
        # 1) JSON subcategory 필드 직접 사용 (있을 때)
        raw_sub = f.get("subcategory", "")
        if raw_sub:
            subcategory = raw_sub
        # 2) CATEGORY_INFO item key 기반 매핑 (영문 키 → 표시 명칭)
        if not subcategory:
            import re as _re
            # title에서 "(파일명.확장자)" 형태의 괄호 내용을 제거 — 파일명 포함 오탐 방지
            # 예: "민감정보(PII) 평문 로깅 — 1건 (JwtAuthenticationFilter.java)" 에서
            #      "(JwtAuthenticationFilter.java)" 제거 → "jwt" 오탐 방지
            title_no_filename = _re.sub(
                r'\s*\([^)]*\.(java|kt|xml|js|ts|jsx|tsx|py|go|cs|rb|cpp|c|h)\b[^)]*\)',
                '', title_lower
            )
            for key in sorted(cat_info["items"].keys(), key=len, reverse=True):
                name = cat_info["items"][key]
                if key in cat_lower or key in title_no_filename:
                    subcategory = name
                    break
        # 3) SUBCATEGORY_EXTRA_KEYWORDS 기반 매핑 (LLM 한국어/혼용 category 대응)
        if not subcategory:
            combined = title_lower + " " + cat_lower
            for keyword, item_key in SUBCATEGORY_EXTRA_KEYWORDS.get(category, []):
                if keyword in combined:
                    subcategory = cat_info["items"].get(item_key, "")
                    if subcategory:
                        break
        # 4) fallback: 첫 번째 항목
        if not subcategory:
            subcategory = list(cat_info["items"].values())[0]

        # JSON result 필드로 severity 보정 (LLM 최종 결과 우선)
        _severity = f.get("severity", "info").lower()
        _json_result = f.get("result", "").strip()
        if _json_result == "양호" and _severity not in ("high", "critical"):
            _severity = "low"
        elif _json_result == "취약" and _severity not in ("high", "critical"):
            # LLM이 "취약"으로 판정한 경우 medium/info → high(취약)로 상향
            _severity = "high"

        findings.append(Finding(
            id=f"{cat_info['number']}-{idx}",
            title=f.get("title", ""),
            severity=_severity,
            category=cat_info["name"],
            subcategory=subcategory,
            description=f.get("description", ""),
            file=file_path,
            line=line_num,
            endpoint=endpoint,
            code_snippet=code_snippet,
            context_before=ctx_before if isinstance(ctx_before, list) else [],
            context_after=ctx_after if isinstance(ctx_after, list) else [],
            recommendation=f.get("recommendation", ""),
            evidence_type="code" if code_snippet else "description",
            flow=f.get("flow", []),
            instances=instances,
            affected_endpoints=affected_endpoints,
            is_supplemental=is_supplemental,
            original_id=f.get("id", ""),  # 원본 JSON id 보존 (override 매칭용)
            scan_category=f.get("category", ""),  # 원본 JSON category (category-replace 매칭용)
            log_instances=f.get("log_instances", []),  # SENSITIVE_LOGGING 파일별 노출 민감정보 목록
        ))

    return category, findings


# =============================================================================
#  보고서 생성
# =============================================================================

def load_endpoint_group_findings(filepath: Path,
                                  source_dir: Path,
                                  llm_supp_data: dict | None = None) -> tuple[str, list[Finding]]:
    """스캔 JSON의 endpoint_diagnoses에서 정보 엔드포인트를 그룹 Finding으로 변환.

    injection(2-2)  : diagnosis_type별 그룹 (외부의존성 / XML미발견)
    xss     (2-3)   : xss_category별 그룹 (잠재적위협=Persistent / 수동확인필요=Reflected)
    """
    try:
        raw = json.loads(filepath.read_text(encoding="utf-8"))
    except Exception:
        return "", []
    if "endpoint_diagnoses" not in raw:
        return "", []

    task_id  = raw.get("task_id", "")
    category = detect_category(filepath, task_id)
    cat_info = CATEGORY_INFO[category]

    info_eps = [ep for ep in raw["endpoint_diagnoses"] if ep.get("result") == "정보"]
    # XSS(2-3): 자동스캔이 "취약"으로 판정한 endpoint_diagnoses도 그룹 Finding으로 변환
    vuln_eps_for_group = (
        [ep for ep in raw["endpoint_diagnoses"] if ep.get("result") == "취약"]
        if task_id == "2-3" else []
    )
    if not info_eps and not vuln_eps_for_group:
        return category, []

    def _find_method_in_file(src_dir: Path, process_file: str, method_name: str,
                              request_mapping: str) -> tuple[str, list, list]:
        """컨트롤러 파일에서 핸들러 메서드 코드 블록 추출 (대표 케이스용)"""
        if not process_file or not src_dir:
            return "", [], []
        fp = src_dir / process_file
        if not fp.exists():
            for ext in ("*.kt", "*.java"):
                for f in src_dir.rglob(ext):
                    if process_file.split("/")[-1] in str(f) or process_file in str(f):
                        fp = f
                        break
                if fp.exists():
                    break
        if not fp.exists():
            return "", [], []
        try:
            lines = fp.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            return "", [], []

        # 메서드 찾기: @Mapping 어노테이션 또는 메서드명
        search_terms = []
        if request_mapping:
            # URL의 마지막 세그먼트 — @PutMapping("/reacquiring/malls") 에서 seg="malls"
            # 단, 세그먼트가 경로 중간이므로 따옴표로 감싸인 패턴 대신 값 자체로도 검색
            seg = request_mapping.rstrip("/").split("/")[-1]
            # {pathVariable} 형태이면 제외
            if seg and not (seg.startswith("{") and seg.endswith("}")):
                search_terms.append(f'"{seg}"')        # "@PutMapping("/...malls")" 매칭
                search_terms.append(f"/{seg}\"")       # "/reacquiring/malls"" 패턴 매칭
                search_terms.append(f'"{request_mapping}"')
        if method_name:
            # method_name은 "allReacquiring()" 형태일 수 있으므로 () 제거 후 기본명 추출
            base = method_name.rstrip("()")
            search_terms.append(f"fun {base}(")         # Kotlin
            search_terms.append(f" {base}(")            # Java: 리턴타입 뒤 공백 + 메서드명
            search_terms.append(f"\t{base}(")           # 탭 들여쓰기
            search_terms.append(f"void {base}(")        # void 리턴
            search_terms.append(f"public {base}(")      # 단순 public (리턴타입 없는 경우)

        hit_line = 0
        for i, ln in enumerate(lines):
            for term in search_terms:
                if term in ln:
                    hit_line = i + 1
                    break
            if hit_line:
                break
        if not hit_line:
            return "", [], []

        idx = hit_line - 1
        # 메서드 블록 추출: hit부터 메서드 바디({}) 끝까지 (어노테이션 포함)
        # depth==0 조기 종료 문제: @PutMapping 어노테이션 hit 후 시그니처를 거쳐 { 진입 전에 끊기는 것 방지
        snippet_lines = []
        depth = 0
        entered_body = False  # 실제 메서드 바디({})에 진입했는지 여부
        for ln in lines[idx:idx + 30]:
            snippet_lines.append(ln)
            depth += ln.count("{") - ln.count("}")
            if depth > 0:
                entered_body = True
            if entered_body and depth <= 0:
                # 메서드 바디 진입 후 닫힘 → 메서드 종료
                break
            if not entered_body and len(snippet_lines) > 10:
                # 10줄 이상 어노테이션/시그니처만 지속 → 위치가 잘못됐거나 추상 메서드
                break

        if not snippet_lines:
            return "", [], []
        code_line = snippet_lines[0]
        after = snippet_lines[1:]
        before = lines[max(0, idx - 3):idx]
        return code_line, before, after

    findings: list[Finding] = []

    if task_id == "2-2":  # Injection: SQL injection 수동검토 그룹
        from collections import defaultdict
        groups: dict[str, list] = defaultdict(list)
        for ep in info_eps:
            groups[ep.get("diagnosis_type", "기타")].append(ep)

        sqli_review = (llm_supp_data or {}).get("sqli_endpoint_review", {})
        sqli_overall = sqli_review.get("overall_sqli_judgment", "")
        sqli_rationale = sqli_review.get("rationale", "")
        # group_judgments를 group명(diagnosis_type 부분문자열) → 판정/근거로 인덱싱
        # diagnosis_type 값이 그룹명에 포함되어 있으면 매칭 (프로젝트별 명칭 변동 대응)
        sqli_group_map: dict[str, dict] = {}
        _sqli_dtype_keys = (
            "외부 의존성 호출", "XML 미발견 패턴 추정",
            "DB 접근 미확인", "자동 판정 불가", "추적 불가",
        )
        for gj in sqli_review.get("group_judgments", []):
            gname = gj.get("group", "")
            for key in _sqli_dtype_keys:
                if key in gname:
                    sqli_group_map[key] = gj
                    break

        def _sqli_llm_note(dtype: str, n: int) -> str:
            """LLM 검토 결과를 description 보완 문자열로 반환."""
            gj = sqli_group_map.get(dtype)
            if not gj:
                return ""
            judgment = gj.get("judgment", "")
            if not judgment:
                return ""
            details = []
            for s in gj.get("services_reviewed", []) + gj.get("daos_reviewed", []):
                name = s.get("service") or s.get("dao", "")
                finding = (s.get("finding", "")
                           .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("*", "&#42;"))
                result = s.get("result", "")
                if name:
                    details.append(f"  - {name}: {finding} → **{result}**")
            detail_str = ("\n" + "\n".join(details)) if details else ""
            return (
                f"\n\n**✅ LLM 검토 완료 (Phase 3)** — 판정: **{judgment}**{detail_str}"
                + (f"\n\n**근거:** {sqli_rationale}" if sqli_rationale and dtype == "외부 의존성 호출" else "")
            )

        _desc_map = {
            "외부 의존성 호출": (
                "SQL 인젝션",
                "소스 트리에 포함되지 않은 **외부 Maven 모듈**에 구현된 서비스/레포지토리를 호출하는 "
                "엔드포인트입니다. 해당 외부 모듈의 SQL 쿼리 구성 방식(MyBatis `#{}` 바인딩 여부, "
                "취약한 `${}` 문자열 연결 여부)을 수동으로 검증해야 합니다.\n\n"
                "**주요 패턴:** UserService·AppConfigService 등 외부 모듈 호출 → 구현 확인 불가\n\n"
                "**위험도 판단:** 외부 모듈이 안전한 바인딩을 사용하면 양호, 그렇지 않으면 취약으로 재분류."
                + _sqli_llm_note("외부 의존성 호출", 0),
                "외부 모듈의 SQL 구현을 확인하고 MyBatis `#{}` 바인딩 또는 JPA/Spring Data 인터페이스를 사용하는지 검증하십시오.",
            ),
            "XML 미발견 패턴 추정": (
                "SQL 인젝션",
                "MyBatis/iBatis XML 매퍼 파일이 소스 트리에 존재하지 않거나 매핑이 확인되지 않은 "
                "엔드포인트입니다. `#{}` 바인딩 사용으로 **안전 추정**하지만, 외부 JAR 또는 "
                "빌드 산출물 내 XML을 직접 확인해야 합니다.\n\n"
                "**주요 패턴:** BarcodePageMapper·TcUserDao 등 외부 모듈 매퍼 — XML 미발견\n\n"
                "**위험도 판단:** XML 확인 후 `#{}` 확정 시 양호, `${}` 발견 시 취약으로 재분류."
                + _sqli_llm_note("XML 미발견 패턴 추정", 0),
                "빌드된 JAR 또는 외부 모듈 소스에서 MyBatis XML을 확인하고 `#{}` 파라미터 바인딩 사용 여부를 검증하십시오.",
            ),
        }

        for g_idx, (dtype, eps) in enumerate(groups.items(), 1):
            subcategory, desc_body, rec = _desc_map.get(
                dtype,
                ("SQL 인젝션", f"**{dtype}** — 수동 검증 필요.", "소스 코드를 직접 확인하십시오.")
            )
            instances = [
                {"file": ep.get("process_file", ""), "line": 0,
                 "endpoint": ep.get("request_mapping", "")}
                for ep in eps
            ]
            # 대표 케이스: 첫 번째 endpoint에서 코드 흐름 + 소스 추출
            rep = eps[0]
            rep_flow = rep.get("service_calls", [])[:10]  # 최대 10단계
            rep_diag = rep.get("diagnosis_detail", "")
            if rep_diag:
                rep_flow = rep_flow + [f"[판정] {rep_diag[:120]}"]
            rep_code, rep_before, rep_after = _find_method_in_file(
                source_dir, rep.get("process_file", ""),
                rep.get("method_name", ""), rep.get("request_mapping", "")
            )
            # LLM 검토 결과로 제목/설명 갱신
            gj_for_type = sqli_group_map.get(dtype)
            llm_judgment = gj_for_type.get("judgment", "") if gj_for_type else sqli_overall
            if llm_judgment == "양호":
                title = f"SQL 인젝션 LLM 검토 완료 — {dtype} ({len(eps)}건) [양호]"
                lead = (
                    f"**{len(eps)}개 엔드포인트**의 SQL 인젝션 가능성을 LLM이 직접 검토하여 "
                    f"**양호**로 확정하였습니다.\n\n"
                )
            elif llm_judgment in ("취약", "정보"):
                title = f"SQL 인젝션 LLM 검토 — {dtype} ({len(eps)}건) [{llm_judgment}]"
                lead = (
                    f"**{len(eps)}개 엔드포인트**의 SQL 인젝션 가능성을 LLM이 직접 검토하였습니다 "
                    f"(판정: **{llm_judgment}**).\n\n"
                )
            else:
                title = f"SQL 인젝션 수동검토 필요 — {dtype} ({len(eps)}건)"
                lead = (
                    f"**{len(eps)}개 엔드포인트**에서 소스 코드 추적이 불완전하여 "
                    f"SQL 인젝션 여부를 자동으로 확정할 수 없습니다. 수동 검증이 필요합니다.\n\n"
                )
            findings.append(Finding(
                id=f"{cat_info['number']}-EP{g_idx}",
                title=title,
                # LLM 양호 확인 → "low"(양호) 분류 → 세부 내용에서 제외, 매트릭스엔 양호로 집계
                severity="low" if llm_judgment == "양호" else "info",
                category=cat_info["name"],
                subcategory=subcategory,
                description=lead + desc_body,
                file=rep.get("process_file", "") if eps else "",
                line=0,
                endpoint=rep.get("request_mapping", "") if len(eps) == 1 else "",
                code_snippet=rep_code,
                context_before=rep_before,
                context_after=rep_after,
                recommendation=rec,
                evidence_type="code" if rep_code else "description",
                flow=rep_flow,
                instances=instances,
                is_supplemental=False,
                from_ep_group=True,
            ))

    elif task_id == "2-3":  # XSS: 잠재적위협 / 수동확인필요 그룹
        from collections import defaultdict
        groups: dict[str, list] = defaultdict(list)
        for ep in info_eps + vuln_eps_for_group:
            groups[ep.get("xss_category", "기타")].append(ep)

        xss_review = (llm_supp_data or {}).get("xss_endpoint_review", {})
        # group_judgments를 group명 키워드 → 판정으로 인덱싱
        xss_group_map: dict[str, dict] = {}
        for gj in xss_review.get("group_judgments", []):
            gname = gj.get("group", "")
            if "잠재적위협" in gname:
                xss_group_map["잠재적위협"] = gj
            elif "수동확인필요" in gname:
                xss_group_map.setdefault("수동확인필요", gj)

        def _md_escape_angle(s: str) -> str:
            """마크다운 → XHTML 변환 시 <...>가 태그로, *가 이탤릭으로 파싱되지 않도록 이스케이프."""
            return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("*", "&#42;")

        def _xss_llm_note(cat_key: str) -> str:
            gj = xss_group_map.get(cat_key)
            if not gj:
                return ""
            judgment = gj.get("judgment", "")
            rationale = gj.get("rationale", "")
            if not judgment:
                return ""
            detail_lines = []
            for c in gj.get("controllers_reviewed", []):
                name = c.get("controller", "")
                finding = _md_escape_angle(c.get("finding", ""))
                result = c.get("result", "")
                if name:
                    detail_lines.append(f"  - {name}: {finding} → **{result}**")
            for e in gj.get("endpoints_reviewed", []):
                ep_name = e.get("endpoint", "")
                finding = _md_escape_angle(e.get("finding", ""))
                result = e.get("result", "")
                if ep_name:
                    detail_lines.append(f"  - {ep_name}: {finding} → **{result}**")
            detail_str = ("\n" + "\n".join(detail_lines)) if detail_lines else ""
            rat_str = f"\n\n**근거:** {rationale}" if rationale else ""
            return f"\n\n**✅ LLM 검토 완료 (Phase 3)** — 판정: **{judgment}**{detail_str}{rat_str}"

        for g_idx, (xss_cat, eps) in enumerate(groups.items(), 1):
            instances = [
                {"file": ep.get("process_file", ""), "line": 0,
                 "endpoint": ep.get("request_mapping", "")}
                for ep in eps
            ]
            if xss_cat == "잠재적위협":
                subcategory = "Persistent XSS"
                llm_note = _xss_llm_note("잠재적위협")
                gj = xss_group_map.get("잠재적위협", {})
                llm_j = gj.get("judgment", "")
                if llm_j == "양호":
                    title = f"Persistent XSS 잠재 위협 LLM 검토 완료 — ({len(eps)}건) [양호]"
                else:
                    title = f"Persistent XSS — 전역 XSS 필터 미적용, 입력값 필터링 없이 DB 저장 ({len(eps)}건)"

                # 전역 XSS 필터 상태를 scan_metadata에서 읽어 동적으로 설명 생성
                _gxf = raw.get("scan_metadata", {}).get("global_xss_filter", {})
                _filter_level = _gxf.get("filter_level", "none")
                _has_lucy = _gxf.get("has_lucy", False)
                if _filter_level == "none":
                    _filter_state_desc = "전역 XSS 필터가 미설정된 상태(Lucy/AntiSamy/ESAPI 모두 미발견)"
                elif _has_lucy:
                    _filter_state_desc = "Lucy XSS 필터가 설정되었으나 일부 경로에서 필터링이 우회됨"
                else:
                    _filter_state_desc = "전역 XSS 필터가 불충분하게 설정된 상태"

                # taint 경로 확인된 엔드포인트 추출 (코드 흐름 증적용)
                _taint_confirmed_eps = [
                    ep for ep in eps
                    if isinstance(ep.get("phase_details", {}).get("phase5_persistent"), dict)
                    and ep["phase_details"]["phase5_persistent"].get("taint_result", {}).get("taint_confirmed")
                ]
                _taint_count = len(_taint_confirmed_eps)
                _taint_note = ""
                if _taint_count > 0:
                    _chains = []
                    for _tc in _taint_confirmed_eps:
                        _tr = _tc["phase_details"]["phase5_persistent"]["taint_result"]
                        _chain = _tr.get("call_chain", [])
                        _ep_path = _tc.get("request_mapping", "")
                        _ep_method = _tc.get("http_method", "")
                        if _chain:
                            _chains.append(
                                f"- `{_ep_method} {_ep_path}`: "
                                + " → ".join(f"`{c}`" for c in _chain)
                            )
                    _taint_note = (
                        f"\n\n**DB 저장 경로 확인 완료 ({_taint_count}건):**\n"
                        + "\n".join(_chains)
                    )

                desc = (
                    f"{_filter_state_desc}에서 자유 텍스트 파라미터가 필터링 없이 DB에 저장되는 "
                    f"**{len(eps)}개 엔드포인트**가 Persistent XSS 위험에 노출됩니다.\n\n"
                    "**공통 패턴:** `@RestController` / `@ResponseBody` — JSON 응답으로 "
                    "현재 아키텍처에서 직접 HTML 렌더링 경로는 없으나, 동일 데이터를 소비하는 "
                    "프론트엔드(React/Vue) 또는 관리자 화면에서 적절한 출력 인코딩이 없을 경우 "
                    "Stored XSS가 발현됩니다."
                    + _taint_note
                    + llm_note
                )

                # 대응방안: 필터 유무에 따라 다르게 생성
                if _filter_level == "none":
                    rec = (
                        "저장 시점 XSS 입력 필터 적용 (Defense-in-Depth):\n"
                        "1. Spring Lucy XSS Filter (naver/lucy-xss-servlet) 전역 적용 — "
                        "JSON 요청(`Content-Type: application/json`) 포함 처리\n"
                        "2. 또는 Jackson `ObjectMapper`에 커스텀 `JsonDeserializer` 적용으로 "
                        "HTML 특수문자(< > ' \" 등) Sanitize\n"
                        "3. 소비자(프론트엔드/관리자 앱) 측 출력 인코딩 별도 적용 권고 "
                        "(저장 측 필터와 상호보완)"
                    )
                elif _has_lucy:
                    rec = (
                        "Lucy XSS 필터 설정 보완:\n"
                        "1. `skipXss` 기본값을 `false`로 설정하여 전체 요청에 필터 적용\n"
                        "2. `multipart/form-data` 요청에 `multipartFilter` 설정 추가\n"
                        "3. JSON `Content-Type` 요청 처리 여부 확인 및 보완"
                    )
                else:
                    rec = (
                        "전역 XSS 필터 적용 강화:\n"
                        "1. Lucy XSS Filter 또는 OWASP AntiSamy 전역 적용\n"
                        "2. 모든 Content-Type 요청 커버 여부 확인\n"
                        "3. 소비자 측 출력 인코딩 병행 적용"
                    )
            else:  # 수동확인필요
                subcategory = "Reflected XSS"
                llm_note = _xss_llm_note("수동확인필요")
                gj = xss_group_map.get("수동확인필요", {})
                llm_j = gj.get("judgment", "")
                if llm_j == "양호":
                    title = f"XSS 수동확인 LLM 검토 완료 — Reflected/View XSS ({len(eps)}건) [양호]"
                else:
                    title = f"XSS 수동 확인 필요 — Reflected/View XSS ({len(eps)}건)"
                desc = (
                    f"URL 파라미터·헤더를 통한 입력이 View 또는 응답에 반영될 가능성이 있는 "
                    f"**{len(eps)}개 엔드포인트**입니다. "
                    "XSS 필터 적용 여부 및 출력 인코딩을 수동으로 확인해야 합니다.\n\n"
                    "**주요 패턴:** JSP View 반환 또는 파라미터를 응답에 직접 포함하는 핸들러."
                    + llm_note
                )
                rec = ("각 엔드포인트에서 사용자 입력이 View/응답에 반영되는 지점을 확인하고 "
                       "JSTL `<c:out>`, Spring `HtmlUtils.htmlEscape()` 등으로 출력 인코딩을 적용하십시오.")

            # 대표 케이스: taint 확인된 EP 우선 선택, 없으면 첫 번째 EP
            _taint_eps_local = [
                ep for ep in eps
                if isinstance(ep.get("phase_details", {}).get("phase5_persistent"), dict)
                and ep["phase_details"]["phase5_persistent"].get("taint_result", {}).get("taint_confirmed")
            ]
            rep = _taint_eps_local[0] if _taint_eps_local else eps[0]
            rep_flow: list[str] = []
            ph = rep.get("phase_details", {})
            if isinstance(ph, dict):
                p1 = ph.get("phase1_controller", {})
                if isinstance(p1, dict):
                    ct = p1.get("controller_type", "")
                    ret = p1.get("return_type", "")
                    if ct:
                        rep_flow.append(f"[컨트롤러] type={ct}, return={ret}")
                p5 = ph.get("phase5_persistent", {})
                if isinstance(p5, dict) and p5:
                    tr = p5.get("taint_result", {})
                    if isinstance(tr, dict) and tr.get("taint_confirmed") and tr.get("call_chain"):
                        chain_str = " → ".join(tr["call_chain"])
                        rep_flow.append(f"[DB 저장 경로] {chain_str}")
                        rep_flow.append(f"[판정] {tr.get('reason', '')[:200]}")
                    else:
                        reason = p5.get("reason", "")
                        if reason:
                            rep_flow.append(f"[Phase5 Persistent] {reason[:200]}")
            diag = rep.get("diagnosis_detail", "")
            if diag and not rep_flow:
                rep_flow.append(f"[판정] {diag[:200]}")

            rep_code, rep_before, rep_after = _find_method_in_file(
                source_dir, rep.get("process_file", ""),
                rep.get("handler", "").split(".")[-1] if rep.get("handler") else "",
                rep.get("request_mapping", "")
            )
            # Persistent XSS: rep_code 추출 실패 시 LLM taint_evidence Controller→Service 코드 사용
            # (전역 필터 없음 증적은 finding-2-1에서 담당 → Persistent XSS finding은 DB 저장 경로 증적 우선)
            if not rep_code and xss_cat == "잠재적위협" and llm_supp_data:
                for _lf in llm_supp_data.get("findings", []):
                    _te_list = _lf.get("taint_evidence", [])
                    if not _te_list:
                        continue
                    _te = _te_list[0]
                    _ctrl_snippet = _te.get("controller_snippet", "").strip()
                    _ctrl_file    = _te.get("controller_file", "")
                    _ctrl_lines   = _te.get("controller_lines", "")
                    _svc_snippet  = _te.get("service_snippet", "").strip()
                    _svc_file     = _te.get("service_file", "")
                    _svc_lines    = _te.get("service_lines", "")
                    if _ctrl_snippet or _svc_snippet:
                        _parts: list[str] = []
                        if _ctrl_snippet:
                            _clabel = _ctrl_file.split("/")[-1] + (f" (lines {_ctrl_lines})" if _ctrl_lines else "")
                            _parts.append(f"// [Controller] {_clabel}")
                            _parts.extend(_ctrl_snippet.splitlines())
                        if _svc_snippet:
                            if _parts:
                                _parts.append("")
                            _slabel = _svc_file.split("/")[-1] + (f" (lines {_svc_lines})" if _svc_lines else "")
                            _parts.append(f"// [Service] {_slabel}")
                            _parts.extend(_svc_snippet.splitlines())
                        rep_code = "\n".join(_parts)
                        rep_before = []
                        rep_after  = []
                    break
            # LLM 판정이 양호이고 개별 endpoints_reviewed 중 정보/취약 없으면 → "low"(양호)
            _xss_gj = xss_group_map.get("잠재적위협" if xss_cat == "잠재적위협" else "수동확인필요", {})
            _xss_eps_reviewed = (_xss_gj.get("endpoints_reviewed", [])
                                 + _xss_gj.get("controllers_reviewed", []))
            _has_non_safe = any(e.get("result") in ("정보", "취약") for e in _xss_eps_reviewed)
            _xss_llm_j = _xss_gj.get("judgment", "")
            # 그룹 내 취약 판정 EP가 있으면 severity를 high(→취약)으로 상향
            _group_has_vuln = any(e.get("result") == "취약" for e in eps)
            if _xss_llm_j == "양호" and not _has_non_safe:
                _ep_severity = "low"
            elif _group_has_vuln or _xss_llm_j == "취약":
                _ep_severity = "high"
            else:
                _ep_severity = "info"

            # Persistent XSS: persistent_xss_revision이 있으면 EP별 행 분리 데이터 생성
            _ep_expansion: dict = {}
            if xss_cat == "잠재적위협":
                _pxss_rev = raw.get("summary", {}).get("persistent_xss_revision", {})
                if isinstance(_pxss_rev, dict) and _pxss_rev.get("upgraded_to_vuln"):
                    _confirmed = _pxss_rev["upgraded_to_vuln"]
                    _all_diag = raw.get("endpoint_diagnoses", [])
                    _vuln_eps = [ep for ep in _all_diag if ep.get("persistent_xss") == "취약"]
                    _info_eps = [ep for ep in _all_diag if ep.get("persistent_xss") == "정보"]
                    _ep_expansion = {
                        "vuln_instances": [
                            {"file": ep.get("process_file", ""), "endpoint": ep.get("request_mapping", "")}
                            for ep in _vuln_eps[:_confirmed]
                        ],
                        "info_instances": [
                            {"file": ep.get("process_file", ""), "endpoint": ep.get("request_mapping", "")}
                            for ep in (_vuln_eps[_confirmed:] + _info_eps)
                        ],
                    }
                    _ep_severity = "info"  # 숨기지 않고 테이블에 EP별 행으로 전개

            findings.append(Finding(
                id=f"{cat_info['number']}-EP{g_idx}",
                title=title,
                severity=_ep_severity,
                category=cat_info["name"],
                subcategory=subcategory,
                description=desc,
                file=rep.get("process_file", "") if eps else "",
                line=0,
                endpoint=rep.get("request_mapping", ""),
                code_snippet=rep_code,
                context_before=rep_before,
                context_after=rep_after,
                recommendation=rec,
                evidence_type="code" if rep_code else "description",
                flow=rep_flow,
                instances=instances,
                is_supplemental=False,
                from_ep_group=True,
                ep_expansion=_ep_expansion,
            ))

    return category, findings


def _collect_supplemental_paths(finding_files: list[Path],
                                page_map_path: Path) -> dict[str, list[Path]]:
    """confluence_page_map.json 에서 각 finding 파일의 supplemental_sources 경로를 수집.

    Returns: {str(finding_path): [Path(supp1), Path(supp2), ...]}
    """
    if not page_map_path or not page_map_path.exists():
        return {}

    try:
        page_map = json.loads(page_map_path.read_text(encoding="utf-8"))
    except Exception:
        return {}

    base_dir = page_map_path.parent.parent  # tools/ → playbook root

    # 모든 entries를 평탄화
    def _iter_entries(node):
        for e in node.get("entries", []):
            yield e
        for g in node.get("groups", []):
            yield from _iter_entries(g)

    # finding 파일 경로 집합 (정규화)
    finding_stems = {str(fp.resolve()) for fp in finding_files}

    result: dict[str, list[Path]] = {}
    for entry in _iter_entries(page_map):
        src = entry.get("source", "")
        supp_list = entry.get("supplemental_sources", [])
        if not supp_list:
            continue
        src_abs = str((base_dir / src).resolve())
        if src_abs not in finding_stems:
            continue
        paths = []
        for s in supp_list:
            p = (base_dir / s).resolve()
            if p.exists():
                paths.append(p)
        if paths:
            result[src_abs] = paths

    return result


def generate_task_tree(all_findings: dict[str, list[Finding]]) -> str:
    """진단 항목 분류 ASCII 트리 생성.

    CATEGORY_INFO['items']를 읽어 Task별 하위 진단 항목을 시각화한다.
    실제 finding이 존재하는 Task만 강조(* 표시)하고, 없는 Task는 그대로 출력한다.
    """
    lines: list[str] = [
        "```",
        "🌳 진단 항목 분류 (Task Tree)",
        "Phase 2: 정적 분석",
    ]

    n_tasks = len(_TASK_ORDER)
    for t_idx, (task_label, task_desc, cat_id) in enumerate(_TASK_ORDER):
        is_last_task  = (t_idx == n_tasks - 1)
        task_prefix   = "└──" if is_last_task else "├──"
        child_prefix  = "    " if is_last_task else "│   "

        lines.append(f"{task_prefix} {task_label}: {task_desc}")

        items = list(CATEGORY_INFO[cat_id]["items"].values())
        # 중복 제거 (ssi/ssti 같은 중복 값)
        seen: list[str] = []
        for v in items:
            if v not in seen:
                seen.append(v)
        items = seen

        for i_idx, item_name in enumerate(items):
            is_last_item = (i_idx == len(items) - 1)
            item_prefix  = "└──" if is_last_item else "├──"
            lines.append(f"{child_prefix}{item_prefix} {item_name}")

    lines.append("```")
    return "\n".join(lines)


def generate_stats_matrix(all_findings: dict[str, list[Finding]],
                          scan_summaries: dict[str, dict] | None = None,
                          llm_overrides: dict[tuple[str, str], dict] | None = None) -> str:
    """Task × 세부항목 진단 결과 매트릭스 표 생성.

    findings[]에서 취약/정보/양호 건수를 집계하되,
    scan_summaries가 제공된 경우 스캔 JSON의 summary(endpoint 전수 집계)로
    양호/정보 카운트를 우선 보완한다 (100% 커버리지 증명).
    Task 컬럼은 첫 번째 항목 행에만 표시하고 이후 행은 공백으로 처리한다.
    """
    scan_summaries = scan_summaries or {}

    header = ("| Task | 세부 진단 항목 | 진단 대상 "
              "| 🔴 취약 | 🟡 정보 (수동검토) | 🟢 양호 / 해당없음 |")
    sep    = ("|:-----|:------------|:--------:"
              "|:------:|:-----------------:|:-----------------:|")
    rows: list[str] = [header, sep]

    for task_label, _task_desc, cat_id in _TASK_ORDER:
        findings  = all_findings.get(cat_id, [])
        cat_items = CATEGORY_INFO[cat_id]["items"]
        cat_summary = scan_summaries.get(cat_id, {})

        # 진단 대상 수: endpoint 전수 스캔 task만 표시
        total_ep = cat_summary.get("total_endpoints")
        target_str = f"{total_ep:,} EP" if total_ep else "-"

        # subtype별 카운터 초기화 (중복 제거)
        seen_names: list[str] = []
        for v in cat_items.values():
            if v not in seen_names:
                seen_names.append(v)

        counts: dict[str, dict[str, int]] = {
            name: {"vuln": 0, "info": 0, "safe": 0} for name in seen_names
        }

        # findings에서 정수 단위 집계 (취약/정보/양호 finding 오브젝트)
        for f in findings:
            result, _ = RISK_MAP.get(f.severity, ("정보", 4))
            subcat = f.subcategory
            if subcat not in counts:
                counts[subcat] = {"vuln": 0, "info": 0, "safe": 0}
            key = {"취약": "vuln", "정보": "info", "양호": "safe"}.get(result, "info")
            counts[subcat][key] += 1

        # 스캔 summary 기반 카운트 보완:
        # _SCAN_SUMMARY_STATS에 매핑된 항목은 스캔 JSON의 전수 집계를 사용
        for item_name in seen_names:
            # LLM override가 있으면 scan summary보다 우선 (LLM 최종 판정 반영)
            llm_key = (cat_id, item_name)
            if llm_overrides and llm_key in llm_overrides:
                lo = llm_overrides[llm_key]
                counts[item_name]["safe"] = lo.get("safe", 0)
                counts[item_name]["info"] = lo.get("info", 0)
                counts[item_name]["vuln"] = lo.get("vuln", 0)
            else:
                extractor = _SCAN_SUMMARY_STATS.get((cat_id, item_name))
                if extractor and cat_summary:
                    try:
                        sc = extractor(cat_summary)
                        # 스캔 summary 값이 finding 집계보다 크거나 같으면 override
                        # (finding 집계는 취약/정보 위주이므로 양호는 summary 우선)
                        if sc.get("safe", 0) > counts[item_name]["safe"]:
                            counts[item_name]["safe"] = sc["safe"]
                        if sc.get("info", 0) > counts[item_name]["info"]:
                            counts[item_name]["info"] = sc["info"]
                        if sc.get("vuln", 0) > counts[item_name]["vuln"]:
                            counts[item_name]["vuln"] = sc["vuln"]
                    except Exception:
                        pass
            # 스캔 실행 확인(cat_summary 존재) 후에도 0/0/0이면 양호(safe=1) 표시
            # 스캔이 진행됐고 해당 항목에 아무 발견이 없음 → 양호로 기록
            if cat_summary and counts[item_name] == {"vuln": 0, "info": 0, "safe": 0}:
                counts[item_name]["safe"] = 1

        first_row = True
        for item_name, c in counts.items():
            task_col: str = task_label if first_row else ""
            target_col: str = target_str if first_row else ""
            v: int = c["vuln"]
            i: int = c["info"]
            s: int = c["safe"]
            # 취약/정보 건수가 있으면 굵게 강조
            v_str = f"**{v}**" if v > 0 else "0"
            i_str = f"**{i}**" if i > 0 else "0"
            s_str = f"**{s}**" if s > 0 else "0"
            rows.append(f"| {task_col} | {item_name} | {target_col} | {v_str} | {i_str} | {s_str} |")
            first_row = False

    return "\n".join(rows)


def generate_summary_table(all_findings: dict[str, list[Finding]],
                           scan_summaries: dict[str, dict] | None = None,
                           llm_overrides: dict[tuple[str, str], dict] | None = None) -> str:
    """진단 결과 요약 표 생성 (Task Tree + 매트릭스 표 + 항목별 목록)"""
    lines = []
    if ANCHOR_STYLE == "md2cf":
        lines.append(_anchor("summary-table"))
        lines.append("## summary-table\n")
        lines.append("**2. 종합 진단 결과 요약**\n")
    else:
        lines.append("## 2. 종합 진단 결과 요약\n")
        anchor_line = _anchor("summary-table")
        if anchor_line:
            lines.append(anchor_line)
            lines.append("")

    # ── 진단 항목 분류 트리 ────────────────────────────────────────────────
    lines.append("### 🌳 진단 항목 분류 (Task Tree)\n")
    lines.append(generate_task_tree(all_findings))
    lines.append("")

    # ── Task × 세부항목 매트릭스 표 ──────────────────────────────────────
    lines.append("### 📊 Task별 진단 결과 매트릭스\n")
    lines.append(generate_stats_matrix(
        all_findings, scan_summaries,
        llm_overrides=llm_overrides,
    ))
    lines.append("")

    # ── 항목별 상세 목록 ──────────────────────────────────────────────────
    # '양호' 판정 finding은 매트릭스 집계에만 반영하고 목록에서 제외
    lines.append("### 📋 항목별 상세 목록\n")
    headers = ["No", "점검 구분", "점검 항목", "결과", "위험도", "Request Mapping", "File", "상세"]
    rows: list[list[str]] = []

    # Persistent XSS 기준 anchor (XSS-PERSISTENT-001 등 EP 그룹 기반 아닌 finding)
    _pxss_anchor_id: str = ""
    for _f in all_findings.get("xss", []):
        if (_f.subcategory == "Persistent XSS"
                and not _f.from_ep_group
                and RISK_MAP.get(_f.severity, ("", 0))[0] != "양호"):
            _pxss_anchor_id = f"finding-{_f.id}"
            break

    def _current_max_seq(row_list: list, cat_prefix: str) -> int:
        """rows 리스트에서 특정 카테고리 prefix의 최대 순번 반환"""
        m = 0
        for _r in row_list:
            if _r[0].startswith(cat_prefix + "-"):
                try:
                    m = max(m, int(_r[0][len(cat_prefix) + 1:]))
                except (ValueError, IndexError):
                    pass
        return m

    for category_id, findings in all_findings.items():
        _cat_num = CATEGORY_INFO[category_id]["number"]

        for f in findings:
            result, risk = RISK_MAP.get(f.severity, ("정보", 4))

            # '양호' 항목은 상세 목록에서 제외 (매트릭스 집계에만 포함)
            if result == "양호":
                continue

            # EP expansion: Persistent XSS 그룹 finding → EP별 개별 행으로 전개
            if f.ep_expansion and f.from_ep_group and f.subcategory == "Persistent XSS":
                _base_anchor = _pxss_anchor_id or f"finding-{f.id}"
                _detail_link = f'<a href="#{_base_anchor}">상세</a>'
                # 현재까지 추가된 동일 카테고리 행의 최대 순번 파악
                _seq = _current_max_seq(rows, _cat_num)
                for _inst in f.ep_expansion.get("vuln_instances", []):
                    _seq += 1
                    _ep = f"`{_inst.get('endpoint','')}`" if _inst.get('endpoint') else "-"
                    _fn = _inst.get('file', '').split('/')[-1] if _inst.get('file') else '-'
                    rows.append([f"{_cat_num}-{_seq}", f.category, "Persistent XSS",
                                 "취약", "5", _ep, _fn, _detail_link])
                for _inst in f.ep_expansion.get("info_instances", []):
                    _seq += 1
                    _ep = f"`{_inst.get('endpoint','')}`" if _inst.get('endpoint') else "-"
                    _fn = _inst.get('file', '').split('/')[-1] if _inst.get('file') else '-'
                    rows.append([f"{_cat_num}-{_seq}", f.category, "Persistent XSS",
                                 "정보", "4", _ep, _fn, _detail_link])
                continue  # 그룹 finding 자체 행은 생성하지 않음

            # File 표시: 단건이면 파일명, 다건이면 "{대표 파일명} 외 OO건"
            # 우선순위: log_instances > instances > 콤마 구분 file > 단건 file
            if f.log_instances:
                # SENSITIVE_LOGGING: log_instances 파일 목록 기반
                _rep = f.log_instances[0].get("file", "-")
                _extra = len(f.log_instances) - 1
                file_short = f"{_rep} 외 {_extra}건" if _extra > 0 else _rep
            elif len(f.instances) > 1:
                rep_file = f.file.split("/")[-1] if f.file else (f.instances[0].get("file", "").split("/")[-1] if f.instances else "")
                extra = len(f.instances) - 1
                file_short = f"{rep_file} 외 {extra}건" if rep_file else f"외 {extra}건"
            elif f.file and "," in f.file:
                # 콤마 구분 다중 파일 경로 (예: "a/Foo.java, b/Bar.java, c/Baz.java")
                _parts = [p.strip() for p in f.file.split(",") if p.strip()]
                _rep = _parts[0].split("/")[-1]
                _extra = len(_parts) - 1
                file_short = f"{_rep} 외 {_extra}건" if _extra > 0 else _rep
            elif f.file:
                _basename = f.file.split("/")[-1]
                # scan artifact(.json) 또는 서술형 문자열이면 affected_endpoints 기반으로 대체
                if _basename.endswith(".json") or "전체 목록" in f.file or "파일 외" in f.file:
                    _eps = f.affected_endpoints
                    if _eps:
                        _ctrl = _eps[0].get("controller", "").split("(")[0].strip()
                        _ctrl = _ctrl.split(" — ")[0].strip()
                        _extra = len(_eps) - 1
                        file_short = f"{_ctrl} 외 {_extra}건" if (_ctrl and _extra > 0) else (_ctrl or _basename)
                    else:
                        file_short = _basename
                else:
                    file_short = _basename
            else:
                file_short = "-"

            # Request Mapping: endpoint 있으면 표시, 없으면 "-"
            endpoint_display = f"`{f.endpoint}`" if f.endpoint else "-"

            # 상세 링크 열 (HTML anchor)
            anchor_id = f"finding-{f.id}"
            detail_link = f'<a href="#{anchor_id}">상세</a>'

            rows.append([
                f.id, f.category, f.subcategory,
                _colored_result(result), str(risk),
                endpoint_display, file_short,
                detail_link,
            ])

    if ANCHOR_STYLE == "md2cf":
        lines.append(_html_table(headers, rows))
        lines.append("")
    else:
        lines.append("| No | 점검 구분 | 점검 항목 | 결과 | 위험도 | Request Mapping | File | 상세 |")
        lines.append("|:--:|:-------:|:-------:|:---:|:-----:|:----------------|:-----|:----:|")
        for row in rows:
            fid = row[0]
            lines.append(
                f"| {row[0]} | {row[1]} | {row[2]} | {row[3]} | {row[4]} | "
                f"{row[5]} | {row[6]} | {_anchor_link(f'finding-{fid}', '상세')} |"
            )
        lines.append("")

    return "\n".join(lines)


def generate_category_detail(category_id: str, findings: list[Finding],
                             source_dir: Path) -> str:
    """카테고리별 상세 보고서 생성.

    '양호' 판정 finding은 매트릭스 집계 대상이지만 상세 섹션에서는 제외한다.
    LLM Override로 하향된 항목이 보고서 본문에 노출되지 않도록 필터링한다.
    """
    cat_info = CATEGORY_INFO[category_id]

    # '취약' / '정보' 항목만 렌더링 대상으로 한정
    # EP expansion finding (from_ep_group + ep_expansion)은 테이블 행으로만 전개되므로 상세 섹션에서 제외
    reportable = [
        f for f in findings
        if RISK_MAP.get(f.severity, ("정보", 4))[0] != "양호"
        and not (f.from_ep_group and f.ep_expansion)
    ]
    if not reportable:
        return ""   # 카테고리 전체가 양호면 섹션 자체 생략

    lines = []

    # 카테고리 헤더
    lines.append(f"### ({cat_info['number']}) {cat_info['name']}\n")

    # 카테고리 요약 표
    lines.append("| No | 취약점 항목 | 현황 | 결과 | 위험도 | 보안 위협 |")
    lines.append("|:--:|:----------|:-----|:---:|:-----:|:---------|")

    for f in reportable:
        result, risk = RISK_MAP.get(f.severity, ("정보", 4))
        # 현황 요약: title 기반 (suffix 제거 후 사용, description 말줄임 없음)
        import re as _re_s
        _title = (f.title or "").strip()
        # "(N건)" suffix 제거
        _title = _re_s.sub(r"\s*\(\d+건\)\s*$", "", _title).strip()
        # "— anything (file.ext)" suffix 제거
        _title = _re_s.sub(
            r"\s*—\s*[^—\n]*?\(\w[\w.]*\.(?:java|kt|xml|json|properties|py)\)\s*$",
            "", _title
        ).strip()
        # "— 설명" suffix: 앞부분이 40자 이하이면 앞부분만 사용 (단, subcategory와 동일해지면 스킵)
        _m = _re_s.match(r"^(.+?)\s*—\s*.+$", _title)
        if _m and len(_m.group(1).strip()) <= 40:
            _candidate = _m.group(1).strip()
            if _candidate != (f.subcategory or "").strip():
                _title = _candidate
        # title이 subcategory와 동일(너무 일반적)이면 description 첫 문장 fallback
        if not _title or _title == (f.subcategory or "").strip():
            _desc_raw = (f.description or "").strip().split('\n')[0]
            _title = _desc_raw.split('. ')[0] if '. ' in _desc_raw else _desc_raw
        status = _title or "-"
        if not status:
            status = "-"

        lines.append(
            f"| {f.id} | {f.subcategory} | {status} | {_colored_result(result)} | {risk} | {cat_info['threat']} |"
        )

    lines.append("")

    # 각 취약점 상세
    for f in reportable:
        result, risk = RISK_MAP.get(f.severity, ("정보", 4))

        finding_label = "취약점"
        lines.append(f"---\n")
        if ANCHOR_STYLE == "md2cf":
            lines.append(_anchor(f"finding-{f.id}"))
            lines.append(f"#### finding-{f.id}\n")
            # 색상 span을 위해 <strong> HTML 직접 출력 (** 안에 <span> 넣으면 파싱 충돌)
            _result_colored = _colored_result(result)
            lines.append(
                f"<strong>＊ {finding_label} {f.id} {f.subcategory} ({_result_colored})</strong>\n"
            )
        else:
            lines.append(_anchor(f"finding-{f.id}"))
            lines.append(f"#### ＊ {finding_label} {f.id} {f.subcategory} ({result})\n")

        # 영향 받는 엔드포인트/파일 (단순 단일 표시)
        if not f.affected_endpoints:
            # affected_endpoints 목록이 없을 때만 단일 endpoint/file 표시
            if f.endpoint:
                lines.append(f"**영향 받는 API:** `{f.endpoint}`\n")
        if f.file:
            file_display = f.file
            if f.line:
                file_display += f":{f.line}"
            lines.append(f"**파일:** `{file_display}`\n")

        # ── expand 섹션: 로그 내 정보 노출이면 파일 목록, 그 외 API 엔드포인트 목록 ─────────
        if f.log_instances:
            # SENSITIVE_LOGGING: 취약 파일 및 노출 민감정보 목록
            _li_cnt = len(f.log_instances)
            _title  = f"취약 파일 및 노출 민감정보 목록 ({_li_cnt}건)"
            if ANCHOR_STYLE == "md2cf":
                rows_html = []
                for li in f.log_instances:
                    fname_disp = f"<code>{li.get('file', '-')}</code>"
                    sdata_disp = li.get("sensitive_data", "-")
                    snip_disp  = f"<code>{li.get('snippet', '-')[:120]}</code>"
                    rows_html.append(
                        f"<tr><td>{fname_disp}</td><td>{sdata_disp}</td><td>{snip_disp}</td></tr>"
                    )
                table_html = (
                    "<table><tbody>"
                    "<tr><th>파일명</th><th>노출 민감정보</th><th>로그 코드(대표)</th></tr>"
                    + "".join(rows_html)
                    + "</tbody></table>"
                )
                lines.append(
                    '<ac:structured-macro ac:name="expand">'
                    f'<ac:parameter ac:name="title">{_title} — 펼치기</ac:parameter>'
                    f'<ac:rich-text-body>{table_html}</ac:rich-text-body>'
                    '</ac:structured-macro>'
                )
                lines.append("")
            else:
                lines.append("<details>")
                lines.append(f"<summary><strong>{_title}</strong></summary>\n")
                lines.append("| 파일명 | 노출 민감정보 | 로그 코드(대표) |")
                lines.append("|:-------|:-------------|:----------------|")
                for li in f.log_instances:
                    _fn = f"`{li.get('file', '-')}`"
                    _sd = li.get("sensitive_data", "-")
                    _sn = f"`{li.get('snippet', '-')[:80]}`"
                    lines.append(f"| {_fn} | {_sd} | {_sn} |")
                lines.append("\n</details>\n")

        elif f.affected_endpoints:
            # 그 외: 영향 받는 API 엔드포인트 목록
            _ep_cnt = len(f.affected_endpoints)
            _title  = f"영향 받는 API 엔드포인트 ({_ep_cnt}건)"
            if ANCHOR_STYLE == "md2cf":
                rows_html = []
                for ep in f.affected_endpoints:
                    m_disp   = f"<code>{ep['method']}</code>"  if ep.get("method")      else "-"
                    p_disp   = f"<code>{ep['path']}</code>"    if ep.get("path")        else "-"
                    c_disp   = f"<code>{ep['controller']}</code>" if ep.get("controller") else "-"
                    d_disp   = ep.get("description", "") or "-"
                    rows_html.append(
                        f"<tr><td>{m_disp}</td><td>{p_disp}</td>"
                        f"<td>{c_disp}</td><td>{d_disp}</td></tr>"
                    )
                table_html = (
                    "<table><tbody>"
                    "<tr><th>Method</th><th>Endpoint</th><th>Controller</th><th>설명</th></tr>"
                    + "".join(rows_html)
                    + "</tbody></table>"
                )
                expand_macro = (
                    '<ac:structured-macro ac:name="expand">'
                    f'<ac:parameter ac:name="title">{_title} — 펼치기</ac:parameter>'
                    f'<ac:rich-text-body>{table_html}</ac:rich-text-body>'
                    '</ac:structured-macro>'
                )
                lines.append(expand_macro)
                lines.append("")
            else:
                lines.append("<details>")
                lines.append(f"<summary><strong>{_title}</strong></summary>\n")
                lines.append("| Method | Endpoint | Controller | 설명 |")
                lines.append("|:------:|:---------|:-----------|:-----|")
                for ep in f.affected_endpoints:
                    _m = f"`{ep['method']}`" if ep.get("method") else "-"
                    _p = f"`{ep['path']}`"   if ep.get("path")   else "-"
                    _c = f"`{ep['controller']}`" if ep.get("controller") else "-"
                    _d = ep.get("description", "") or "-"
                    lines.append(f"| {_m} | {_p} | {_c} | {_d} |")
                lines.append("\n</details>\n")

        if len(f.instances) > 1:
            if ANCHOR_STYLE == "md2cf":
                # Confluence Expand 매크로: 영향 받는 전체 API/파일 목록 펼치기
                rows_html = []
                for i_num, inst in enumerate(f.instances, 1):
                    inst_ep   = inst.get("endpoint", "") or inst.get("file", "") or "-"
                    inst_file = (inst.get("file", "") or "-").split("/")[-1]
                    inst_ep_disp = f"<code>{inst_ep}</code>" if inst_ep != "-" else "-"
                    rows_html.append(
                        f"<tr><td>{i_num}</td><td>{inst_ep_disp}</td>"
                        f"<td><code>{inst_file}</code></td></tr>"
                    )
                table_html = (
                    "<table><tbody>"
                    "<tr><th>No</th><th>Request Mapping / 파일</th><th>파일명</th></tr>"
                    + "".join(rows_html)
                    + "</tbody></table>"
                )
                expand_macro = (
                    '<ac:structured-macro ac:name="expand">'
                    f'<ac:parameter ac:name="title">영향 받는 전체 목록 ({len(f.instances)}건) — 펼치기</ac:parameter>'
                    f'<ac:rich-text-body>{table_html}</ac:rich-text-body>'
                    '</ac:structured-macro>'
                )
                lines.append(expand_macro)
                lines.append("")
            else:
                lines.append(f"**전체 인스턴스 목록:** {_anchor_link('appendix-instances', '부록 참조')}\n")
                preview = f.instances[:10]
                preview_items = []
                for inst in preview:
                    inst_file = inst.get("file", "-") or "-"
                    inst_line = inst.get("line", "-") or "-"
                    preview_items.append(f"`{inst_file}:{inst_line}`")
                suffix = f", ...외 {len(f.instances) - 10}개" if len(f.instances) > 10 else ""
                lines.append(f"**관련 파일(상위 10개):** {', '.join(preview_items)}{suffix}\n")

        # 취약점 설명
        lines.append(f"**설명:**\n")
        lines.append(f"{f.description}\n")

        # 코드 흐름
        if f.flow:
            lines.append("**코드 흐름:**\n")
            if isinstance(f.flow, list):
                for step in f.flow:
                    lines.append(f"- {step}")
                lines.append("")
            else:
                lines.append(f"{f.flow}\n")

        # 코드 증적
        if f.code_snippet or f.context_before or f.context_after:
            lines.append(f"\n**코드 증적:**\n")
            # language hint based on file extension
            lang = "text"
            if f.file:
                ext = Path(f.file).suffix.lower()
                if ext == ".kt":
                    lang = "kotlin"
                elif ext == ".java":
                    lang = "java"
                elif ext in [".yml", ".yaml"]:
                    lang = "yaml"
                elif ext == ".json":
                    lang = "json"
                elif ext == ".xml":
                    lang = "xml"
                elif ext == ".properties":
                    lang = "properties"
                elif ext in [".sql"]:
                    lang = "sql"
            lines.append(f"```{lang}")

            title_marker = ""
            if f.file:
                file_display = f.file
                if f.line:
                    file_display += f":{f.line}"
                title_marker = f"FILE: {file_display}"
                lines.append(title_marker)

            # 라인 번호 계산
            start_line = max(1, f.line - len(f.context_before)) if f.line else 1

            for i, ctx_line in enumerate(f.context_before):
                lines.append(f"{start_line + i:4d} │ {ctx_line}")

            if f.code_snippet:
                highlight_line = start_line + len(f.context_before)
                lines.append(f"{highlight_line:4d} │ {f.code_snippet}  // ◀ 취약 지점")

            for i, ctx_line in enumerate(f.context_after):
                after_line = highlight_line + 1 + i if f.code_snippet else start_line + len(f.context_before) + i
                lines.append(f"{after_line:4d} │ {ctx_line}")

            lines.append("```\n")

        # 대응 방안
        if f.recommendation:
            lines.append(f"**대응 방안:**\n")
            lines.append(f"{f.recommendation}\n")

        if ANCHOR_STYLE == "html":
            lines.append("**요약으로 돌아가기:** 진단 결과 요약\n")
        else:
            lines.append("**요약으로 돌아가기:** [진단 결과 요약](#summary-table)\n")
        lines.append("")

    return "\n".join(lines)


def generate_instance_appendix(all_findings: dict[str, list[Finding]]) -> str:
    """인스턴스 상세 목록 부록 생성 (다중 위치이고 양호가 아닌 항목만)"""
    lines = []
    appendix_items = []
    for category_id, findings in all_findings.items():
        for f in findings:
            if len(f.instances) > 1 and RISK_MAP.get(f.severity, ("정보", 4))[0] != "양호":
                appendix_items.append(f)

    if not appendix_items:
        return ""

    if ANCHOR_STYLE == "md2cf":
        lines.append(_anchor("appendix-instances"))
        lines.append("## appendix-instances\n")
        lines.append("**4. 부록: 인스턴스 상세 목록**\n")
    else:
        lines.append("## 4. 부록: 인스턴스 상세 목록\n")
        anchor_line = _anchor("appendix-instances")
        if anchor_line:
            lines.append(anchor_line)
    for f in appendix_items:
        lines.append(f"### {f.id} {f.subcategory}\n")
        lines.append("| File | Line | Endpoint |")
        lines.append("|:-----|:----:|:---------|")
        for inst in f.instances:
            inst_file = inst.get("file", "-") or "-"
            inst_line = inst.get("line", "-") or "-"
            inst_endpoint = inst.get("endpoint", "-") or "-"
            lines.append(f"| `{inst_file}` | {inst_line} | `{inst_endpoint}` |")
        lines.append("")
    if ANCHOR_STYLE == "html":
        lines.append("**요약으로 돌아가기:** 진단 결과 요약\n")
    else:
        lines.append("**요약으로 돌아가기:** [진단 결과 요약](#summary-table)\n")

    return "\n".join(lines)


def _render_asset_info_section(asset_info: dict) -> list[str]:
    """task_11_result.json 데이터를 서비스 설명 + 자산 구조 Markdown으로 변환."""
    lines = []
    findings = asset_info.get("findings", [])
    if not findings:
        return lines

    first = findings[0]

    # 서비스 설명
    service_detail = first.get("service_detail") or first.get("asset_name", "")
    purpose = first.get("purpose", "")
    framework = first.get("framework", "")
    tech_stack = first.get("tech_stack", [])
    build_tool = first.get("build_tool", "")
    repo_url = first.get("repository_url", "")
    biz_owner = first.get("biz_owner", "")
    dev_owner = first.get("dev_owner", "")
    was_version = first.get("was_version", "")
    language_version = first.get("language_version", "")

    lines.append("### 1.1 서비스 정보\n")
    rows = []
    if service_detail:
        rows.append(["서비스 설명", service_detail])
    if purpose:
        rows.append(["용도", purpose])
    if framework:
        rows.append(["프레임워크", framework])
    if tech_stack:
        rows.append(["기술 스택", ", ".join(tech_stack)])
    if build_tool:
        rows.append(["빌드 도구", build_tool])
    if language_version:
        rows.append(["언어 버전", language_version])
    if was_version:
        rows.append(["WAS", was_version])
    if repo_url:
        rows.append(["소스 레포", repo_url])
    if biz_owner:
        rows.append(["기획 담당자", biz_owner])
    if dev_owner:
        rows.append(["개발 담당자", dev_owner])

    lines.append("| 항목 | 내용 |")
    lines.append("|------|------|")
    for k, v in rows:
        lines.append(f"| {k} | {v} |")
    lines.append("")

    # 자산 구조 표 (환경별)
    lines.append("### 1.2 자산 구조\n")
    lines.append("| 환경 | 노출 | 도메인 | 포트 | 담당자(개발) |")
    lines.append("|------|------|--------|------|------------|")
    for asset in findings:
        env = asset.get("environment", "")
        exposure = asset.get("exposure", "")
        domain_val = asset.get("domain", "")
        ports = asset.get("ports", [])
        ports_str = ", ".join(str(p) for p in ports) if ports else ""
        owner = asset.get("dev_owner", "")
        lines.append(f"| {env} | {exposure} | {domain_val} | {ports_str} | {owner} |")
    lines.append("")

    return lines


def _parse_versioned_dir(source_dir: Path) -> tuple[str | None, str | None]:
    """
    '{slug}@{branch}@{commit}' 형식의 디렉토리명에서 branch/commit 자동 파싱.
    반환: (branch, commit) — 파싱 실패 시 (None, None).
    """
    name = source_dir.name
    parts = name.split("@")
    if len(parts) >= 3:
        branch = parts[-2]
        commit = parts[-1]
        return branch, commit
    return None, None


def _load_fetch_meta(source_dir: Path) -> dict:
    """source_dir/.fetch_meta.json 로드. 없으면 빈 dict."""
    meta_path = source_dir / ".fetch_meta.json"
    if meta_path.exists():
        try:
            return json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def generate_report(
    source_dir: Path,
    finding_files: list[Path],
    output_file: Path,
    service_name: str,
    target_modules: list[str] = None,
    repo: str | None = None,
    branch: str | None = None,
    commit: str | None = None,
    maintainers: list[str] | None = None,
    domain: str | None = None,
    source_label: str | None = None,
    anchor_style: str | None = None,
    page_map_path: Path | None = None,
    asset_info_path: Path | None = None,
):
    """최종 보고서 생성"""
    global ANCHOR_STYLE
    if anchor_style:
        ANCHOR_STYLE = anchor_style

    today = date.today().strftime("%Y.%m.%d")

    # .fetch_meta.json 자동 로드 (fetch_bitbucket.py가 기록한 메타정보)
    fetch_meta = _load_fetch_meta(source_dir)

    # branch/commit: 명시 인자 → fetch_meta → 디렉토리명 파싱 순으로 우선순위
    auto_branch, auto_commit = _parse_versioned_dir(source_dir)
    branch = branch or fetch_meta.get("branch") or auto_branch
    commit = commit or fetch_meta.get("commit") or auto_commit

    # 담당자: 명시 인자 → fetch_meta contributors
    if not maintainers:
        maintainers = fetch_meta.get("contributors") or []

    if branch or commit:
        print(f"  소스 버전: branch={branch}, commit={commit}")
    if maintainers:
        print(f"  담당자: {', '.join(maintainers)}")

    # 자산 정보 로드 (task_11_result.json)
    asset_info: dict | None = None
    if asset_info_path and asset_info_path.exists():
        with open(asset_info_path, encoding="utf-8") as f:
            asset_info = json.load(f)
        print(f"  자산정보 로드: {asset_info_path.name}")

    # Findings 로드 + 스캔 JSON summary 수집 (endpoint 전수 통계용)
    all_findings: dict[str, list[Finding]] = {}
    scan_summaries: dict[str, dict] = {}  # category_id -> summary dict
    for fpath in finding_files:
        category, findings = load_findings(fpath, source_dir)
        if category not in all_findings:
            all_findings[category] = []
        all_findings[category].extend(findings)
        print(f"  {fpath.name}: {len(findings)}건 ({category})")
        # 스캔 JSON summary 추출 (task22/23: endpoint_diagnoses 기반, task24/25: upload_diagnoses 등)
        try:
            raw = json.loads(fpath.read_text(encoding="utf-8"))
            if "summary" in raw:
                summary = dict(raw["summary"])
                # scan_metadata 보존 (DOM XSS dom_xss_scan 등 sub-scan 통계)
                if "scan_metadata" in raw:
                    summary["_scan_metadata"] = raw["scan_metadata"]
                scan_summaries[category] = summary
        except Exception:
            pass

    # supplemental_sources 병합 (page_map 기반) — 범용 ID Override + Append 방식
    # 모든 카테고리(22~25)에 동일 로직 적용:
    #   · supplemental finding의 original_id가 원본 finding의 original_id와 일치 → Override (in-place 교체)
    #   · 일치하는 ID 없음 → Append (신규 발견, 연속 순번 부여)
    # Override 후 통계/매트릭스는 병합된 all_findings 기준으로 자동 재계산됨
    supp_map = _collect_supplemental_paths(finding_files, page_map_path)
    if supp_map:
        print("\n  [LLM 수동분석 보완 병합 — Override+Append]")
        for src_abs, supp_paths in supp_map.items():
            for sp in supp_paths:
                try:
                    s_category, s_findings = load_findings(sp, source_dir, is_supplemental=True)
                except Exception as e:
                    print(f"  Warning: {sp.name} 로드 실패: {e}")
                    continue
                if not s_findings:
                    continue
                if s_category not in all_findings:
                    all_findings[s_category] = []

                existing = all_findings[s_category]
                cat_num  = CATEGORY_INFO[s_category]["number"]

                # ── Category-Replace: LLM 보완 finding의 scan_category 수집 ──
                # LLM 보완 파일(is_supplemental=True)의 scan_category가 auto-scan 결과와
                # 겹치면 해당 scan_category의 auto-scan finding 전체를 LLM 결과로 교체.
                # 예) SENSITIVE_LOGGING 27건 → 운영/개발로그 2건으로 그룹화 교체
                supp_scan_cats = {sf.scan_category for sf in s_findings if sf.scan_category}
                replaced_cats: set[str] = set()
                removed_count = 0
                if supp_scan_cats:
                    before_len = len(existing)
                    existing[:] = [
                        f for f in existing
                        if f.scan_category not in supp_scan_cats
                    ]
                    removed_count = before_len - len(existing)
                    replaced_cats = supp_scan_cats if removed_count > 0 else set()

                # 남은 existing finding의 마지막 순번 재계산
                max_seq = 0
                for f in existing:
                    try:
                        max_seq = max(max_seq, int(f.id.split("-")[-1]))
                    except (ValueError, IndexError):
                        pass

                # original_id → list index 역색인 (override 위치 탐색용, category-replace 후)
                orig_id_index: dict[str, int] = {
                    f.original_id: i
                    for i, f in enumerate(existing)
                    if f.original_id
                }

                overridden = 0
                appended   = 0
                for sf in s_findings:
                    if sf.original_id and sf.original_id in orig_id_index:
                        # ── Override: display ID 유지, 나머지 필드 LLM 결과로 교체 ──
                        idx_in_list = orig_id_index[sf.original_id]
                        sf.id = existing[idx_in_list].id   # display ID(e.g. "1-3") 보존
                        existing[idx_in_list] = sf
                        overridden += 1
                    else:
                        # ── Append / Category-Replace insert: 연속 순번 부여 ──
                        max_seq += 1
                        sf.id = f"{cat_num}-{max_seq}"
                        existing.append(sf)
                        if sf.original_id:
                            orig_id_index[sf.original_id] = len(existing) - 1
                        appended += 1

                _replace_info = f", cat-replace={removed_count}건 제거({','.join(sorted(replaced_cats))})" if replaced_cats else ""
                print(
                    f"  {sp.name}: {len(s_findings)}건 ({s_category}) ★보완"
                    f" [override={overridden}, append={appended}{_replace_info}]"
                )

    # endpoint_diagnoses 기반 그룹 Finding 병합 (정보 엔드포인트 → 보고서 항목화)
    ep_group_files = [fp for fp in finding_files
                      if "endpoint_diagnoses" in
                      json.loads(fp.read_text(encoding="utf-8") if fp.exists() else "{}")]
    if ep_group_files:
        print("\n  [endpoint 정보 그룹 Finding 병합]")
    for fpath in ep_group_files:
        # supplemental LLM 데이터 로드 (sqli_endpoint_review / xss_endpoint_review 활용)
        llm_supp: dict | None = None
        for sp in supp_map.get(str(fpath.resolve()), []):
            try:
                sp_data = json.loads(sp.read_text(encoding="utf-8"))
                if sp_data.get("sqli_endpoint_review") or sp_data.get("xss_endpoint_review"):
                    llm_supp = sp_data
                    break
            except Exception:
                pass
        ep_category, ep_findings = load_endpoint_group_findings(
            fpath, source_dir, llm_supp_data=llm_supp
        )
        if not ep_findings:
            continue
        if ep_category not in all_findings:
            all_findings[ep_category] = []
        existing_ids = {f.id for f in all_findings[ep_category]}
        cat_num = CATEGORY_INFO[ep_category]["number"]
        max_seq = 0
        for eid in existing_ids:
            try:
                max_seq = max(max_seq, int(eid.split("-")[-1]))
            except (ValueError, IndexError):
                pass
        for ef in ep_findings:
            max_seq += 1
            ef.id = f"{cat_num}-{max_seq}"
            existing_ids.add(ef.id)
        all_findings[ep_category].extend(ep_findings)
        print(f"  {fpath.name}: {len(ep_findings)}건 ({ep_category}) endpoint 그룹")

    # LLM 최종 카운트 계산 — supplemental endpoint reviews → matrix override
    llm_matrix_overrides: dict[tuple[str, str], dict] = {}
    for _supp_paths in supp_map.values():
        for sp in _supp_paths:
            try:
                sp_data = json.loads(sp.read_text(encoding="utf-8"))
            except Exception:
                continue
            sqli_rev = sp_data.get("sqli_endpoint_review", {})
            if sqli_rev and sqli_rev.get("overall_sqli_judgment") == "양호":
                auto_sqli = scan_summaries.get("injection", {}).get("sqli", {})
                # endpoint_summary.정보 값이 있으면 사용 (LLM 최종 잔여 정보 건수)
                ep_sum = sp_data.get("endpoint_summary", {})
                llm_info_count = ep_sum.get("정보", 0) if isinstance(ep_sum, dict) else 0
                llm_matrix_overrides[("injection", "SQL 인젝션")] = {
                    "safe": auto_sqli.get("양호", 0) + auto_sqli.get("정보", 0) - llm_info_count,
                    "info": llm_info_count,
                    "vuln": auto_sqli.get("취약", 0),
                }
            gfa = sp_data.get("global_findings_analysis", {})
            os_entries = gfa.get("os_command", []) if isinstance(gfa.get("os_command"), list) else []
            if os_entries:
                # 개별 finding 단위로 카운팅 (global_findings_analysis는 그룹 집계라 1건으로 처리됨)
                llm_os_f = [f for f in sp_data.get("findings", [])
                            if any(k in f.get("category", "").lower()
                                   for k in ("os command", "groovy", "rce", "stored rce"))]
                llm_matrix_overrides[("injection", "OS Command 인젝션")] = {
                    "safe": sum(1 for f in llm_os_f if f.get("result") == "양호"),
                    "info": sum(1 for f in llm_os_f if f.get("result") == "정보"),
                    "vuln": sum(1 for f in llm_os_f if f.get("result") == "취약"),
                }
            xss_rev = sp_data.get("xss_endpoint_review", {})
            if xss_rev:
                auto_xss_sum = scan_summaries.get("xss", {})
                per_t = auto_xss_sum.get("per_type", {})
                html_view_safe_count = 0  # HTML_VIEW 그룹 양호 확인 → Reflected 중복 집계 보정용
                for gj in xss_rev.get("group_judgments", []):
                    gname = gj.get("group", "")
                    judgment = gj.get("judgment", "")
                    eps = gj.get("endpoints_reviewed", []) + gj.get("controllers_reviewed", [])
                    if "잠재적위협" in gname and judgment in ("양호", "정보", "취약"):
                        pt = per_t.get("persistent_xss", {}) if isinstance(per_t.get("persistent_xss"), dict) else {}
                        # persistent_xss_revision이 있으면 LLM taint 확인 기반 수치 우선 사용
                        _pxss_rev = auto_xss_sum.get("persistent_xss_revision", {})
                        if isinstance(_pxss_rev, dict) and _pxss_rev.get("upgraded_to_vuln"):
                            _confirmed = _pxss_rev["upgraded_to_vuln"]
                            _auto_vuln = pt.get("취약", 0)
                            llm_matrix_overrides[("xss", "Persistent XSS")] = {
                                "safe": pt.get("양호", 0) + pt.get("해당없음", 0),
                                "info": pt.get("정보", 0) + max(0, _auto_vuln - _confirmed),
                                "vuln": _confirmed,
                            }
                        elif judgment == "양호":
                            # LLM이 잠재위협 전체를 양호로 확인 → 취약 → 양호로 이동
                            llm_matrix_overrides[("xss", "Persistent XSS")] = {
                                "safe": pt.get("양호", 0) + pt.get("해당없음", 0) + pt.get("취약", 0),
                                "info": pt.get("정보", 0),
                                "vuln": 0,
                            }
                        elif judgment == "정보":
                            # LLM이 취약 → 정보(Entry Point 경고)로 재판정 → 취약 건수를 정보로 이동
                            llm_matrix_overrides[("xss", "Persistent XSS")] = {
                                "safe": pt.get("양호", 0) + pt.get("해당없음", 0),
                                "info": pt.get("정보", 0) + pt.get("취약", 0),
                                "vuln": 0,
                            }
                        else:  # judgment == "취약": auto-scan 수치 유지
                            llm_matrix_overrides[("xss", "Persistent XSS")] = {
                                "safe": pt.get("양호", 0) + pt.get("해당없음", 0),
                                "info": pt.get("정보", 0),
                                "vuln": pt.get("취약", 0),
                            }
                    elif "HTML_VIEW" in gname:
                        pt = per_t.get("view_xss", {}) if isinstance(per_t.get("view_xss"), dict) else {}
                        if eps:
                            # HTML_VIEW 양호 확인된 건수: view_xss.정보 (reflected_xss.정보에 중복 집계됨)
                            if judgment == "양호":
                                html_view_safe_count = pt.get("정보", 0)
                            llm_matrix_overrides[("xss", "View XSS")] = {
                                "safe": sum(1 for e in eps if e.get("result") == "양호") + pt.get("양호", 0) + pt.get("해당없음", 0),
                                "info": sum(1 for e in eps if e.get("result") == "정보"),
                                "vuln": sum(1 for e in eps if e.get("result") == "취약") + pt.get("취약", 0),
                            }
                    elif "Reflected" in gname or "text/html" in gname:
                        pt = per_t.get("reflected_xss", {}) if isinstance(per_t.get("reflected_xss"), dict) else {}
                        if eps:
                            # html_view_safe_count: HTML_VIEW 양호 확인 건수 (reflected_xss.정보에 중복 포함된 분)
                            llm_matrix_overrides[("xss", "Reflected XSS")] = {
                                "safe": sum(1 for e in eps if e.get("result") == "양호") + html_view_safe_count + pt.get("양호", 0) + pt.get("해당없음", 0),
                                "info": sum(1 for e in eps if e.get("result") == "정보"),
                                "vuln": sum(1 for e in eps if e.get("result") == "취약") + pt.get("취약", 0),
                            }
            # DOM XSS: LLM 검토 결과 모두 양호(FP)이면 auto-scan 카운트를 safe으로 override
            dom_llm = [f for f in sp_data.get("findings", [])
                       if "dom" in f.get("category", "").lower()]
            if dom_llm:
                all_dom_safe = all(
                    f.get("result") == "양호" or f.get("severity", "").lower() == "low"
                    for f in dom_llm
                )
                if all_dom_safe:
                    _xss_sm = scan_summaries.get("xss", {})
                    dom_count = (
                        _xss_sm.get("_scan_metadata", {}).get("dom_xss_scan", {}).get("findings_count", 0)
                    )
                    llm_matrix_overrides[("xss", "DOM-based XSS")] = {
                        "safe": dom_count or 1,
                        "info": 0,
                        "vuln": 0,
                    }
            # SSI/SSTI: LLM가 전체 FP 확정(result=양호) 시 → safe=1
            ssi_related = [f for f in sp_data.get("findings", [])
                           if any(k in f.get("category", "").lower()
                                  for k in ("ssi", "ssti", "spel", "server-side"))]
            if ssi_related and all(f.get("result") == "양호" for f in ssi_related):
                auto_ssi_total = scan_summaries.get("injection", {}).get("ssi", {}).get("total", 0)
                if auto_ssi_total <= len(ssi_related):
                    llm_matrix_overrides[("injection", "SSI/SSTI 인젝션")] = {
                        "safe": 1, "info": 0, "vuln": 0,
                    }
            # 데이터보호 assessment 기반 카테고리별 양호 override
            dp_assessment = sp_data.get("data_protection_assessment", {})
            if dp_assessment:
                if dp_assessment.get("weak_crypto_count", -1) == 0:
                    llm_matrix_overrides.setdefault(
                        ("data_protection", "취약한 암호화 알고리즘"), {"safe": 1, "info": 0, "vuln": 0}
                    )
                if dp_assessment.get("cors_wildcard") is False:
                    llm_matrix_overrides.setdefault(
                        ("data_protection", "CORS 설정 미흡"), {"safe": 1, "info": 0, "vuln": 0}
                    )
                if dp_assessment.get("jwt_unsigned_allowed") is False:
                    llm_matrix_overrides.setdefault(
                        ("data_protection", "JWT 취약점"), {"safe": 1, "info": 0, "vuln": 0}
                    )

    # 코드 증적 보완: finding 중 code_snippet 없는 경우, 같은 category 내 코드가 있는 finding에서 차용
    # Pass 1: EP 그룹 finding에서 동일 subcategory 코드 차용
    # Pass 2: 동일 category 내 아무 finding(코드 있는 것) 중 첫 번째 차용 (fallback)
    for cat_id, findings in all_findings.items():
        ep_with_code_by_sub: dict[str, "Finding"] = {
            f.subcategory: f
            for f in findings
            if getattr(f, "from_ep_group", False) and f.code_snippet
        }
        any_with_code = next((f for f in findings if f.code_snippet), None)

        for f in findings:
            if f.code_snippet:
                continue  # 이미 코드 있음
            # Pass 1: EP 그룹에서 동일 subcategory (EP 그룹 finding 자신 제외)
            ref = ep_with_code_by_sub.get(f.subcategory)
            if ref is f:
                ref = None
            # Pass 2: fallback — 동일 subcategory 내 다른 finding (cross-subcategory 차용 금지)
            # 이유: subcategory가 다른 finding의 코드를 차용하면 증적과 파일명이 불일치함
            # 예) "XSS 필터 결함"의 LoggingFilter 코드가 "Persistent XSS"에 차용되는 문제 방지
            if not ref:
                ref = next(
                    (sf for sf in findings
                     if sf is not f and sf.code_snippet and sf.subcategory == f.subcategory),
                    None
                )
            if ref and ref is not f:
                f.code_snippet = ref.code_snippet
                f.context_before = ref.context_before
                f.context_after = ref.context_after
                if not f.file:
                    f.file = ref.file
                    f.line = ref.line
                if not f.flow:
                    f.flow = (ref.flow or []) + [f"[참조] 대표 코드 증적: {ref.file or ref.subcategory}"]

    # 통계
    total_vuln = sum(
        sum(1 for f in findings if RISK_MAP.get(f.severity, ("", 0))[0] == "취약")
        for findings in all_findings.values()
    )
    total_info = sum(
        sum(1 for f in findings if RISK_MAP.get(f.severity, ("", 0))[0] == "정보")
        for findings in all_findings.values()
    )

    # 보고서 작성
    report_lines = []

    # 제목
    report_lines.append(f"# [보안진단] {service_name} 보안진단 결과\n")

    # 서비스 개요
    report_lines.append("## 1. 서비스 개요\n")
    report_lines.append(f"**진단 대상:** {service_name}\n")
    report_lines.append(f"**진단 일자:** {today}\n")
    report_lines.append(f"**소스 경로:** `{source_label or source_dir}`\n")
    if repo:
        report_lines.append(f"**레포:** `{repo}`\n")
    if branch:
        report_lines.append(f"**브랜치:** `{branch}`\n")
    if commit:
        report_lines.append(f"**커밋:** `{commit}`\n")
    if maintainers:
        report_lines.append(f"**담당자:** {', '.join(maintainers)}\n")
    if domain:
        report_lines.append(f"**도메인:** `{domain}`\n")
    if target_modules:
        report_lines.append(f"**대상 모듈:** {', '.join(target_modules)}\n")
    report_lines.append("")

    # 자산 정보 (task_11_result.json 제공 시)
    if asset_info:
        report_lines.extend(_render_asset_info_section(asset_info))

    # 진단 결과 요약
    section_num = "1.3" if asset_info else "1.1"
    report_lines.append(f"### {section_num} 진단 결과 통계\n")
    report_lines.append(f"- **취약:** {total_vuln}건")
    report_lines.append(f"- **정보:** {total_info}건")
    report_lines.append("")

    if total_vuln > 0 or total_info > 0:
        report_lines.append(f"### {'1.4' if asset_info else '1.2'} 주요 식별 취약점\n")

        # severity 순위 (높을수록 먼저)
        # 위험도 숫자 기준 정렬 (RISK_MAP의 위험도 값과 일치)
        _SEV_RANK = {
            "critical": 5, "risk 5": 5,
            "high":     4, "risk 4": 4,
            "medium":   3, "risk 3": 3,
            "low":      2, "risk 2": 2,
            "info":     1, "risk 1": 1,
        }

        def _type_key(f: "Finding") -> str:
            """finding 그룹핑 키 (1.4 주요 식별 취약점 전용).
            subcategory 대신 title 기반 그룹핑 — subcategory는 "정보 누출"처럼 이질적 유형을
            하나로 뭉뚱그리는 경우가 있어 실제 취약점 유형 구분 불가.
            - "민감정보(PII) 평문 로깅 — 3건 (StampService.java)" → "민감정보(PII) 평문 로깅"
            - "Lombok @ToString PII 필드 노출 — @ToString.Exclude 미처리 (File.java)" → "Lombok @ToString PII 필드 노출"
            - "Persistent XSS — 전역 XSS 필터 미적용... (82건)" → "Persistent XSS"
            """
            import re as _re
            title = f.title
            # "— ... (파일명.확장자)" suffix 제거 (Lombok 등 파일별 finding 대응)
            title = _re.sub(
                r"\s*—\s*[^—\n]*?\(\w[\w.]*\.(?:java|kt|xml|json|properties|py)\)\s*$",
                "", title
            ).strip()
            # "(N건)" suffix 제거
            title = _re.sub(r"\s*\(\d+건\)\s*$", "", title).strip()
            # "— 긴 부가 설명" suffix 제거 (XSS EP그룹 finding: "Persistent XSS — 전역 XSS 필터 미적용...")
            # 단, "—" 앞부분이 subcategory 수준의 짧은 명칭이면 그 앞만 사용
            m = _re.match(r"^(.+?)\s*—\s*.+$", title)
            if m and len(m.group(1).strip()) <= 40:
                title = m.group(1).strip()
            return title

        # Task 순서대로 처리: subcategory별 dedup → severity 내림차순 최대 3유형/카테고리
        KEY_PER_CAT = 3   # 카테고리당 최대 표시 유형 수
        cat_blocks: list[tuple[str, str, list[str]]] = []  # (task_label, cat_name, bullets)

        for task_label, _task_desc, cat_id in _TASK_ORDER:
            findings = all_findings.get(cat_id, [])
            # 취약/정보 중 Critical/High/Medium만 후보 (severity 대소문자 정규화)
            candidates = [
                f for f in findings
                if f.severity.lower() in ("critical", "high", "medium")
                and RISK_MAP.get(f.severity.lower(), ("", 0))[0] in ("취약", "정보")
            ]
            if not candidates:
                continue

            # subcategory(또는 타입키) 기준 그룹핑
            groups: dict[str, list["Finding"]] = {}
            for f in candidates:
                key = _type_key(f)
                groups.setdefault(key, []).append(f)

            # 그룹별 대표: 그룹 내 최고 severity finding, count 산출
            # 정렬: severity 내림차순
            group_reps: list[tuple[int, "Finding", int, str]] = []  # (sev_rank, rep, count, label)
            for key, gf_list in groups.items():
                rep = max(gf_list, key=lambda f: _SEV_RANK.get(f.severity.lower(), 0))
                sev_rank = _SEV_RANK.get(rep.severity.lower(), 0)
                count = len(gf_list)
                # 대표 레이블: 타입키를 사용 (파일명 suffix 제거된 깔끔한 이름)
                label = key
                group_reps.append((sev_rank, rep, count, label))

            group_reps.sort(key=lambda x: -x[0])

            bullets: list[str] = []
            for sev_rank, rep, count, label in group_reps[:KEY_PER_CAT]:
                # 위험도 숫자 기반 레이블 (Critical/High 등 영문 등급 미표시)
                _risk_num = RISK_MAP.get(rep.severity.lower(), ("", 3))[1]
                sev_tag = f"위험도 {_risk_num}"
                count_str = f" ({count}건)" if count > 1 else ""
                bullets.append(f"  - [{sev_tag}] {label}{count_str}")

            if bullets:
                cat_info = CATEGORY_INFO[cat_id]
                cat_blocks.append((task_label, cat_info["name"], bullets))

        for task_label, cat_name, bullets in cat_blocks:
            report_lines.append(f"* **[{task_label}] {cat_name}**")
            report_lines.extend(bullets)
            report_lines.append("")

    # 요약 표
    report_lines.append(generate_summary_table(
        all_findings, scan_summaries,
        llm_overrides=llm_matrix_overrides or None,
    ))

    # Persistent XSS 주 finding에 EP 연계 현황 주입 (취약/정보 분류 기준 포함)
    _pxss_rev = scan_summaries.get("xss", {}).get("persistent_xss_revision", {})
    if isinstance(_pxss_rev, dict) and _pxss_rev.get("upgraded_to_vuln"):
        _ep_exp_f = next(
            (f for f in all_findings.get("xss", [])
             if f.from_ep_group and f.ep_expansion and f.subcategory == "Persistent XSS"),
            None
        )
        _main_pxss_f = next(
            (f for f in all_findings.get("xss", [])
             if f.subcategory == "Persistent XSS"
             and not f.from_ep_group
             and RISK_MAP.get(f.severity, ("", 0))[0] != "양호"),
            None
        )
        if _ep_exp_f and _main_pxss_f:
            _vc = len(_ep_exp_f.ep_expansion.get("vuln_instances", []))
            _ic = len(_ep_exp_f.ep_expansion.get("info_instances", []))
            _vuln_reason = _pxss_rev.get("reason", "DB 쓰기 흐름 정적 확인 완료")
            _info_reason = _pxss_rev.get("info_kept_reason", "DB 쓰기 미확인 — 동적 분석 필요")
            _ep_note = (
                f"\n\n---\n\n"
                f"**📊 연계 API 현황 — 취약 {_vc}건 / 정보 {_ic}건**\n\n"
                f"이 취약점(finding-{_main_pxss_f.id})에 연계된 API 엔드포인트를 "
                f"항목별 상세 목록(No. {_main_pxss_f.id} 이후 행)에서 확인할 수 있습니다.\n\n"
                f"| 분류 | 판정 기준 | 건수 |\n"
                f"|:---:|:---------|:---:|\n"
                f"| 🔴 취약 | {_vuln_reason} | **{_vc}건** |\n"
                f"| 🟡 정보 (수동검토) | {_info_reason} | **{_ic}건** |\n\n"
                f"> **취약(🔴)**: 전역 XSS 필터 비활성화 상태에서 DB 쓰기 흐름이 정적으로 확인된 엔드포인트. "
                f"클라이언트 innerHTML 삽입 시 Persistent XSS 직접 트리거 가능.\n\n"
                f"> **정보(🟡)**: 컨트롤러·서비스 레이어 정적 분석으로 DB 쓰기 경로를 미확인. "
                f"외부 API 또는 비동기 이벤트 경로를 통한 저장 가능성이 있어 동적 분석 보완이 필요합니다."
            )
            _main_pxss_f.description = _main_pxss_f.description + _ep_note

    # 카테고리별 상세
    report_lines.append("## 3. 진단 결과 상세\n")

    for category_id in ["injection", "xss", "file_handling", "data_protection"]:
        if category_id in all_findings and all_findings[category_id]:
            report_lines.append(
                generate_category_detail(category_id, all_findings[category_id], source_dir)
            )

    # 부록 (다중 인스턴스 목록)
    appendix = generate_instance_appendix(all_findings)
    if appendix:
        report_lines.append(appendix)

    # 파일 저장
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(report_lines))

    print(f"\n보고서 저장: {output_file}")
    print(f"  총 {total_vuln + total_info}건의 취약점/정보 항목 포함")


# =============================================================================
#  메인
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="취약점 진단 결과 상세 보고서 생성 (Markdown)"
    )
    parser.add_argument(
        "source_dir",
        help="진단 대상 소스코드 디렉토리 (코드 증적 추출용)",
    )
    parser.add_argument(
        "finding_results",
        nargs="+",
        help="Task 2-2~2-5 취약점 진단 결과 JSON 파일들",
    )
    parser.add_argument(
        "--output", "-o",
        help="출력 Markdown 파일 경로",
        default="진단결과_보고서.md",
    )
    parser.add_argument(
        "--service", "-s",
        help="서비스명",
        default="서비스명",
    )
    parser.add_argument(
        "--modules", "-m",
        nargs="*",
        help="대상 모듈 필터 (예: pcona-console)",
        default=None,
    )
    parser.add_argument(
        "--repo",
        help="레포 정보 (예: http://git.example.com/org/repo.git)",
        default=None,
    )
    parser.add_argument(
        "--branch",
        help="브랜치명",
        default=None,
    )
    parser.add_argument(
        "--commit",
        help="커밋 해시",
        default=None,
    )
    parser.add_argument(
        "--maintainer",
        action="append", dest="maintainers", metavar="NAME",
        help="담당자 (복수 지정 가능). 미지정 시 source_dir/.fetch_meta.json 자동 참조.",
        default=None,
    )
    parser.add_argument(
        "--domain",
        help="도메인 정보",
        default=None,
    )
    parser.add_argument(
        "--source-label",
        help="보고서에 표시할 소스 경로/URL (증적 추출 경로와 분리)",
        default=None,
    )
    parser.add_argument(
        "--anchor-style",
        help="Anchor 출력 형식 (confluence|html|md2cf). md2cf 사용 시 md2cf 권장.",
        default="confluence",
        choices=["confluence", "html", "md2cf"],
    )
    parser.add_argument(
        "--page-map",
        help="confluence_page_map.json 경로. supplemental_sources LLM 보완 findings를 통계에 병합한다.",
        default=None,
    )
    parser.add_argument(
        "--asset-info",
        help="자산 식별 결과 JSON 경로 (task_11_result.json). 서비스 설명 및 자산 구조 표를 보고서 상단에 자동 삽입.",
        default=None,
    )
    args = parser.parse_args()

    source_dir = Path(args.source_dir)
    if not source_dir.exists():
        print(f"Error: 소스 디렉토리를 찾을 수 없습니다: {source_dir}")
        sys.exit(1)

    finding_files = []
    for fpath in args.finding_results:
        p = Path(fpath)
        if p.exists():
            finding_files.append(p)
        else:
            print(f"Warning: 파일을 찾을 수 없습니다: {fpath}")

    if not finding_files:
        print("Error: 취약점 진단 결과 파일이 없습니다.")
        sys.exit(1)

    if not args.source_label:
        print("Error: --source-label 값이 필요합니다. (예: repo URL 또는 사용자 표시 경로)")
        sys.exit(1)

    print(f"소스 디렉토리: {source_dir}")
    generate_report(
        source_dir,
        finding_files,
        Path(args.output),
        args.service,
        args.modules,
        args.repo,
        args.branch,
        args.commit,
        args.maintainers,
        args.domain,
        args.source_label,
        args.anchor_style,
        page_map_path=Path(args.page_map) if args.page_map else None,
        asset_info_path=Path(args.asset_info) if args.asset_info else None,
    )


if __name__ == "__main__":
    main()
