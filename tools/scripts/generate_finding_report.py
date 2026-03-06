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
            "nosql": "NoSQL 인젝션",
        }
    },
    "xss": {
        "name": "XSS",
        "number": "2",
        "threat": "세션 탈취, 피싱, 악성코드 배포",
        "items": {
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
            "info_leak": "정보 누출",
            "hardcoded": "하드코딩된 비밀정보",
            "cors": "CORS 설정 미흡",
            "jwt": "JWT 취약점",
            "csrf": "CSRF 보호 미흡",
        }
    },
}

# severity → 위험도
RISK_MAP = {
    "critical": ("취약", 5),
    "high": ("취약", 5),
    "medium": ("정보", 4),
    "low": ("양호", 3),
    "info": ("정보", 4),
}

ANCHOR_STYLE = "confluence"


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
    if ANCHOR_STYLE == "md2cf":
        return ""
    return f"[[ANCHOR:{name}]]"


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
    is_supplemental: bool = False  # LLM 수동분석 보완 finding 여부


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
                          context_lines: int = 5) -> tuple[str, list, list]:
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
        for af in f.get("affected_files", []):
            if isinstance(af, dict):
                if not file_path:
                    file_path = af.get("file", "")
                if not line_num:
                    line_num = af.get("line", 0)
                if not endpoint:
                    endpoint = af.get("api", af.get("endpoint", ""))

        # 기존 evidence 우선 사용 (민감정보는 redacted evidence를 우선 반영)
        code_snippet = ""
        ctx_before = []
        ctx_after = []
        evidence = f.get("evidence", {})
        if isinstance(evidence, dict):
            code_snippet = evidence.get("code_snippet", evidence.get("code", ""))
            ctx_before = evidence.get("context_before", [])
            ctx_after = evidence.get("context_after", [])

        # 코드 증적 추출 (evidence가 없을 때만)
        if not code_snippet:
            code_snippet, ctx_before, ctx_after = extract_code_evidence(
                source_dir, file_path, line_num
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

        if not instances and (file_path or line_num or endpoint):
            instances = [{
                "file": file_path,
                "line": line_num,
                "endpoint": endpoint,
            }]

        # 서브카테고리 추출
        title_lower = f.get("title", "").lower()
        cat_lower = f.get("category", "").lower()
        subcategory = ""
        # Prefer longer keys first to avoid substring collisions (e.g., nosql vs sql)
        for key in sorted(cat_info["items"].keys(), key=len, reverse=True):
            name = cat_info["items"][key]
            if key in title_lower or key in cat_lower:
                subcategory = name
                break
        if not subcategory:
            subcategory = list(cat_info["items"].values())[0]

        findings.append(Finding(
            id=f"{cat_info['number']}-{idx}",
            title=f.get("title", ""),
            severity=f.get("severity", "info").lower(),
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
            is_supplemental=is_supplemental,
        ))

    return category, findings


# =============================================================================
#  보고서 생성
# =============================================================================

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

        has_findings = bool(all_findings.get(cat_id))
        marker = " ★" if has_findings else ""
        lines.append(f"{task_prefix} {task_label}: {task_desc}{marker}")

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


def generate_stats_matrix(all_findings: dict[str, list[Finding]]) -> str:
    """Task × 세부항목 진단 결과 매트릭스 표 생성.

    JSON findings에서 취약/정보/양호 건수를 명확한 정수(int)로 분리 추출하여
    포맷팅 붕괴(예: "취약 0건0건171건")가 발생하지 않도록 한다.
    Task 컬럼은 첫 번째 항목 행에만 표시하고 이후 행은 공백으로 처리한다.
    """
    header = ("| Task | 세부 진단 항목 "
              "| 🔴 취약 | 🟡 정보 (수동검토) | 🟢 양호 / 해당없음 |")
    sep    = ("|:-----|:------------|"
              ":------:|:-----------------:|:-----------------:|")
    rows: list[str] = [header, sep]

    for task_label, _task_desc, cat_id in _TASK_ORDER:
        findings  = all_findings.get(cat_id, [])
        cat_items = CATEGORY_INFO[cat_id]["items"]

        # subtype별 카운터 초기화 (중복 제거)
        seen_names: list[str] = []
        for v in cat_items.values():
            if v not in seen_names:
                seen_names.append(v)

        counts: dict[str, dict[str, int]] = {
            name: {"vuln": 0, "info": 0, "safe": 0} for name in seen_names
        }

        # findings에서 정수 단위 집계
        for f in findings:
            result, _ = RISK_MAP.get(f.severity, ("정보", 4))
            subcat = f.subcategory
            if subcat not in counts:
                counts[subcat] = {"vuln": 0, "info": 0, "safe": 0}
            key = {"취약": "vuln", "정보": "info", "양호": "safe"}.get(result, "info")
            counts[subcat][key] += 1

        first_row = True
        for item_name, c in counts.items():
            task_col: str = task_label if first_row else ""
            v: int = c["vuln"]
            i: int = c["info"]
            s: int = c["safe"]
            # 취약 건수가 있으면 굵게 강조
            v_str = f"**{v}**" if v > 0 else "0"
            i_str = f"**{i}**" if i > 0 else "0"
            rows.append(f"| {task_col} | {item_name} | {v_str} | {i_str} | {s} |")
            first_row = False

    return "\n".join(rows)


def generate_summary_table(all_findings: dict[str, list[Finding]]) -> str:
    """진단 결과 요약 표 생성 (Task Tree + 매트릭스 표 + 항목별 목록)"""
    lines = []
    if ANCHOR_STYLE == "md2cf":
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
    lines.append(generate_stats_matrix(all_findings))
    lines.append("")

    # ── 항목별 상세 목록 ──────────────────────────────────────────────────
    lines.append("### 📋 항목별 상세 목록\n")
    headers = ["No", "점검 구분", "점검 항목", "결과", "위험도", "Request Mapping", "File"]
    rows: list[list[str]] = []

    link_pairs = []
    for category_id, findings in all_findings.items():
        for f in findings:
            result, risk = RISK_MAP.get(f.severity, ("정보", 4))
            if result == "양호":
                continue  # 양호 항목은 요약에서 제외

            if len(f.instances) > 1:
                file_short = f"multiple ({len(f.instances)})"
            else:
                file_short = f.file.split("/")[-1] if f.file else "-"
            endpoint = f.endpoint if f.endpoint else "-"

            supp_marker = " ★LLM보완" if f.is_supplemental else ""
            rows.append([f.id, f.category, f.subcategory + supp_marker, result, str(risk), f"`{endpoint}`", file_short])
            link_pairs.append((f.id, f.subcategory))

    if ANCHOR_STYLE == "md2cf":
        lines.append(_html_table(headers, rows))
        lines.append("")
    else:
        lines.append("| No | 점검 구분 | 점검 항목 | 결과 | 위험도 | Request Mapping | File |")
        lines.append("|:--:|:-------:|:-------:|:---:|:-----:|:----------------|:-----|")
        for row in rows:
            lines.append(
                f"| {row[0]} | {row[1]} | {row[2]} | {row[3]} | {row[4]} | "
                f"{row[5]} | {row[6]} |"
            )
        lines.append("")

    if link_pairs and ANCHOR_STYLE != "html":
        lines.append("**상세 링크**")
        for fid, subcat in link_pairs:
            lines.append(f"- {fid} {subcat}: {_anchor_link(f'finding-{fid}', '상세 보기')}")
        lines.append("")

    return "\n".join(lines)


def generate_category_detail(category_id: str, findings: list[Finding],
                             source_dir: Path) -> str:
    """카테고리별 상세 보고서 생성"""
    cat_info = CATEGORY_INFO[category_id]
    lines = []

    # 카테고리 헤더
    lines.append(f"### ({cat_info['number']}) {cat_info['name']}\n")

    # 카테고리 요약 표
    lines.append("| No | 취약점 항목 | 현황 | 결과 | 위험도 | 보안 위협 |")
    lines.append("|:--:|:----------|:-----|:---:|:-----:|:---------|")

    for f in findings:
        result, risk = RISK_MAP.get(f.severity, ("정보", 4))
        # 현황 요약 (description 첫 문장)
        status = f.description.split(".")[0][:50] if f.description else "-"

        lines.append(
            f"| {f.id} | {f.subcategory} | {status}... | {result} | {risk} | {cat_info['threat']} |"
        )

    lines.append("")

    # 각 취약점 상세
    for f in findings:
        result, risk = RISK_MAP.get(f.severity, ("정보", 4))

        lines.append(f"---\n")
        if ANCHOR_STYLE == "md2cf":
            lines.append(f"#### finding-{f.id}\n")
            lines.append(f"**＊ 취약점 {f.id} {f.subcategory} ({result})**\n")
        else:
            lines.append(_anchor(f"finding-{f.id}"))
            lines.append(f"#### ＊ 취약점 {f.id} {f.subcategory} ({result})\n")

        # 영향 받는 엔드포인트/파일
        if f.endpoint:
            lines.append(f"**영향 받는 API:** `{f.endpoint}`\n")
        if f.file:
            file_display = f.file
            if f.line:
                file_display += f":{f.line}"
            lines.append(f"**파일:** `{file_display}`\n")

        if len(f.instances) > 1:
            if ANCHOR_STYLE == "html":
                lines.append("**전체 인스턴스 목록:** 부록 참조\n")
            else:
                lines.append(f"**전체 인스턴스 목록:** {_anchor_link('appendix-instances', '부록 참조')}\n")
            preview = f.instances[:10]
            preview_items = []
            for inst in preview:
                inst_file = inst.get("file", "-") or "-"
                inst_line = inst.get("line", "-") or "-"
                preview_items.append(f"`{inst_file}:{inst_line}`")
            suffix = ""
            if len(f.instances) > 10:
                suffix = f", ...외 {len(f.instances) - 10}개"
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
    """인스턴스 상세 목록 부록 생성 (다중 위치만)"""
    lines = []
    appendix_items = []
    for category_id, findings in all_findings.items():
        for f in findings:
            if len(f.instances) > 1:
                appendix_items.append(f)

    if not appendix_items:
        return ""

    if ANCHOR_STYLE == "md2cf":
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


def generate_report(
    source_dir: Path,
    finding_files: list[Path],
    output_file: Path,
    service_name: str,
    target_modules: list[str] = None,
    repo: str | None = None,
    branch: str | None = None,
    commit: str | None = None,
    domain: str | None = None,
    source_label: str | None = None,
    anchor_style: str | None = None,
    page_map_path: Path | None = None,
):
    """최종 보고서 생성"""
    global ANCHOR_STYLE
    if anchor_style:
        ANCHOR_STYLE = anchor_style

    today = date.today().strftime("%Y.%m.%d")

    # Findings 로드
    all_findings: dict[str, list[Finding]] = {}
    for fpath in finding_files:
        category, findings = load_findings(fpath, source_dir)
        if category not in all_findings:
            all_findings[category] = []
        all_findings[category].extend(findings)
        print(f"  {fpath.name}: {len(findings)}건 ({category})")

    # supplemental_sources 병합 (page_map 기반)
    supp_map = _collect_supplemental_paths(finding_files, page_map_path)
    if supp_map:
        print("\n  [LLM 수동분석 보완 병합]")
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
                # ID 중복 체크: 같은 카테고리 내 existing finding과 원본 id 충돌 방지
                existing_ids = {f.id for f in all_findings[s_category]}
                for sf in s_findings:
                    # 새 ID 할당 (LLM 접두사)
                    base_id = sf.id
                    candidate = f"LLM-{base_id}"
                    while candidate in existing_ids:
                        candidate += "'"
                    sf.id = candidate
                    existing_ids.add(candidate)
                    all_findings[s_category].append(sf)
                print(f"  {sp.name}: {len(s_findings)}건 ({s_category}) ★보완")

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
    if domain:
        report_lines.append(f"**도메인:** `{domain}`\n")
    if target_modules:
        report_lines.append(f"**대상 모듈:** {', '.join(target_modules)}\n")
    report_lines.append("")

    # 진단 결과 요약
    report_lines.append("### 1.1 진단 결과 통계\n")
    report_lines.append(f"- **취약:** {total_vuln}건")
    report_lines.append(f"- **정보:** {total_info}건")
    report_lines.append("")

    if total_vuln > 0 or total_info > 0:
        report_lines.append("### 1.2 주요 식별 취약점\n")
        # Task 순서대로 High/Critical 취약점 출력
        for task_label, _task_desc, cat_id in _TASK_ORDER:
            findings = all_findings.get(cat_id, [])
            high_findings = [f for f in findings if f.severity in ("critical", "high")]
            if not high_findings:
                continue
            cat_info = CATEGORY_INFO[cat_id]
            # 예: * **[Task 2-2] 인젝션**
            report_lines.append(f"* **[{task_label}] {cat_info['name']}**")
            for f in high_findings[:3]:   # 상위 3개만
                supp = " _(LLM 보완)_" if f.is_supplemental else ""
                report_lines.append(f"  - {f.title}{supp}")
            report_lines.append("")

    # 요약 표
    report_lines.append(generate_summary_table(all_findings))

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
        args.domain,
        args.source_label,
        args.anchor_style,
        page_map_path=Path(args.page_map) if args.page_map else None,
    )


if __name__ == "__main__":
    main()
