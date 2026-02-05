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


def load_findings(filepath: Path, source_dir: Path) -> tuple[str, list[Finding]]:
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
        ))

    return category, findings


# =============================================================================
#  보고서 생성
# =============================================================================

def generate_summary_table(all_findings: dict[str, list[Finding]]) -> str:
    """진단 결과 요약 표 생성"""
    lines = []
    lines.append("## 2. 진단 결과 요약\n")
    lines.append("| No | 점검 구분 | 점검 항목 | 결과 | 위험도 | Request Mapping | File |")
    lines.append("|:--:|:-------:|:-------:|:---:|:-----:|:----------------|:-----|")

    for category_id, findings in all_findings.items():
        for f in findings:
            result, risk = RISK_MAP.get(f.severity, ("정보", 4))
            if result == "양호":
                continue  # 양호 항목은 요약에서 제외

            file_short = f.file.split("/")[-1] if f.file else "-"
            endpoint = f.endpoint if f.endpoint else "-"

            lines.append(
                f"| {f.id} | {f.category} | {f.subcategory} | {result} | {risk} | "
                f"`{endpoint}` | {file_short} |"
            )

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
        lines.append(f"#### ＊ 취약점 {f.id} {f.subcategory} ({result})\n")

        # 영향 받는 엔드포인트/파일
        if f.endpoint:
            lines.append(f"**영향 받는 API:** `{f.endpoint}`\n")
        if f.file:
            file_display = f.file
            if f.line:
                file_display += f":{f.line}"
            lines.append(f"**파일:** `{file_display}`\n")

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

        lines.append("")

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
):
    """최종 보고서 생성"""

    today = date.today().strftime("%Y.%m.%d")

    # Findings 로드
    all_findings: dict[str, list[Finding]] = {}
    for fpath in finding_files:
        category, findings = load_findings(fpath, source_dir)
        if category not in all_findings:
            all_findings[category] = []
        all_findings[category].extend(findings)
        print(f"  {fpath.name}: {len(findings)}건 ({category})")

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
        # 주요 취약점 요약 (High/Critical만)
        for category_id, findings in all_findings.items():
            high_findings = [f for f in findings if f.severity in ("critical", "high")]
            if high_findings:
                cat_info = CATEGORY_INFO[category_id]
                report_lines.append(f"**{cat_info['name']}**")
                for f in high_findings[:3]:  # 상위 3개만
                    report_lines.append(f"- {f.title}")
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
    )


if __name__ == "__main__":
    main()
