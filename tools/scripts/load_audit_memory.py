"""
load_audit_memory.py — 프로젝트별 오탐(FP) 영속 메모리 로더

state/<prefix>/.audit-memory.json 의 fp_rules를 읽어
Phase 3 LLM 분석 컨텍스트로 주입할 마크다운 파일을 생성한다.

파일 위치: state/<prefix>/.audit-memory.json  (gitignored, 프로젝트 전용 디렉터리)
템플릿:    tools/audit_memory_template.json

Usage:
    python3 tools/scripts/load_audit_memory.py \
        --state-dir state/<prefix>/ \
        --output state/<prefix>/audit_memory.md

    python3 tools/scripts/load_audit_memory.py \
        --state-dir state/0331_ocbwebview_comm_api/ \
        --output state/0331_ocbwebview_comm_api/audit_memory.md
"""

import argparse
import json
import sys
from pathlib import Path

_MEMORY_FILENAME = ".audit-memory.json"


def _load_fp_rules(state_dir: Path) -> dict | None:
    """state/<prefix>/.audit-memory.json 탐색 후 파싱."""
    path = state_dir / _MEMORY_FILENAME
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        print(f"[audit-memory] 로드: {path}", file=sys.stderr)
        return data
    except json.JSONDecodeError as e:
        print(f"[audit-memory] JSON 파싱 오류 ({path}): {e}", file=sys.stderr)
        return None


def _format_vuln_type(vtype: str) -> str:
    labels = {
        "SQL_INJECTION":        "SQL Injection",
        "OS_COMMAND_INJECTION": "OS Command Injection",
        "XSS":                  "XSS (크로스사이트 스크립팅)",
        "SSRF":                 "SSRF",
        "PATH_TRAVERSAL":       "Path Traversal / LFI",
        "OPEN_REDIRECT":        "Open Redirect",
        "SENSITIVE_LOGGING":    "민감정보 로깅",
        "HARDCODED_SECRET":     "하드코딩 시크릿",
        "WEAK_CRYPTO":          "취약 암호화",
        "CORS":                 "CORS 설정 오류",
        "SCA":                  "SCA (오픈소스 취약점)",
    }
    return labels.get(vtype.upper(), vtype)


def _render_markdown(data: dict) -> str:
    project  = data.get("project", "unknown")
    version  = data.get("version", "1.0")
    updated  = data.get("updated_at", "")
    fp_rules = data.get("fp_rules", [])

    lines = [
        "# [Project Specific Context & Exceptions]",
        "",
        f"> **프로젝트**: `{project}`  |  **메모리 버전**: {version}"
        + (f"  |  **최종 수정**: {updated}" if updated else ""),
        ">",
        "> 아래 규칙은 보안 담당자가 코드 검토를 통해 **확정한 오탐(FP) 예외 목록**입니다.",
        "> 스캐너가 취약점으로 분류하더라도, 일치하는 규칙이 존재하면 즉시 **양호(FP)**로 판정하십시오.",
        "",
    ]

    if not fp_rules:
        lines += ["*(등록된 FP 예외 규칙 없음)*", ""]
        return "\n".join(lines)

    lines += [
        f"## FP 예외 규칙 ({len(fp_rules)}건)",
        "",
        "| # | 적용 대상 (클래스/경로) | 취약점 유형 | 판정 사유 | 확정자 | 확정일 |",
        "|---|------------------------|-------------|-----------|--------|--------|",
    ]

    for i, rule in enumerate(fp_rules, 1):
        rid    = rule.get("id", f"FP-{i:03d}")
        target = rule.get("target_class_or_path", "").replace("|", "\\|")
        vtype  = _format_vuln_type(rule.get("vulnerability_type", ""))
        reason = rule.get("reason", "").replace("|", "\\|")
        by     = rule.get("confirmed_by", "")
        date   = rule.get("confirmed_date", "")
        lines.append(f"| {rid} | `{target}` | {vtype} | {reason} | {by} | {date} |")

    lines += [
        "",
        "---",
        "",
        "## 적용 지침",
        "",
        "- Phase 3 LLM 분석 전 위 테이블을 반드시 확인합니다.",
        "- 분석 대상 항목의 `file` 경로가 `적용 대상`과 **부분 일치**하고,",
        "  취약점 유형이 `취약점 유형`과 일치하면 → **즉시 양호(FP) 판정**.",
        "- 판정 결과의 `reason` 필드에 해당 FP 규칙 ID와 판정 사유를 기재합니다.",
        "  예: `\"reason\": \"[FP-001] SafeQueryBuilder — 화이트리스트 사전검증 확정\"`",
        "",
    ]

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="state/<prefix>/.audit-memory.json → Phase 3 LLM 컨텍스트 마크다운 생성"
    )
    parser.add_argument(
        "--state-dir", required=True, type=Path,
        help="프로젝트 상태 디렉터리 (state/<prefix>/)"
    )
    parser.add_argument(
        "--output", "-o", type=Path, default=None,
        help="출력 파일 경로 (기본: stdout). 미지정 시 state-dir/audit_memory.md 자동 설정."
    )
    args = parser.parse_args()

    state_dir = args.state_dir
    output    = args.output or (state_dir / "audit_memory.md")

    data = _load_fp_rules(state_dir)

    if data is None:
        print("[audit-memory] .audit-memory.json 없음 — 컨텍스트 주입 건너뜀", file=sys.stderr)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("", encoding="utf-8")
        sys.exit(0)

    md = _render_markdown(data)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(md, encoding="utf-8")
    print(f"[audit-memory] 컨텍스트 저장: {output}", file=sys.stderr)


if __name__ == "__main__":
    main()
