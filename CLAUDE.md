# AI Security Audit Playbook

This is a security audit automation framework for static/dynamic code analysis.

## HARD RULE — 자율 완주 (모든 skill 실행에 적용)

**`/sec-audit-static` (및 모든 skill) 실행 중 다음을 절대 하지 말 것:**

- "Do you want to proceed?" 출력 금지
- "계속 진행할까요?" 출력 금지
- "다음 단계로 넘어가도 될까요?" 출력 금지
- Phase 사이, Task 사이, 스크립트 실행 전후 **어떤 형태의 확인 질문도 금지**

**대신:**
- 오류 발생 시 → fallback 자동 적용 후 다음 단계 즉시 진행
- Phase 1 → 2 → 3 → 4 무중단 완주
- 유일한 예외: 토큰/자격증명 누락 등 사람만 해결 가능한 blocking 오류 → 보고 후 대기

## Skills

The following skills are available for security audits:

- `/sec-audit-static` - Static code security analysis (SAST)

## Project Structure

- `skills/` - Self-contained skill definitions (diagnosis criteria, schemas, prompts, rules)
- `tools/scripts/` - Automation scripts
- `docs/` - Procedure documentation (Confluence publishing)
- `state/` - Scan results and reports (gitignored)
- `testbed/` - Target source code for analysis (gitignored)

## Quick Start

1. Place target source code in `testbed/<project-name>/`
2. Run `/sec-audit-static` skill to start static analysis workflow
3. Results are saved to `state/` directory

> **중요**: testbed 대상의 모든 진단은 반드시 `/sec-audit-static` skill을 통해 실행할 것.
> 스크립트 직접 실행 대신 skill 워크플로(Phase 1→2→3)를 따라야 표준화된 결과가 보장됨.

## Available Scripts

| 스크립트 | 용도 | Task |
|---|---|---|
| `scan_api.py` | API 엔드포인트 인벤토리 추출 | 2-1 |
| `scan_injection_enhanced.py` | SQL/Command/SSI Injection 진단 (호출 그래프 추적) | 2-2 |
| `scan_xss.py` | XSS 진단 (Persistent/Reflected/DOM/Redirect) | 2-3 |
| `scan_file_processing.py` | 파일 처리 취약점 진단 (Upload/Download/LFI) | 2-4 |
| `scan_data_protection.py` | 데이터 보호 진단 (CORS/Secrets/JWT/Crypto/Logging) | 2-5 |
| `scan_injection_patterns.py` | 패턴 기반 취약점 탐지 (보조) | — |
| `publish_confluence.py` | Confluence 보고서 게시 | Phase 4 |
| `push_bitbucket.py` | Bitbucket 팀 공유 (증분 커밋, 태그) | — |
| `generate_finding_report.py` | Markdown 보고서 생성 | Phase 4 |
| `merge_results.py` | 다중 태스크 결과 집계 | Phase 4 |
| `validate_task_output.py` | 스키마 유효성 검증 | Phase 4 |
| `redact.py` | 민감정보 마스킹 | Phase 4 |
