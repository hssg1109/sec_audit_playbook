---
allowed-tools: Read, Glob, Grep, Bash, Edit, Write, Agent, WebFetch
description: testbed 대상 정적 보안 진단 (SAST) — SQL Injection, OS Command, XSS, File Handling, Data Protection 전체 워크플로 실행 후 Confluence 게시
---

# Static Security Audit

대상: $ARGUMENTS (미입력 시 testbed/ 내 대상 목록을 먼저 확인)

## 실행 절차

다음 순서로 반드시 수행하라.

### 1. SKILL 로드
`skills/sec-audit-static/SKILL.md`를 읽어 전체 워크플로를 파악한 뒤, 아래 reference 파일들을 모두 읽어라:
- `skills/sec-audit-static/references/workflow.md`
- `skills/sec-audit-static/references/static_scripts.md`
- `skills/sec-audit-static/references/severity_criteria.md`
- `skills/sec-audit-static/references/output_schemas.md`
- `skills/sec-audit-static/references/injection_diagnosis_criteria.md`
- `skills/sec-audit-static/references/cross_verification.md`
- `skills/sec-audit-static/references/manual_review_prompt.md`
- `skills/sec-audit-static/references/taint_tracking.md`
- `skills/sec-audit-static/references/global_filters.md`
- `skills/sec-audit-static/references/vuln_automation_principles.md`
- `skills/sec-audit-static/references/reporting_summary.md`

### 2. Task Prompt 로드
- `skills/sec-audit-static/references/task_prompts/task_11_asset_identification.md`
- `skills/sec-audit-static/references/task_prompts/task_21_api_inventory.md`
- `skills/sec-audit-static/references/task_prompts/task_22_injection_review.md`
- `skills/sec-audit-static/references/task_prompts/task_23_xss_review.md`
- `skills/sec-audit-static/references/task_prompts/task_24_file_handling.md`
- `skills/sec-audit-static/references/task_prompts/task_25_data_protection.md`

### 3. 워크플로 실행
`workflow.md`에 정의된 Phase 1 → Phase 2 → Phase 3 → Phase 4 순서로 진단을 수행하라.

- **Phase 1**: 자산 식별 (task_11)
- **Phase 2**: 정적 분석 (task_21~25, 스크립트 우선 → LLM 검증)
- **Phase 3**: 교차검증 (Phase 3-1) + 수동 심층진단 (Phase 3-2)
- **Phase 4**: 보고서 생성 → Confluence 게시

각 Phase의 상세 실행 기준은 `workflow.md`와 각 task prompt를 따른다.
