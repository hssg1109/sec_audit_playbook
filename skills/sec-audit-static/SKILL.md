---
name: sec-audit-static
description: Static code security audit playbook (SAST) — SQL Injection, OS Command, XSS, File Handling, Data Protection diagnosis for Spring/Kotlin/Java backends. Runs automated scan scripts then LLM cross-verification. Use when asked to run security audit, SAST scan, or 정적 진단 on a target in testbed/.
tools: Read, Glob, Grep, Bash, Edit, Write, Agent, WebFetch
---

# Sec Audit Static

## Overview
Run the static audit workflow for a codebase: asset identification, API inventory, SAST-style reviews, SCA/secret checks (Gitleaks-first), and report generation.

This skill is **self-contained**: `skills/sec-audit-static/` + `tools/scripts/` 만으로 동일한 진단 결과를 재현할 수 있습니다.

## Workflow

### Step 1: Load references
- `references/workflow.md` for phase/task execution map and security policy.
- `references/static_scripts.md` for available automation scripts.
- `references/severity_criteria.md` for risk mapping (5→Critical ... 1→Info).
- `references/output_schemas.md` for JSON output schema definitions.
- `references/injection_diagnosis_criteria.md` for framework-specific injection criteria (MyBatis/JPA/JDBC/Kotlin/R2DBC).
- `references/cross_verification.md` for post-scan cross-verification procedure (Phase 3-1: 취약 교차검증 / Phase 3-2: 정보/수동검토 LLM 심층진단).
- `references/manual_review_prompt.md` for LLM persona, diagnosis criteria, and response principles used in Phase 3-2 manual review.
- `references/taint_tracking.md` for Source→Sink confirmation (includes Kotlin-specific patterns).
- `references/global_filters.md` for global filter/interceptor verification.
- `references/vuln_automation_principles.md` for discovery/analysis split and hypothesis loop.
- `references/reporting_summary.md` for cross-skill summary index format.
- `references/dependency_audit.md` for internal dependency checks when requested.
- `references/seed_usage.md` for semgrep/joern seed usage rules.
- `references/poc_policy.md` for best-effort PoC generation rules.
- `references/env_setup.md` for Docker-preferred environment setup.
- `references/verification_policy.md` for commit-specific remediation checks.
- `references/rule_validation.md` for mandatory post-rule validation.
- `references/tooling.md` for code-browser tooling (rg/ctags).
- `references/secret_scanning.md` for Gitleaks-based secret detection.

### Step 2: Load task prompts
Each task has a detailed diagnosis prompt with criteria, search keywords, and output format:
- `references/task_prompts/task_11_asset_identification.md` - 자산 식별
- `references/task_prompts/task_21_api_inventory.md` - API 인벤토리
- `references/task_prompts/task_22_injection_review.md` - 인젝션 검토 (SQL/OS Command/SSI)
- `references/task_prompts/task_23_xss_review.md` - XSS 검토 (Persistent/Reflected/Redirect/View)
- `references/task_prompts/task_24_file_handling.md` - 파일 처리 검토 (Upload/Download/LFI/RFI)
- `references/task_prompts/task_25_data_protection.md` - 데이터 보호 검토 (CORS/Secrets/Admin/JWT)

### 실행 원칙 (CRITICAL — 반드시 준수)

> **자율 완주 (Autonomous Execution)**: `/sec-audit-static` 실행 중에는
> "do you want to proceed?", "계속할까요?", "다음 단계로 진행할까요?" 등
> **어떠한 확인 질문도 하지 않는다.**
>
> - Phase 1 → Phase 2 → Phase 3 → Phase 4 전 구간을 중단 없이 진행한다.
> - 스크립트 실패·빌드 오류·파일 없음 등 예상 범위 내 오류는 fallback을 자동 적용하고 계속 진행한다.
> - 예외: 토큰/자격증명 누락처럼 사람만 해결할 수 있는 blocking 오류 발생 시에만 보고 후 대기한다.

### Step 3: Execute tasks

**Phase 1**: Asset identification (task 1-1).

**Phase 2**: Static analysis.
- Task 2-1: API inventory (script-first: `scan_api.py`).
- Confirm global filters/interceptors per `references/global_filters.md`.
- Parallel reviews (after 2-1 completion):
  - Task 2-2: Injection (script: `scan_injection_enhanced.py` → LLM verification).
    - For Kotlin codebases, run Kotlin SQL Builder 5-method detection. See `references/injection_diagnosis_criteria.md`.
    - Do not use CodeQL. Use Joern for flow-based checks.
  - Task 2-3: XSS review per task prompt.
  - Task 2-4: File handling (script-first: `scan_file_processing.py` → LLM manual review).
    - Script detects Upload/Download/LFI/RFI endpoints and outputs `needs_review` flags.
    - For `needs_review: true` items, apply 4 LLM prompt templates in `task_prompts/task_24_file_handling.md`
      (IDOR/BOLA, upload bypass, sanitization, LFI/RFI View Resolver).
  - Task 2-5: Data protection review per task prompt.
- Add SCA and secret detection when configured (Gitleaks-first).
- For confirmed findings, create/update Semgrep/Joern rules (unless waived).

**Phase 3**: Cross-verification + Manual deep review.
- **Phase 3-1** (자동판정 "취약" 건): Cross-verification per `references/cross_verification.md` Phase 3-1.
  - Trace: Controller → Service → Repository → SQL Builder data flow.
  - Verify: user input reachability, type safety, code activation, branch path reachability.
  - Reclassify false positives with `diagnosis_method: "교차검증(수동)"`.
- **Phase 3-2** ("정보/수동검토" 건): LLM manual deep review per `references/cross_verification.md` Phase 3-2.
  - Target: `result: "정보"` with `needs_review: true`, or `taint_confirmed: null`, or `[잠재] 취약한 쿼리 구조`.
  - Use LLM persona and criteria defined in `references/manual_review_prompt.md`.
  - Update result with `diagnosis_method: "수동진단(LLM)"` and `manual_review_note`.

**Phase 4**: Reporting + Confluence 게시 (필수).
- Merge: `tools/scripts/merge_results.py`
- Redact: `tools/scripts/redact.py`
- Validate: `tools/scripts/validate_task_output.py` against `references/output_schemas.md`
- Report: `tools/scripts/generate_finding_report.py --source-label <label> --anchor-style md2cf --page-map tools/confluence_page_map.json`
  - `--anchor-style md2cf` 는 항상 필수 (Confluence 앵커/HTML 테이블 포맷)
  - `--page-map` 지정 시 supplemental_sources LLM 보완 findings 자동 병합
- Publish: `tools/scripts/publish_confluence.py` (필수 — dry-run 확인 후 실행)
  - `confluence_page_map.json`에 해당 진단 항목이 등록되어 있어야 함
  - `workflow.md` Phase 4 참조: main_report / api_inventory / finding / supplemental 구조

**Phase 5** (선택): SSC 정합성 검증 — Fortify SSC High/Critical findings를 소스코드와 교차검증 후 별도 보고서 생성.
- `references/ssc_verification.md` 전체 절차 참조.
- Step 5-0: **브랜치/커밋 일치 검증** (필수) — `--testbed` 옵션으로 SSC 스캔 버전 vs testbed 소스 일치 확인
- Step 5-1: `tools/scripts/fetch_ssc.py --project <name> --testbed <path> -o state/<prefix>_ssc_findings.json`
- Step 5-2: LLM이 각 finding의 소스코드 위치를 직접 확인 → TP/FP/검토필요 판정
- Step 5-3: 검증 결과 → `state/<prefix>_ssc_report.md` 생성
- Step 5-4: SSC TP → SAST 피드백 환류 — 미탐 원인 분석 + Semgrep 룰 / task prompt 개선 적용 (`references/ssc_feedback_ruleset.md`)
- 기존 Phase 1~4와 독립 실행 가능 (testbed 소스코드만 있으면 됨)

### Step 4: Output validation
- Every task output **must** include `metadata.source_repo_url`, `metadata.source_repo_path`, `metadata.source_modules`.
- If wiki published, include `metadata.report_wiki_url` and `metadata.report_wiki_status`.
- Validate JSON against schemas in `references/output_schemas.md`.
- Ensure subcategory classification is correct (e.g., NoSQL vs SQL).

## Reporting
- Primary output: task JSONs + `final_report.json` + Markdown report.
- Use severity mapping from `references/severity_criteria.md`.
- Produce summary JSON per `references/reporting_summary.md`.

## Resources

### references/
#### Workflow & Policy
- `references/workflow.md` - Phase/Task execution map, security policy
- `references/output_schemas.md` - JSON output schemas (task_output, finding, enhanced_injection)
- `references/severity_criteria.md` - Severity mapping
- `references/reporting_summary.md` - Summary index format

#### Diagnosis Criteria
- `references/injection_diagnosis_criteria.md` - SQL/OS Command/SSI diagnosis criteria by framework
- `references/cross_verification.md` - Phase 3-1 교차검증 + Phase 3-2 LLM 수동 심층진단 절차
- `references/manual_review_prompt.md` - LLM 수동진단 페르소나, 진단기준, 답변원칙 (Phase 3-2)
- `references/taint_tracking.md` - Source→Sink taint tracking (Kotlin-specific patterns)
- `references/global_filters.md` - Global filter/interceptor verification

#### Task Prompts (diagnosis guide per task)
- `references/task_prompts/task_11_asset_identification.md`
- `references/task_prompts/task_21_api_inventory.md`
- `references/task_prompts/task_22_injection_review.md`
- `references/task_prompts/task_23_xss_review.md`
- `references/task_prompts/task_24_file_handling.md`
- `references/task_prompts/task_25_data_protection.md`

#### Scripts & Tooling
- `references/static_scripts.md` - Available automation scripts
- `references/tooling.md` - Code browser tooling (rg/ctags)
- `references/env_setup.md` - Docker environment setup

#### Advanced
- `references/vuln_automation_principles.md` - Discovery/analysis split
- `references/seed_usage.md` - Semgrep/Joern seed rules
- `references/poc_policy.md` - PoC generation rules
- `references/dependency_audit.md` - Internal dependency checks
- `references/verification_policy.md` - Commit-specific remediation
- `references/rule_validation.md` - Post-rule validation
- `references/secret_scanning.md` - Gitleaks secret detection
- `references/ssc_verification.md` - SSC High/Critical findings 정합성 검증 (Phase 5)
- `references/ssc_feedback_ruleset.md` - SSC TP → SAST 피드백 룰셋 (미탐 분석 + 개선 액션 누적)

### rules/
- `references/rules/semgrep/kotlin-sql-string-template.yaml`
- `references/rules/semgrep/sql-string-format.yaml`
- `references/rules/semgrep/sql-utils-tosql.yaml`
- `references/rules/semgrep/thymeleaf-ssti.yaml`
- `references/rules/semgrep/config-hardcoded-secrets.yaml`
- `references/rules/semgrep/properties-hardcoded-secrets.yaml`
- `references/rules/semgrep/elasticsearch-query-annotation.yaml`
- `references/rules/joern/taint_queries.sc`
- `references/rules/joern/pcona-console-taint.sc`
