---
name: sec-audit-static
description: Static code security audit playbook (SAST, SCA, secret detection) with standardized JSON outputs and reporting. Self-contained skill - all diagnosis criteria, task prompts, schemas, and workflow definitions are included in references/.
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
- `references/cross_verification.md` for post-scan cross-verification procedure.
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
  - Task 2-4: File handling review per task prompt.
  - Task 2-5: Data protection review per task prompt.
- Add SCA and secret detection when configured (Gitleaks-first).
- For confirmed findings, create/update Semgrep/Joern rules (unless waived).

**Phase 3**: Cross-verification.
- For all automated "취약" findings, perform cross-verification per `references/cross_verification.md`.
- Trace: Controller → Service → Repository → SQL Builder data flow.
- Verify: user input reachability, type safety, code activation, branch path reachability.
- Reclassify false positives with `diagnosis_method: "교차검증(수동)"`.

**Phase 4**: Reporting.
- Merge: `tools/scripts/merge_results.py`
- Redact: `tools/scripts/redact.py`
- Validate: `tools/scripts/validate_task_output.py` against `references/output_schemas.md`
- Report: `tools/scripts/generate_finding_report.py --source-label <label>`
  - For Confluence: `--anchor-style md2cf`
- Publish (optional): `tools/scripts/publish_confluence.py`

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
- `references/cross_verification.md` - Post-scan cross-verification procedure
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
