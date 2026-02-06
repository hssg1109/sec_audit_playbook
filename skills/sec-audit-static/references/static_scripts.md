# Static Audit Scripts

Canonical automation scripts (repo `tools/scripts/`):

- `parse_asset_excel.py`: asset Excel -> JSON
- `merge_results.py`: merge task results -> `final_report.json`
- `redact.py`: redact sensitive data in reports
- `validate_task_output.py`: schema validation for task outputs/reports
- `generate_finding_report.py`: generate Markdown report from findings
- `publish_confluence.py`: publish report to Confluence (optional)
- `scan_api.py`: API scan helper (if used)
- `scan_injection_enhanced.py`: enhanced injection scan helper (if used)
- `scan_injection_patterns.py`: injection pattern scan helper (if used)
- `extract_endpoints_rg.py`: Spring/Kotlin endpoint inventory (rg/regex, low-cost)
- `extract_endpoints_treesitter.py`: Spring/Kotlin endpoint inventory (tree-sitter, higher precision)
- `migrate_test_groups.py`: internal migration utility (use only if needed)
- `rename_remove_prefix.py`: internal rename utility (use only if needed)

Use only the scripts required for the target workflow; mark optional ones explicitly.

Notes:
- Task outputs must include `metadata.source_repo_url`, `metadata.source_repo_path`, `metadata.source_modules`.
- `generate_finding_report.py` 실행 시 `--source-label` 필수.
 - Confluence(md2cf) 업로드 시 `--anchor-style md2cf` 사용.
 - Confluence 앵커 링크는 **헤더 텍스트 기반 자동 앵커**가 가장 안정적임.
   - `finding-<id>` 형태의 헤더를 출력하고, 실제 취약점 제목은 별도 텍스트로 표시.
   - 링크는 `#finding-<id>` 형태로 생성.
