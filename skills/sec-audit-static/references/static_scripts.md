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
- `migrate_test_groups.py`: internal migration utility (use only if needed)
- `rename_remove_prefix.py`: internal rename utility (use only if needed)

Use only the scripts required for the target workflow; mark optional ones explicitly.
