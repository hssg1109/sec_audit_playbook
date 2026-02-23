# Static Playbook Sources

All resources are now self-contained within `skills/sec-audit-static/references/`.

## Task Prompts (진단 기준 + 실행 지침)
- `references/task_prompts/task_11_asset_identification.md`
- `references/task_prompts/task_21_api_inventory.md`
- `references/task_prompts/task_22_injection_review.md`
- `references/task_prompts/task_23_xss_review.md`
- `references/task_prompts/task_24_file_handling.md`
- `references/task_prompts/task_25_data_protection.md`

## Schemas
- `references/output_schemas.md` (task_output_schema + finding_schema embedded)
- `references/schemas/finding_schema.json` (JSON schema for validation script)
- `references/schemas/task_output_schema.json` (JSON schema for validation script)

## Workflow
- `references/workflow.md` (phase/task execution map)

## Scripts
- `tools/scripts/` directory (see `references/static_scripts.md` for full list)
