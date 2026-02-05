# Static Playbook Sources

Use these as the canonical sources for procedure, prompts, and schemas:

- Playbook guide: `docs/PLAYBOOK_GUIDE.md`
- Overview: `docs/00_overview.md`
- Asset identification: `docs/10_asset_identification.md`
- Static analysis overview: `docs/20_static_analysis.md`
- Task docs: `docs/21_api_inventory.md`, `docs/22_injection_review.md`, `docs/23_xss_review.md`, `docs/24_file_handling_review.md`, `docs/25_data_protection_review.md`
- Prompts: `prompts/static/task_11_asset_identification.md`, `prompts/static/task_21_api_inventory.md`, `prompts/static/task_22_injection_review.md`, `prompts/static/task_23_xss_review.md`, `prompts/static/task_24_file_handling.md`, `prompts/static/task_25_data_protection.md`
- Schemas: `schemas/task_output_schema.json`, `schemas/finding_schema.json`
- Governance: `ai/AI_USAGE_POLICY.md`, `ai/PROMPT_STYLE_GUIDE.md`, `ai/REDACTION_RULES.md`

Use `workflows/audit_workflow.yaml` as the phase/task execution map.
