---
name: sec-audit-static
description: Static code security audit playbook (SAST, SCA, secret detection) with standardized JSON outputs and reporting. Use for source-code based assessments, schema validation, and generating final reports.
---

# Sec Audit Static

## Overview
Run the static audit workflow for a codebase: asset identification, API inventory, SAST-style reviews, SCA/secret checks, and report generation using the existing schemas and scripts.

## Workflow
1. Load playbook references:
- `references/static_sources.md` for the canonical docs/prompts/schemas locations.
- `references/static_scripts.md` for available automation entrypoints.
- `references/severity_criteria.md` plus `skills/SEVERITY_CRITERIA_DETAIL.md` for risk mapping (5->Critical ... 1->Info).
- `references/reporting_summary.md` for the cross-skill summary index format.
- `references/dependency_audit.md` for internal dependency checks when requested.
- `references/seed_usage.md` for semgrep/joern seed usage rules (2-3/2-4/2-5).
- `references/poc_policy.md` for best-effort PoC generation rules.
- `references/env_setup.md` for Docker-preferred environment setup.
- `references/verification_policy.md` for commit-specific remediation checks.
- `references/taint_tracking.md` for Source->Sink confirmation and rule generation.
- `references/rule_validation.md` for mandatory post-rule validation.
- `references/tooling.md` for code-browser tooling (rg/ctags).
2. Execute tasks in order:
- Phase 1: asset identification.
- Phase 2: API inventory, then parallel reviews (injection/XSS/file handling/data protection).
- Add SCA and secret detection as part of Phase 2 when configured.
 - If semgrep/joern rules are updated, re-run seed generation and re-check affected phases before finalizing outputs.
- For 2-2 (injection), always check for dynamic SQL assembly patterns (`toSql`, `String.format`, string concatenation, template SQL) even if seeds are empty.
3. Produce outputs in JSON matching the schemas.
4. Generate final report and validate:
- `tools/scripts/merge_results.py`
- `tools/scripts/redact.py`
- `tools/scripts/validate_task_output.py`
5. Generate Markdown report (required):
- `tools/scripts/generate_finding_report.py`
- Ensure subcategory classification is validated (e.g., NoSQL vs SQL) after report generation.

## Reporting
- Primary output: task JSONs + `final_report.json` + Markdown report.
- Use severity mapping from `references/severity_criteria.md` and detailed criteria in `skills/SEVERITY_CRITERIA_DETAIL.md`.
- Produce a common summary JSON using `schemas/reporting_summary_schema.json`.

## Resources
### scripts/
Use the existing automation scripts from the repo (see `references/static_scripts.md`).

### references/
- `references/static_sources.md`
- `references/static_scripts.md`
- `references/severity_criteria.md`
- `references/reporting_summary.md`
- `references/dependency_audit.md`
- `references/seed_usage.md`
- `references/poc_policy.md`
- `references/env_setup.md`
- `references/verification_policy.md`
- `references/taint_tracking.md`
- `references/rule_validation.md`
- `references/tooling.md`
