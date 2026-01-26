# Governance

## Source of truth
- Files in `state/` are the source of truth for execution status and findings.
- All task outputs must be written to `state/task_<id>_result.json` and validated.

## Change control
- Commit after each phase (Discovery, Static, Dynamic, Dependency Scan, Reporting).
- No manual editing of `state/` files; always use task execution + validation.

## Roles
- Audit Lead: owns workflow coordination and approval gates.
- Task Owner: executes tasks and submits validated state files.
- Reviewer: verifies evidence and compliance with schemas.

## Retention
- Keep `state/` for 1 year or as required by policy.
- Redact secrets and PII from evidence artifacts.

## Exceptions
- Any exception to these rules requires written approval in the PR.
