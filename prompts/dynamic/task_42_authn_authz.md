## Task: 4-2 Authentication and Authorization
**Dependencies**: task_11
**Inputs**: `state/task_11_result.json`
**Output**: `state/task_42_result.json` (schema: `schemas/task_output_schema.json`)
**Parallel Safe**: Yes

### Quality gates
- Evidence for auth flow and role enforcement
- Minimum 2 tests per critical role

### Rollback procedure
- If validation fails, fix JSON and re-run `tools/scripts/validate_task_output.py`
