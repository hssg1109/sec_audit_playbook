## Task: 2-1 Static Analysis Request
**Dependencies**: task_11
**Inputs**: `state/task_11_result.json`
**Output**: `state/task_21_result.json` (schema: `schemas/task_output_schema.json`)
**Parallel Safe**: Yes

### Quality gates
- Evidence of request submission (ticket ID or email)
- Tool versions and scope documented

### Rollback procedure
- If validation fails, fix JSON and re-run `tools/scripts/validate_task_output.py`
