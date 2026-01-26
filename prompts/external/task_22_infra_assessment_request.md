## Task: 2-2 Infrastructure Assessment Request
**Dependencies**: task_11
**Inputs**: `state/task_11_result.json`
**Output**: `state/task_22_result.json` (schema: `schemas/task_output_schema.json`)
**Parallel Safe**: Yes

### Quality gates
- Evidence of request submission
- Scope and environments documented

### Rollback procedure
- If validation fails, fix JSON and re-run `tools/scripts/validate_task_output.py`
