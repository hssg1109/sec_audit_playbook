## Task: 3-1 API Inventory
**Dependencies**: task_11
**Inputs**: `state/task_11_result.json`
**Output**: `state/task_31_result.json` (schema: `schemas/task_output_schema.json`)
**Parallel Safe**: Yes

### Quality gates
- Include method, path, auth requirement, data sensitivity
- Minimum 3 evidence items per API group

### Rollback procedure
- If validation fails, fix JSON and re-run `tools/scripts/validate_task_output.py`
