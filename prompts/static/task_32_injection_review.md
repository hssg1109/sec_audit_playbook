## Task: 3-2 Injection Review
**Dependencies**: task_31
**Inputs**: `state/task_31_result.json`
**Output**: `state/task_32_result.json` (schema: `schemas/task_output_schema.json`)
**Parallel Safe**: Yes

### Quality gates
- Each finding must include evidence ref and taint path
- Validate at least one input sink per critical API

### Rollback procedure
- If validation fails, fix JSON and re-run `tools/scripts/validate_task_output.py`
