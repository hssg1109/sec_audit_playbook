## Task: 4-1 Data Protection
**Dependencies**: task_11
**Inputs**: `state/task_11_result.json`
**Output**: `state/task_41_result.json` (schema: `schemas/task_output_schema.json`)
**Parallel Safe**: Yes

### Quality gates
- Evidence for encryption in transit and at rest
- Include data exposure checks

### Rollback procedure
- If validation fails, fix JSON and re-run `tools/scripts/validate_task_output.py`
