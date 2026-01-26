## Task: 3-3 XSS Review
**Dependencies**: task_31
**Inputs**: `state/task_31_result.json`
**Output**: `state/task_33_result.json` (schema: `schemas/task_output_schema.json`)
**Parallel Safe**: Yes

### Quality gates
- Evidence for each rendered output sink
- Confirm encoding/sanitization strategy

### Rollback procedure
- If validation fails, fix JSON and re-run `tools/scripts/validate_task_output.py`
