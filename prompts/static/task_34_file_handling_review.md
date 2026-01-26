## Task: 3-4 File Handling Review
**Dependencies**: task_31
**Inputs**: `state/task_31_result.json`
**Output**: `state/task_34_result.json` (schema: `schemas/task_output_schema.json`)
**Parallel Safe**: Yes

### Quality gates
- Evidence for upload, download, and file path usage
- Validate content-type and path traversal controls

### Rollback procedure
- If validation fails, fix JSON and re-run `tools/scripts/validate_task_output.py`
