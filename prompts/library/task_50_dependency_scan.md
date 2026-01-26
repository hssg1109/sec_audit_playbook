## Task: 5 Dependency Scan
**Dependencies**: task_11
**Inputs**: `state/task_11_result.json`
**Output**: `state/task_50_result.json` (schema: `schemas/task_output_schema.json`)
**Parallel Safe**: Yes

### Quality gates
- Evidence of tool output and version
- Each finding maps to a dependency and CVE if applicable

### Rollback procedure
- If validation fails, fix JSON and re-run `tools/scripts/validate_task_output.py`
