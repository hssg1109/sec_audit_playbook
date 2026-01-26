## Finding Writeup
**Dependencies**: static_analysis, dynamic_testing, dependency_scan
**Inputs**: `state/task_32_result.json`, `state/task_33_result.json`, `state/task_34_result.json`, `state/task_41_result.json`, `state/task_42_result.json`, `state/task_50_result.json`
**Output**: `state/task_60_result.json` (schema: `schemas/task_output_schema.json`)
**Parallel Safe**: No

### Quality gates
- Each finding must include severity rationale
- Evidence references must be traceable

### Rollback procedure
- If validation fails, fix JSON and re-run `tools/scripts/validate_task_output.py`
