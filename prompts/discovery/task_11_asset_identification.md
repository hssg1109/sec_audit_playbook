## Task: 1-1 Asset Identification
**Dependencies**: none
**Inputs**: inventory docs, system diagrams, ownership lists
**Output**: `state/task_11_result.json` (schema: `schemas/task_output_schema.json`)
**Parallel Safe**: Yes

### Quality gates
- At least one evidence item per identified asset
- Include asset owner and data sensitivity

### Rollback procedure
- If validation fails, fix JSON and re-run `tools/scripts/validate_task_output.py`
