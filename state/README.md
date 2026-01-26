# State Tracking

The `state/` folder stores task outputs and is the source of truth for audit execution.

## Format
Each task writes `state/task_<id>_result.json` matching `schemas/task_output_schema.json`.

Example:
{
  "task_id": "3-2",
  "status": "completed",
  "findings": [],
  "evidence_refs": [],
  "executed_at": "2025-01-26T10:30:00Z",
  "claude_session": "abc123",
  "metadata": {
    "reviewer": "jane.doe",
    "inputs": ["state/task_31_result.json"]
  }
}

## Retention
Keep state for at least 1 year unless policy requires otherwise.
