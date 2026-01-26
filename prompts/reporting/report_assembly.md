## Report Assembly
**Dependencies**: task_60
**Inputs**: `state/task_60_result.json`, templates under `templates/report/`
**Output**: final report in `reports/` (not tracked in schema)
**Parallel Safe**: No

### Quality gates
- All findings mapped to evidence and mitigations
- Use templates and include remediation plan

### Rollback procedure
- Fix report and re-run validation checklist
