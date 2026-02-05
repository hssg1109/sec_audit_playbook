# Rule Validation

After generating detection rules, always validate them:

- Semgrep: run new rules against the target module and verify hits.
- Joern: execute the query script and confirm expected nodes.

Record validation status in JSON metadata:
```json
"metadata": {
  "rule_validation": {
    "semgrep": "passed|failed",
    "joern": "passed|failed"
  }
}
```
