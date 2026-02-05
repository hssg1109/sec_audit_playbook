# Taint Tracking Requirement

When identifying findings, explicitly confirm taint flow:

- Source: user-controlled input (request param, header, body, or DB content derived from user input)
- Transform: any validation/sanitization or intermediate processing
- Sink: execution point (template rendering, query building, file IO, etc.)

Only promote a candidate to a confirmed finding when a Source -> Sink path is demonstrated.

If a finding is confirmed with taint flow, generate or update detection rules:
- Semgrep rules (pattern-based)
- Joern queries (flow-based)

Store rules under:
- `skills/sec-audit-static/references/rules/semgrep/`
- `skills/sec-audit-static/references/rules/joern/`
