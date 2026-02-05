# Taint Tracking Requirement

When identifying findings, explicitly confirm taint flow:

- Source: user-controlled input (request param, header, body, or DB content derived from user input)
- Transform: any validation/sanitization or intermediate processing
- Sink: execution point (template rendering, query building, file IO, etc.)

Only promote a candidate to a confirmed finding when a Source -> Sink path is demonstrated.

For every confirmed finding, generate or update detection rules (mandatory unless explicitly waived):
- Semgrep rules (pattern-based)
- Joern queries (flow-based)

Note: In Kotlin/Reactive codebases, Joern dataflow may be sparse. In that case, record a heuristic flow within the same method (e.g., identifier or field access to sink) and still capture the source/sink evidence.
If only heuristic flow is possible, explicitly mark it as `heuristic: true` in the emitted seed metadata.

Store rules under:
- `skills/sec-audit-static/references/rules/semgrep/`
- `skills/sec-audit-static/references/rules/joern/`
