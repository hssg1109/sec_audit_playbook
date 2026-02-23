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

## Kotlin-Specific Taint Patterns

Kotlin SQL Builder functions require special attention:

### String Template Injection
```
Source: @RequestParam / @PathVariable (String type)
  → Controller method parameter
    → Service method argument
      → Repository method argument
        → Kotlin fun parameter
          → Sink: "$param" or "${expr}" inside SQL string literal
```

### Cross-File Tracing
Kotlin top-level functions (e.g., `Comment.kt`, `FeedQuery.kt`) are called from Java repositories via `XxxKt.methodName()`. Trace:
```
Java Repository: BatchKt.createFeedTodayByTotal(topicName)
  → Kotlin file: Batch.kt → fun createFeedTodayByTotal(topicName: String)
    → SQL: '$topicName'
```

### Delegate Function Tracing
Kotlin functions may delegate to other functions in the same file:
```
fun getCommentList(...) = selectCommentList(...)  // delegates
fun selectCommentList(ordering: String): String { ... SQL with $ordering ... }
```
Trace delegate chains up to depth 3.

### False Positive Indicators
- Parameter type is `Long`, `Int`, `Boolean` → cannot inject SQL
- Value is hardcoded in Service layer (e.g., `"free"`, `"mission"`)
- Value comes from `@Value` Spring config (check type)
- Calling code is in commented-out class (`/* ... */`)
- Switch/if branch doesn't reach vulnerable method

→ See `references/cross_verification.md` for full procedure.

## Rule Storage

Store rules under:
- `skills/sec-audit-static/references/rules/semgrep/`
- `skills/sec-audit-static/references/rules/joern/`
