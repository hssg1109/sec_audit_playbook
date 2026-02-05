# PoC Policy (When Possible)

PoC generation is **best-effort only**. If there is no runnable environment, document the need for manual verification.

Preferred order:
1. JUnit5 integration test (default)
2. Playwright (web UI flows)
3. Jazzer fuzzing (parser/serializer)
4. ZAP (DAST verification)

Rules:
- If a PoC is feasible with best-effort local setup, implement it without pausing to ask.
- Create PoC tests for every confirmed finding **and each distinct instance** (file:line) unless explicitly waived by the user.
- Only ask the user when execution is blocked by missing prerequisites.
- Do not attempt PoC if no runnable test environment exists.
- After PoC execution, revert local repo changes (tests, build artifacts, patched config) unless the user requests to keep them.
- Record PoC feasibility in JSON metadata:
```json
"metadata": {
  "poc_status": "not_run | manual_required | implemented",
  "poc_reason": "no test environment",
  "poc_method": "junit5 | playwright | jazzer | zap"
}
```
