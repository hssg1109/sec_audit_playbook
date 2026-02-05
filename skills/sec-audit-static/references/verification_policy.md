# Verification (Commit-Specific)

When the user requests a remediation/verification check ("이행점검"), always:

1) Ask for the target commit hash.
2) Check out that commit in the repo.
3) Run PoC or verification tests against that commit only.
4) Report results referencing the commit hash.

Do not run verification against other branches or HEAD unless explicitly requested.

For verification PoC setup, use the shared artifacts repository branch:
- `audit_result` repo `artifacts` branch
- Apply tests via `artifacts/pcona-ad/apply.sh --repo /path/to/pcona-ad`
- Apply tests via `artifacts/pcona-console/apply.sh --repo /path/to/pcona-console`

Kotlin/Maven PoC runs:
- Use `./mvnw -q test -DfailIfNoTests=false` to avoid JUnit5 provider mismatch from `-Dtest` patterns.
