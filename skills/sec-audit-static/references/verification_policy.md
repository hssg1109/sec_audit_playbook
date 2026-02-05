# Verification (Commit-Specific)

When the user requests a remediation/verification check ("이행점검"), always:

1) Ask for the target commit hash.
2) Check out that commit in the repo.
3) Run PoC or verification tests against that commit only.
4) Report results referencing the commit hash.

Do not run verification against other branches or HEAD unless explicitly requested.
