# Seed Usage (Semgrep / Joern)

When running tasks 2-3, 2-4, 2-5, incorporate semgrep and joern outputs as seed signals.
For secrets/data-protection (2-5), use Gitleaks as the primary seed source and keep Semgrep as fallback for config patterns.
If any confirmed finding lacks a corresponding Semgrep/Joern rule, you must create the rule and re-run seed generation before finalizing.

Guidance:
- Use seed outputs to prioritize review, but confirm findings in code.
- Do not include seed content in the final Markdown report.
- Record seed usage only in JSON metadata.
- If seed rules are updated, re-run seed generation and re-review any affected findings before finalizing reports.

Metadata field:
```json
"metadata": {
  "seed_used": true,
  "seed_sources": ["state/seed_gitleaks.json", "state/seed_semgrep.json", "state/seed_joern.json"]
}
```
