# Secret Scanning

Primary tool: **Gitleaks**

Usage (preferred):
- `tools/scripts/run_gitleaks.sh --repo /path/to/repo --out state/seed_gitleaks.json`

Notes:
- Use `--redact` to avoid leaking secrets in reports.
- Set `--exit-code 0` so CI/automation does not fail on findings.
- Keep Semgrep config-based checks as fallback.
