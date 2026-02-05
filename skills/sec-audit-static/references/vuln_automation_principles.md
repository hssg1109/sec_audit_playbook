# Vulnerability Analysis Automation Principles

## Discovery → Analysis split
- **Discovery:** fast, low-cost signal collection (regex/rg, Semgrep, Joern seed, API inventory).
- **Analysis:** focused, high-precision reasoning on a reduced candidate set.
- Keep discovery outputs cached and reused to reduce token cost.

## Iterative hypothesis loop
- Use a repeatable loop: **Hypothesis → Evidence → PoC → Re-check**.
- Record outcomes in metadata (confirmed/failed, PoC status, rule validation).

## Tooling choices
- **No CodeQL.** Use **Joern** for flow-based checks.
- Semgrep is preferred for lightweight pattern discovery.
- Gitleaks is primary for secret detection.

## Token efficiency
- Prefer scripts for extraction (API inventory, seed generation, diff-based re-scan).
- Re-run only affected phases when rules change.
- Use cached seeds to avoid re-tokenizing unchanged code.
