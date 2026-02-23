# AI Security Audit Playbook

This is a security audit automation framework for static/dynamic code analysis.

## Skills

The following skills are available for security audits:

- `/sec-audit-static` - Static code security analysis (SAST)
- `/sec-audit-dast` - Dynamic application security testing (DAST)
- `/external-software-analysis` - External software/package analysis

## Project Structure

- `skills/` - Self-contained skill definitions (diagnosis criteria, schemas, prompts, rules)
- `tools/scripts/` - Automation scripts
- `docs/` - Procedure documentation (Confluence publishing)
- `state/` - Scan results and reports (gitignored)
- `testbed/` - Target source code for analysis (gitignored)

## Quick Start

1. Place target source code in `testbed/<project-name>/`
2. Run `/sec-audit-static` to start static analysis workflow
3. Results are saved to `state/` directory

## Available Scripts

- `scan_api.py` - API endpoint inventory extraction
- `scan_injection_enhanced.py` - SQL/Command/SSI injection detection
- `scan_injection_patterns.py` - Pattern-based vulnerability detection
- `generate_finding_report.py` - Markdown report generation
- `publish_confluence.py` - Wiki publishing
