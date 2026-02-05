---
name: external-software-analysis
description: External software analysis workflows for binaries/packages (decompilation, reverse engineering, static analysis, fuzzing, and evidence collection). Use when analyzing third-party software without source access.
---

# External Software Analysis

## Overview
Guide external software analysis from decompilation to vulnerability discovery and evidence collection. Output is a structured Markdown report.

## Workflow
1. Read `references/external_sources.md` for the canonical case template.
2. Apply the discovery process (decompile -> static scan -> flow tracing -> evidence).
3. Produce a Markdown report following the reference report structure.
4. When summarizing, map severity using `references/severity_criteria.md` and `skills/SEVERITY_CRITERIA_DETAIL.md`.

## Reporting
- Primary output: Markdown report (example reference provided).
- Use severity mapping from `references/severity_criteria.md` and detailed criteria in `skills/SEVERITY_CRITERIA_DETAIL.md`.
- Produce a common summary JSON using `schemas/reporting_summary_schema.json`.

## Resources
### references/
- `references/external_sources.md`
- `references/severity_criteria.md`
- `references/reporting_summary.md`
