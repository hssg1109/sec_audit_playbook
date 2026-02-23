# Reporting Summary (Common Index)

Use a single JSON index to summarize all analysis outputs across skills.

Schema:
- `references/output_schemas.md` (reporting summary section, TBD)

Generator:
- `tools/scripts/generate_reporting_summary.py`

Severity mapping:
- `references/severity_criteria.md`

Required source fields (analysis entry):
- `source_repo_url`, `source_repo_path`, `source_modules`

Optional wiki fields (analysis entry):
- `report_wiki_url`, `report_wiki_page_id`, `report_wiki_status`
