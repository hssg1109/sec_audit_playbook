# SARIF Conversion

When ASM/DAST outputs are produced in CSV/TSV, normalize them to SARIF using:

- `tools/scripts/sarif_from_csv.py`

Expected headers:
- `rule_id`, `message`, `uri`, `severity` (optional), `line` (optional), `column` (optional)

Example:
```bash
python tools/scripts/sarif_from_csv.py --in data/outputs/findings.csv --out data/outputs/results.sarif --tool-name "asm-dast"
```
