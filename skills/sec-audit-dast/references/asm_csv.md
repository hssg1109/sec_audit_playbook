# ASM CSV Extraction

Use this script to extract basic CSV findings from common ASM outputs, then convert to SARIF:

- `tools/scripts/asm_findings_to_csv.py`

Example:
```bash
python tools/scripts/asm_findings_to_csv.py \
  --httpx data/outputs/httpx_full.txt \
  --out data/outputs/findings.csv

python tools/scripts/sarif_from_csv.py \
  --in data/outputs/findings.csv \
  --out data/outputs/results.sarif \
  --tool-name "asm-dast"
```
