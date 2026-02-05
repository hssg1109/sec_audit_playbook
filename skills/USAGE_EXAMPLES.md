# Skill Usage Examples

## sec-audit-static
Trigger examples:
- "이 코드베이스 정적 분석해줘"
- "SAST/SCA/시크릿 탐지 결과 JSON으로 만들어줘"
- "정적 진단 결과를 스키마에 맞게 검증해줘"

Flow summary:
1. Load static references and severity criteria.
2. Run Phase 1/2 tasks; output task JSONs.
3. Merge -> redact -> validate.
4. Update reporting summary JSON.

## sec-audit-dast
Trigger examples:
- "URL 타깃 DAST/ASM 스캔 돌려줘"
- "IP 리스트 기반으로 서비스 감지 스캔하고 SARIF로 출력해줘"
- "ASM 파이프라인 실행해줘"

Flow summary:
1. Load ASM docs/scripts and severity criteria.
2. Run URL or IP track.
3. Extract CSV (if needed) -> convert to SARIF.
4. Update reporting summary JSON.

Example:
```bash
python tools/scripts/asm_findings_to_csv.py --httpx data/outputs/httpx_full.txt --out data/outputs/findings.csv
python tools/scripts/sarif_from_csv.py --in data/outputs/findings.csv --out data/outputs/results.sarif --tool-name "asm-dast"
```

## external-software-analysis
Trigger examples:
- "외부 솔루션 바이너리 분석 절차대로 보고서 써줘"
- "디컴파일 기반 취약점 발견 과정 정리해줘"

Flow summary:
1. Load external analysis references.
2. Apply discovery flow and collect evidence.
3. Produce Markdown report.
4. Update reporting summary JSON.

## Common summary
```bash
python tools/scripts/generate_reporting_summary.py \
  --config skills/REPORTING_SUMMARY_CONFIG.json \
  --out state/reporting_summary.json
```
