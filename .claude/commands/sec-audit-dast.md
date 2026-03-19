---
allowed-tools: Read, Glob, Grep, Bash, Edit, Write, Agent, WebFetch
description: 라이브 대상 DAST/ASM 워크플로 실행 — URL/IP 트랙 스캔 후 SARIF 출력
---

# DAST / ASM Security Audit

대상: $ARGUMENTS (URL 또는 IP 목록)

## 실행 절차

### 1. SKILL 로드
`skills/sec-audit-dast/SKILL.md`를 읽어 전체 워크플로를 파악한 뒤, 아래 reference 파일들을 읽어라:
- `skills/sec-audit-dast/references/asm_sources.md`
- `skills/sec-audit-dast/references/asm_scripts.md`
- `skills/sec-audit-dast/references/asm_csv.md`
- `skills/sec-audit-dast/references/sarif_conversion.md`
- `skills/sec-audit-dast/references/severity_criteria.md`
- `skills/sec-audit-dast/references/reporting_summary.md`
- `skills/SEVERITY_CRITERIA_DETAIL.md`

### 2. 워크플로 실행
`asm_sources.md`에 정의된 트랙을 대상에 맞게 선택하여 실행:
- **URL Track**: discovery → probing → scanners → SARIF 출력
- **IP Track**: IP 목록 → 서비스/데몬 탐지 → SARIF 출력

### 3. 출력 정규화
모든 스캔 결과를 SARIF 형식으로 변환 후 보고서 생성.
