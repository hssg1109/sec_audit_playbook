---
allowed-tools: Read, Glob, Grep, Bash, Edit, Write, Agent, WebFetch
description: 외부 소프트웨어 분석 — 바이너리/패키지 디컴파일, 리버싱, 정적 분석, 퍼징, 취약점 증거 수집 후 Markdown 보고서 생성
---

# External Software Analysis

대상: $ARGUMENTS (바이너리 경로 또는 패키지명)

## 실행 절차

### 1. SKILL 로드
`skills/external-software-analysis/SKILL.md`를 읽어 전체 워크플로를 파악한 뒤, 아래 reference 파일들을 읽어라:
- `skills/external-software-analysis/references/external_sources.md`
- `skills/external-software-analysis/references/severity_criteria.md`
- `skills/external-software-analysis/references/reporting_summary.md`
- `skills/SEVERITY_CRITERIA_DETAIL.md`

### 2. 분석 실행
`external_sources.md`의 케이스 템플릿에 따라:
1. 디컴파일 → 정적 스캔 → 플로우 추적 → 증거 수집
2. 취약점 발견 시 severity_criteria에 따라 위험도 분류

### 3. 보고서 생성
`external_sources.md`의 레퍼런스 보고서 구조를 따라 Markdown 보고서 작성.
