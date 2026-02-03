# 00. 보안 진단 프로세스 개요

## 목적
AI 기반 정적 분석 특화 보안 진단 자동화 시스템의 전체 프로세스를 정의합니다.

## 입력
- **자산 정보 Excel 파일**: 고객 제공 자산 목록 (서버, 도메인, 기술 스택 등)
- **로컬 소스코드**: 진단 대상 애플리케이션 소스코드

## 진단 단계 (3 Phase / 5 Task)

```
Phase 1: 자산 식별 (Asset Identification)
  └── Task 1-1: 자산 목록 작성 (Excel 파싱 + 소스코드 분석)
          ↓
Phase 2: 정적 분석 (Static Analysis)
  ├── Task 2-1: API 인벤토리 추출 ──┐
  │                                  ↓ (2-1 완료 후 병렬)
  ├── Task 2-2: 인젝션 취약점 검토 ──┤
  ├── Task 2-3: XSS 취약점 검토 ─────┤
  └── Task 2-4: 파일 처리 검토 ──────┘
          ↓
Phase 3: 보고서 생성 (Reporting)
  └── merge_results.py 자동 실행
```

## 핵심 원칙
1. **정적 분석 특화**: 소스코드 수준의 취약점 식별에 집중
2. **병렬 처리**: Task 2-2, 2-3, 2-4는 2-1 완료 후 동시에 수행
3. **의존성 관리**: `workflows/audit_workflow.yaml`에 정의된 순서 준수
4. **상태 추적**: 모든 작업 결과는 `state/` 폴더에 JSON으로 저장
5. **품질 보증**: `schemas/`의 JSON 스키마로 결과물 자동 검증
6. **보안 준수**: `ai/REDACTION_RULES.md`에 따른 민감정보 마스킹

## 참조 문서
- 작업 절차서: `docs/` 폴더 내 각 단계별 문서
- 워크플로우: `workflows/audit_workflow.yaml`
- 프롬프트: `prompts/static/` 폴더
- 스키마: `schemas/` 폴더
