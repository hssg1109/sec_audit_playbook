# Audit Workflow Definition

## Phase 구조

```
Phase 1: 자산 식별
  └─ Task 1-1: 자산 목록 작성

Phase 2: 정적 분석
  ├─ Task 2-1: API 인벤토리 추출 (선행)
  └─ 병렬 실행 (2-1 완료 후):
     ├─ Task 2-2: 인젝션 취약점 검토
     ├─ Task 2-3: XSS 취약점 검토
     ├─ Task 2-4: 파일 처리 검토
     └─ Task 2-5: 데이터 보호 검토

Phase 3: 교차검증 + 수동 심층진단
  ├─ Phase 3-1: 자동 스캔 "취약" 건에 대해 데이터 흐름 교차검증
  └─ Phase 3-2: "정보/수동검토(needs_review:true)" 건에 대해 LLM 수동 심층진단

Phase 4: 보고서 생성
  ├─ merge_results.py (결과 병합)
  ├─ redact.py (민감정보 마스킹)
  ├─ validate_task_output.py (스키마 검증)
  └─ generate_finding_report.py (마크다운 보고서)
```

## Task별 프롬프트

각 태스크의 상세 진단 기준 및 실행 지침:
- `task_prompts/task_11_asset_identification.md`
- `task_prompts/task_21_api_inventory.md`
- `task_prompts/task_22_injection_review.md`
- `task_prompts/task_23_xss_review.md`
- `task_prompts/task_24_file_handling.md`
- `task_prompts/task_25_data_protection.md`

## 실행 순서

1. testbed에 소스코드 배치: `testbed/<project-name>/`
2. (선택) 자산 Excel 파싱: `parse_asset_excel.py`
3. API 인벤토리: `scan_api.py <source_dir> -o state/<prefix>_api_inventory.json`
4. 인젝션 진단: `scan_injection_enhanced.py <source_dir> --api-inventory <inventory.json> -o state/<prefix>_task22.json`
4b. XSS 진단: `scan_xss.py <source_dir> --api-inventory <inventory.json> -o state/<prefix>_task23.json`
4c. 파일 처리 진단: `scan_file_processing.py <source_dir> --api-inventory <inventory.json> -o state/<prefix>_task24.json`
4d. 데이터 보호 진단: `scan_data_protection.py <source_dir> --api-inventory <inventory.json> -o state/<prefix>_task25.json`
5. 교차검증 (Phase 3-1): LLM이 취약 건에 대해 데이터 흐름 추적
5b. 수동 심층진단 (Phase 3-2): 정보/수동검토(needs_review:true) 건에 대해 manual_review_prompt.md 기반 LLM 분석
   - Task 2-5 수동 진단: 케이스 A (하드코딩 시크릿 Prod/테스트 판별), 케이스 B (민감정보 로깅 마스킹 검증), 케이스 C (커스텀 암호화 안전성 검증)
6. View XSS/파일처리 LLM 심층분석: task_prompts/task_23_xss_review.md, task_prompts/task_24_file_handling.md 프롬프트 기준
7. 결과 병합 및 보고서 생성

## 보안 정책

- 고객 DB 자격증명, API 시크릿 등은 AI 프롬프트에 포함 금지
- 고객 PII는 마스킹 없이 AI에 전달 금지
- AI 결과는 반드시 검증 후 최종 보고서에 반영
- 실제 공격 Exploit 코드 생성 금지
