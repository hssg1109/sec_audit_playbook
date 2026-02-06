# 20. 정적 분석 (Static Analysis)

## Phase 2 - Static Analysis

### 목적
소스코드 수준에서 보안 취약점을 식별합니다. 실행 없이 코드 자체를 분석하는 단계입니다.

### 사전 조건
- Phase 1 (자산 식별) 완료
- `state/task_11_result.json` (자산 목록) 존재
- 소스코드 접근 가능

### 작업 흐름
```
Task 2-1 (API 인벤토리)
    │
    ├──→ Task 2-2 (인젝션 검토)     ──┐
    ├──→ Task 2-3 (XSS 검토)        ──┤
    ├──→ Task 2-4 (파일 처리 검토)   ──├──→ Phase 3 (보고서)
    └──→ Task 2-5 (데이터 보호 검토) ──┘
```

**Task 2-1은 선행 필수**, 2-2/2-3/2-4/2-5는 2-1 완료 후 병렬 실행 가능

### 파일 탐색 전략 (토큰 최적화)

모든 진단 태스크는 전체 소스코드를 탐색하지 않고, API 인벤토리 기반으로 필요한 파일만 추적합니다:

```
API 목록 → Controller → Service → Repository/Mapper/DAO
```

### 하위 작업

| Task | 문서 | 프롬프트 | 출력 |
|------|------|----------|------|
| 2-1 API 인벤토리 | `21_api_inventory.md` | `task_21_api_inventory.md` | `task_21_result.json` |
| 2-2 인젝션 검토 | `22_injection_review.md` | `task_22_injection_review.md` | `task_22_result.json` |
| 2-3 XSS 검토 | `23_xss_review.md` | `task_23_xss_review.md` | `task_23_result.json` |
| 2-4 파일 처리 검토 | `24_file_handling_review.md` | `task_24_file_handling.md` | `task_24_result.json` |
| 2-5 데이터 보호 검토 | `25_data_protection_review.md` | `task_25_data_protection.md` | `task_25_result.json` |

### 완료 기준
- [ ] 모든 하위 Task 결과 JSON 생성
- [ ] JSON 스키마 검증 통과
- [ ] 발견된 취약점 severity 분류 완료
- [ ] Phase 3 (보고서 생성) 진입 준비 완료
- [ ] 모든 Task 결과의 `metadata`에 `source_repo_url`, `source_repo_path`, `source_modules` 포함
- [ ] 위키 배포 시 `report_wiki_url`과 `report_wiki_status` 기록
- [ ] Confluence(md2cf) 업로드 시 `--anchor-style md2cf` 사용 (헤더 기반 앵커)
