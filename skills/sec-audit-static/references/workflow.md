# Audit Workflow Definition

## Phase 구조

```
Phase 1: 자산 식별
  └─ Task 1-1: 자산 목록 작성

Phase 2: 정적 분석 (자동스캔)
  ├─ Task 2-1: API 인벤토리 추출 (선행)
  └─ 병렬 실행 (2-1 완료 후):
     ├─ Task 2-2: 인젝션 자동스캔  → <prefix>_injection.json
     ├─ Task 2-3: XSS 자동스캔     → <prefix>_xss.json
     ├─ Task 2-4: 파일처리 자동스캔 → <prefix>_task24.json
     └─ Task 2-5: 데이터보호 자동스캔 → <prefix>_task25.json

Phase 3: LLM 수동분석 보완 (자동스캔 결과를 보완·갱신)
  ├─ Task 3-2: 인젝션 수동분석    → <prefix>_task22_llm.json
  │   ├─ [필수] 자동스캔 "정보/needs_review" endpoint 전수 판정
  │   │   ├─ diagnosis_type 그룹별 외부 서비스/DAO 소스 직접 확인
  │   │   ├─ [필수] "자동 판정 불가" (diagnosis_type="자동 판정 불가") → 양호 자동 처리 금지
  │   │   │   └─ 반드시 LLM이 해당 서비스/DAO 코드 직접 확인 후 판정 (Kotlin SQL 상수·동적SQL 등)
  │   │   ├─ MyBatis/iBatis XML 전수 스캔: ${} 위험패턴 여부
  │   │   └─ 판정 결과 → sqli_endpoint_review 블록 저장
  │   └─ 전역 패턴(OS Command/GroovyShell 등) 판정
  ├─ Task 3-3: XSS 수동분석       → <prefix>_task23_llm.json
  │   ├─ [필수] 자동스캔 "정보" endpoint 전수 판정
  │   │   ├─ 잠재적위협(Persistent): controller_type 확인 → REST_JSON이면 양호, 전역필터 finding 커버 확인
  │   │   ├─ 수동확인필요(HTML_VIEW 미탐지): 실제 반환타입 확인 (Protobuf/JSON=양호, JSP render=JSP 이스케이핑 확인)
  │   │   ├─ 수동확인필요(Reflected text/html): 파라미터→JSP 출력 taint 추적, escapeHtml 적용 여부
  │   │   └─ 판정 결과 → xss_endpoint_review 블록 저장
  │   └─ 전역 XSS 필터 취약점 finding 생성
  ├─ Task 3-4: 파일처리 수동분석  → <prefix>_task24_llm.json
  │   └─ needs_review 항목 IDOR/우회기법/무해화/LFI 심층 확인
  └─ Task 3-5: 데이터보호 수동분석 → <prefix>_task25_llm.json
      └─ 하드코딩 시크릿 Prod/테스트 판별, PII 로깅 마스킹 검증 (케이스 A/B/C)

Phase 4: 보고서 생성 + Confluence 게시 [필수]
  ├─ generate_finding_report.py --anchor-style md2cf --page-map tools/confluence_page_map.json
  │   └─ [권장] --asset-info state/<prefix>_task11.json  ← 서비스 설명 + 자산 구조 표 자동 삽입
  └─ publish_confluence.py (dry-run 확인 후 실행)
      ├─ main_report: 진단보고서.md (task_sources로 JSON 참조, API 인벤토리 요약 포함)
      ├─ api_inventory: <prefix>_api_inventory.json  ← API별 실제 입력값(DTO 필드 전개) 상세
      ├─ finding: <prefix>_injection.json
      │   └─ supplemental_sources: [<prefix>_task22_llm.json]  ← 한 페이지로 통합
      ├─ finding: <prefix>_xss.json
      │   └─ supplemental_sources: [<prefix>_task23_llm.json]  ← 한 페이지로 통합
      ├─ finding: <prefix>_task24.json
      │   └─ supplemental_sources: [<prefix>_task24_llm.json]  ← 한 페이지로 통합
      └─ finding: <prefix>_task25.json
          └─ supplemental_sources: [<prefix>_task25_llm.json]  ← 한 페이지로 통합
```

### 단일 finding 페이지 원칙
- 자동스캔 결과와 LLM 수동분석 보완은 **하나의 Confluence 페이지**에 게시한다.
- `confluence_page_map.json`에서 finding 항목의 `supplemental_sources` 배열에
  LLM 보완 JSON을 지정하면 `publish_confluence.py`가 자동으로 통합 렌더링한다.
- LLM 수동분석 결과만 별도 finding 페이지로 게시하지 않는다.

## Task별 프롬프트

각 태스크의 상세 진단 기준 및 실행 지침:
- `task_prompts/task_11_asset_identification.md`
- `task_prompts/task_21_api_inventory.md`
- `task_prompts/task_22_injection_review.md`
- `task_prompts/task_23_xss_review.md`
- `task_prompts/task_24_file_handling.md`
- `task_prompts/task_25_data_protection.md`

## 실행 순서

### Phase 2: 자동스캔 (스크립트)

```bash
# 1. testbed에 소스코드 배치

# 2-a. DTO 카탈로그 선행 추출 (API 인벤토리의 @RequestBody 내부 필드 해석에 사용)
python3 tools/scripts/scan_dto.py <source_dir> -o state/<prefix>_dto_catalog.json

# 2-b. API 인벤토리 (--dto-catalog 옵션으로 DTO 필드 자동 해석)
python3 tools/scripts/scan_api.py <source_dir> \
    --dto-catalog state/<prefix>_dto_catalog.json \
    -o state/<prefix>_api_inventory.json

# 3. 자동스캔 (병렬 가능)
python3 tools/scripts/scan_injection_enhanced.py <source_dir> \
    --api-inventory state/<prefix>_api_inventory.json \
    -o state/<prefix>_injection.json

python3 tools/scripts/scan_xss.py <source_dir> \
    --api-inventory state/<prefix>_api_inventory.json \
    -o state/<prefix>_xss.json

python3 tools/scripts/scan_file_processing.py <source_dir> \
    --api-inventory state/<prefix>_api_inventory.json \
    -o state/<prefix>_task24.json

python3 tools/scripts/scan_data_protection.py <source_dir> \
    --api-inventory state/<prefix>_api_inventory.json \
    -o state/<prefix>_task25.json
```

### Phase 3: LLM 수동분석 보완 (이 프롬프트의 역할)

```
입력: <prefix>_injection.json (자동스캔)
출력: <prefix>_task22_llm.json  ← supplemental (별도 finding 페이지 X)

입력: <prefix>_xss.json (자동스캔)
출력: <prefix>_task23_llm.json  ← supplemental (별도 finding 페이지 X)

입력: <prefix>_task24.json (자동스캔)
출력: <prefix>_task24_llm.json  ← supplemental (별도 finding 페이지 X)

입력: <prefix>_task25.json (자동스캔)
출력: <prefix>_task25_llm.json  ← supplemental (별도 finding 페이지 X)
```

각 task의 상세 분석 기준:
- 인젝션: `task_prompts/task_22_injection_review.md`
- XSS: `task_prompts/task_23_xss_review.md`
- 파일 처리: `task_prompts/task_24_file_handling.md`
- 데이터 보호: `task_prompts/task_25_data_protection.md`

### Phase 4: Confluence 게시

`confluence_page_map.json`에 아래 구조로 등록 후 publish:

```json
{
  "title": "테스트NN - 프로젝트명 진단",
  "entries": [
    {
      "source": "state/<prefix>_진단보고서.md",
      "type": "main_report",
      "task_sources": {
        "api": "state/<prefix>_api_inventory.json",
        "injection": "state/<prefix>_injection.json",
        "xss": "state/<prefix>_xss.json",
        "file_handling": "state/<prefix>_task24.json",
        "data_protection": "state/<prefix>_task25.json"
      }
    },
    {
      "source": "state/<prefix>_api_inventory.json",
      "title": "테스트NN - API 인벤토리",
      "type": "api_inventory"
    },
    {
      "source": "state/<prefix>_injection.json",
      "supplemental_sources": ["state/<prefix>_task22_llm.json"],
      "title": "테스트NN - 인젝션 취약점 진단 결과",
      "type": "finding"
    },
    {
      "source": "state/<prefix>_xss.json",
      "supplemental_sources": ["state/<prefix>_task23_llm.json"],
      "title": "테스트NN - XSS 취약점 진단 결과",
      "type": "finding"
    },
    {
      "source": "state/<prefix>_task24.json",
      "supplemental_sources": ["state/<prefix>_task24_llm.json"],
      "title": "테스트NN - 파일 처리 진단 결과",
      "type": "finding"
    },
    {
      "source": "state/<prefix>_task25.json",
      "supplemental_sources": ["state/<prefix>_task25_llm.json"],
      "title": "테스트NN - 데이터 보호 진단 결과",
      "type": "finding"
    }
  ]
}
```

> **API 인벤토리 페이지 (`type: "api_inventory"`) — Swagger 수준 렌더링**
>
> `api_inventory` 타입 페이지는 **반드시 포함**해야 합니다 (이전에 생략하면 API 엔드포인트 현황이 보고서에 없음).
>
> `publish_confluence.py`의 `_json_to_xhtml_api_inventory()` 렌더러가 아래 구조로 출력합니다:
>
> | 섹션 | 내용 |
> |------|------|
> | 스캔 요약 | 파일 수, 컨트롤러 수, 엔드포인트 수 |
> | HTTP 메서드별 / 인증 분류 | GET/POST/... 건수, 인증 필요/불필요 분포 |
> | 모듈별 TOC 테이블 | 모듈 → 컨트롤러 수, 전체/메서드 분포 요약 |
> | API 레퍼런스 (Swagger 스타일) | 모듈 → 컨트롤러 → **Confluence Expand 매크로** (클릭하여 펼치기) |
> | 엔드포인트 expand 내부 | 핸들러, 위치, 인증, 파라미터 테이블, DTO 필드 스키마 |
>
> **HTTP 메서드 색상 코드** (Swagger 동일 배색):
> - `GET` = 파란색, `POST` = 초록색, `PUT` = 주황색, `DELETE` = 빨간색, `PATCH` = 청록색
>
> **DTO 필드 상세(Request Body 스키마)** 표시 조건:
> `scan_dto.py` 사전 실행 + `scan_api.py --dto-catalog` 연동 완료 시 `resolved_fields` 자동 표시.
> 미연동 시 파라미터 타입(`HashMap<String,String>` 등)만 표시됨.

## 보안 정책

- 고객 DB 자격증명, API 시크릿 등은 AI 프롬프트에 포함 금지
- 고객 PII는 마스킹 없이 AI에 전달 금지
- AI 결과는 반드시 검증 후 최종 보고서에 반영
- 실제 공격 Exploit 코드 생성 금지
