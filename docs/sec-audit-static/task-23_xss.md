# Task 2-3 — XSS 진단

> **관련 파일**
> - 자동 스캔: `tools/scripts/scan_xss.py`
> - LLM 프롬프트: `skills/sec-audit-static/references/task_prompts/task_23_xss_review.md`
> - 전역 필터: `skills/sec-audit-static/references/global_filters.md`
> **스크립트 버전**: v2.5.0 (2026-03-06)
> **최종 갱신**: 2026-03-09

---

## 진단 항목

| 유형 | CWE | 설명 |
|------|-----|------|
| Reflected XSS | CWE-79 | HTTP 파라미터 → 응답 직접 반영 |
| Persistent XSS | CWE-79 | HTTP 파라미터 → DB 저장 → 조회 시 출력 |
| DOM XSS | CWE-79 | innerHTML, document.write, eval 등 |
| View XSS | CWE-79 | JSP `${}`, Thymeleaf `th:utext`, Handlebars `{{{` |
| Open Redirect | CWE-601 | 사용자 입력 → sendRedirect / location.href |
| XSS Filter 우회 | CWE-79 | Lucy XSS Filter multipart 범위 미흡 |

---

## 6단계 진단 흐름 (scan_xss.py)

```mermaid
flowchart TD
    EP["api_inventory.json 엔드포인트"] --> P1

    subgraph P1["Phase 1: Controller 분류 + Content-Type 판정"]
        R1{"@RestController\nor @ResponseBody?"}
        R1 -->|Yes| JSON_API["JSON API\n→ Phase 3 (전역 필터) 확인"]
        R1 -->|No| P2_CHK["@Controller + String/ModelAndView\n→ Phase 2 (View 렌더링)"]
        R1 -->|produces=text/html| VULN1["🚨 취약: Reflected XSS\n(REST API가 HTML 반환)"]
    end

    subgraph P2["Phase 2: View 렌더링 추적 (Outbound Escaping)"]
        P2_CHK --> VIEW{"View 엔진"}
        VIEW -->|JSP| JSP["${value} → 취약\nc:out / fn:escapeXml → 양호"]
        VIEW -->|Thymeleaf| TH["th:utext → 취약\nth:text → 양호"]
        VIEW -->|Handlebars| HB["{{{var}}} → 취약\n{{var}} → 양호"]
    end

    subgraph P3["Phase 3: 전역 XSS 필터 탐지 (Inbound Sanitizing)"]
        JSON_API --> FILTER{"Lucy / AntiSamy / ESAPI\n존재?"}
        FILTER -->|없음| INFO1["⚠️ 정보: 전역 필터 미설정"]
        FILTER -->|Lucy 존재| MULTIPART{"MultipartFilter 순서\n검증 (Bypass 위험)"}
        MULTIPART -->|multipart 미적용| VULN2["🚨 취약: Lucy 우회 가능\n(multipart 요청)"]
        MULTIPART -->|올바른 순서| SAFE1["✅ 양호"]
    end

    subgraph P4["Phase 4: Open Redirect 탐색"]
        P4A["sendRedirect(userInput)\nreturn 'redirect:' + var"]
        P4B["location.href=\nwindow.location="]
        P4A & P4B --> VULN3["🚨 취약: Open Redirect"]
    end

    subgraph P5["Phase 5: Persistent XSS Taint Tracking"]
        P5_IN["HTTP param\n(자유텍스트 확인)"] --> P5_SVC["Service 계층 추적"]
        P5_SVC --> P5_REPO["Repository write 탐지\nsave / insert / update"]
        P5_REPO -->|전역 필터 미적용 + taint 확정| VULN4["🚨 취약: Persistent XSS"]
        P5_REPO -->|전역 필터 적용| SAFE2["✅ 양호"]
    end

    subgraph P6["Phase 6: DOM XSS 전역 스캔"]
        P6A["innerHTML=\ndocument.write()\neval()\ndangerouslySetInnerHTML\ninnerAdjacentHTML()\njQuery .html()\nVue v-html"]
        P6A --> VULN5["🚨 취약: DOM XSS"]
    end
```

---

## 자유텍스트 파라미터 판별 로직

XSS가 성립하려면 공격자가 임의 문자열을 주입할 수 있어야 합니다. 스크립트는 파라미터를 아래 기준으로 필터링합니다.

```mermaid
flowchart LR
    PARAM["파라미터 목록"] --> CHK{"타입 검사"}
    CHK -->|Integer / Boolean / UUID / Enum / 날짜| SAFE["자유텍스트 없음\n→ Phase 5 양호 조기 반환"]
    CHK -->|String / Object / 미확인| FREE["자유텍스트 가능\n→ Taint 추적 계속"]
    FREE --> DTO_CHK{"@RequestBody DTO?"}
    DTO_CHK -->|모든 필드 비-자유텍스트| SAFE
    DTO_CHK -->|String 필드 포함| FREE2["Taint 소스 확정"]
```

---

## 스크립트 주요 함수 맵

```
scan_xss.py
├── scan_xss_endpoints()               ← 진단 진입점
│   ├── _check_controller_type()       ← Phase 1: Controller 분류
│   ├── _check_view_rendering()        ← Phase 2: View 렌더링 추적
│   ├── _check_global_xss_filter()     ← Phase 3: 전역 필터 탐지
│   │   └── _check_lucy_multipart()    ← Lucy multipart bypass 검증
│   ├── _check_redirect()              ← Phase 4: Open Redirect
│   ├── check_persistent_xss()         ← Phase 5: Persistent XSS
│   │   ├── _has_freetext_params()     ← 자유텍스트 파라미터 판별
│   │   ├── _inspect_dto_fields()      ← DTO 필드 1레벨 검사 (v2.3.2)
│   │   ├── _resolve_svc_impl_body()   ← Hexagonal: 구현체 해석 (v2.3.1)
│   │   ├── _check_repo_param_context() ← SET vs WHERE 절 구분 (v2.3.0)
│   │   └── _has_param_in_direct_call() ← HTTP 파라미터 직접 전달 확인
│   └── judge_xss_endpoint()           ← Worst-case 최종 판정
└── scan_dom_xss_global()              ← Phase 6: DOM XSS 전역 스캔
```

---

## 판정 결과 카테고리

| result | severity | 조건 |
|--------|----------|------|
| 취약 | High | Reflected XSS: REST API text/html 반환 |
| 취약 | High | View XSS: th:utext / `${}` 미이스케이프 |
| 취약 | High | Persistent XSS: taint 경로 자동 확인 |
| 취약 | Medium | Persistent XSS: DB write 경로 불명 |
| 취약 | High | Open Redirect: 사용자 입력 직접 반영 |
| 취약 | High | Lucy 우회: multipart 요청 필터 미적용 |
| 정보 | Medium | 전역 XSS 필터 미설정 (수동 확인 필요) |
| 양호 | - | 파라미터 없음 / 전역 필터 적용 / 이스케이프 확인 |

---

## 산출물 구조

```json
{
  "task_id": "2-3",
  "endpoint_diagnoses": [
    {
      "no": "2-3-001",
      "check_item": "XSS",
      "result": "취약",
      "severity": "Risk 4",
      "xss_category": "reflected",
      "path": "/api/v1/error",
      "diagnosis_detail": "REST API produces=text/html — 사용자 입력 직접 반환",
      "needs_review": false
    }
  ],
  "global_findings": {
    "dom_xss": {"total": 3, "findings": [...]}
  },
  "filter_status": {
    "lucy_xss": {"found": true, "multipart_safe": false}
  }
}
```

---

## 변경 이력

> 자세한 내용은 [`RELEASE_NOTES.md`](RELEASE_NOTES.md) 참조

| 버전 | 날짜 | 요약 |
|------|------|------|
| v2.5.0 | 2026-03-06 | Context Bleed 차단, Kotlin 파싱, Protobuf 예외 |
| v2.4.0 | 2026-03-06 | mbrId/memberId 로깅 탐지, FP 수정 |
| v2.3.2 | 2026-03-04 | DTO 필드 1레벨 검사 (`_inspect_dto_fields`) |
| v2.3.1 | 2026-03-04 | Worst-case 원칙 강화, persist(new ...) 탐지 |
| v2.3.0 | 2026-03-03 | SET/WHERE 절 구분, Hexagonal 아키텍처 지원 |
| v2.2.0 | 2026-03-03 | Persistent XSS 무조건 취약 승급 |
| v2.1.0 | 2026-03-03 | FP 3종 수정 (JPA READ, Enum, AuthPrincipal) |
| v2.0.0 | 2026-03-03 | Phase 5 Taint Tracking 전면 강화 |
| v1.1.0 | 2026-02-26 | per-type 판정, Phase 6 DOM XSS |
