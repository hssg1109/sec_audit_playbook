# Audit Workflow Definition

## 자율 완주 원칙 (CRITICAL)

> `/sec-audit-static` 실행 중 Claude는 **절대 확인 질문을 하지 않는다.**
>
> - "진행할까요?", "계속할까요?", "do you want to proceed?" 등 일체 금지.
> - Phase 1 → 2 → 3 → 4를 사용자 개입 없이 끝까지 완주한다.
> - 스크립트 실패, 빌드 오류, 파일 없음 → fallback 자동 적용 후 다음 단계 진행.
> - **유일한 예외**: 토큰/자격증명 누락 등 인간만 해결 가능한 blocking 오류 시 보고 후 대기.

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

## 진단 범위 제한 (Module-Scoped Audit)

> **적용 조건**: 진단 대상이 repo 전체가 아니라 **특정 서브모듈/패키지 경로**만 해당할 경우
> 예: 하나의 repo에서 `wv/pointcon`, `wv/shoppingtab` 두 모듈만 진단

```
┌─────────────────────────────────────────────────────────────┐
│  스코프 지정 진단 전체 흐름 (테스트29 패턴)                   │
│                                                             │
│  Phase 2: 전체 repo 스캔 → 원본 JSON (602 endpoints)        │
│      ↓                                                      │
│  Phase 2.5: _inscope JSON 생성 (54 endpoints)  ← 신규       │
│      ↓                                                      │
│  Phase 3: LLM 분석 → _inscope JSON 기준, 범위 내만 판정      │
│      ↓                                                      │
│  Phase 4: _inscope JSON으로 보고서 생성 + Confluence 게시    │
└─────────────────────────────────────────────────────────────┘
```

### Step 0: 스코프 정의 (진단 시작 전 필수 확정)

```
DIAGNOSIS_SCOPE = ["wv/pointcon", "wv/shoppingtab"]   # 진단 대상 모듈 경로 키워드
PREFIX          = "ocbwebview_wv_dev"                  # state 파일 prefix
```

스코프가 정의된 경우 아래 Phase 2.5 → Phase 3 → Phase 4 절차를 일반 전체 repo 진단과 **다르게** 수행한다.

---

### Phase 2: 자동스캔 — 전체 repo 대상 실행 (변경 없음)

스캔 스크립트는 항상 전체 repo를 대상으로 실행한다. `--modules` 지원 스크립트는 API 인벤토리 기반 필터링을 사용할 수 있으나, **scan_file_processing.py / scan_data_protection.py는 `--modules` 미지원**이므로 전체 스캔 후 Phase 2.5에서 필터링한다.

| 스크립트 | --modules 지원 | Phase 2 실행 방식 |
|---|---|---|
| `scan_injection_enhanced.py` | ✅ | `--modules` 옵션 사용 가능 (API 인벤토리 기반) |
| `scan_xss.py` | ✅ | `--modules` 옵션 사용 가능 (API 인벤토리 기반) |
| `scan_file_processing.py` | ❌ | 전체 repo 스캔 → Phase 2.5 필터링 |
| `scan_data_protection.py` | ❌ | 전체 repo 스캔 → Phase 2.5 필터링 |

> **원본 JSON은 절대 수정하지 않는다.** 전체 repo 스캔 결과는 증거로 보존한다.

---

### Phase 2.5: _inscope JSON 생성 ⬅ 스코프 지정 시 필수 신규 단계

Phase 2 완료 후, **Confluence 게시 및 보고서 생성에 사용할 필터링 JSON을 별도로 생성**한다.

#### 생성 대상 파일

| 원본 (전체 repo) | 필터링본 (in-scope) | 필터링 기준 필드 |
|---|---|---|
| `<prefix>_api_inventory.json` | `<prefix>_api_inventory_inscope.json` | `file` |
| `<prefix>_injection.json` | `<prefix>_injection_inscope.json` | `process_file` |
| `<prefix>_xss.json` | `<prefix>_xss_inscope.json` | `process_file` |
| `<prefix>_task24.json` | `<prefix>_task24_inscope.json` | `file` (findings 없으면 원본 그대로 사용) |
| `<prefix>_task25.json` | `<prefix>_task25_inscope.json` | `file` |

#### 필터링 스크립트 (Python 인라인)

```python
import json, copy

SCOPE  = ("wv/pointcon", "wv/shoppingtab")   # DIAGNOSIS_SCOPE 키워드
PREFIX = "state/ocbwebview_wv_dev"            # state 파일 경로 prefix

def in_scope(path):
    return any(s in (path or '') for s in SCOPE)

# ── API 인벤토리
with open(f"{PREFIX}_api_inventory.json") as f: api = json.load(f)
orig = api.get("endpoints", [])
api_f = copy.deepcopy(api)
api_f["endpoints"] = [e for e in orig if in_scope(e.get("file", ""))]
api_f["original_endpoint_count"] = len(orig)
api_f["scan_summary"] = {**api_f.get("scan_summary", {}),
                          "total_endpoints": len(api_f["endpoints"])}
with open(f"{PREFIX}_api_inventory_inscope.json", "w") as f:
    json.dump(api_f, f, ensure_ascii=False, indent=2)

# ── Injection
with open(f"{PREFIX}_injection.json") as f: inj = json.load(f)
orig = inj.get("endpoint_diagnoses", [])
inj_f = copy.deepcopy(inj)
inj_f["endpoint_diagnoses"] = [e for e in orig if in_scope(e.get("process_file", ""))]
inj_f["scan_metadata"] = {**inj_f.get("scan_metadata", {}),
                           "scope_filter": list(SCOPE),
                           "original_endpoint_count": len(orig),
                           "filtered_endpoint_count": len(inj_f["endpoint_diagnoses"])}
with open(f"{PREFIX}_injection_inscope.json", "w") as f:
    json.dump(inj_f, f, ensure_ascii=False, indent=2)

# ── XSS
with open(f"{PREFIX}_xss.json") as f: xss = json.load(f)
orig = xss.get("endpoint_diagnoses", [])
xss_f = copy.deepcopy(xss)
xss_f["endpoint_diagnoses"] = [e for e in orig if in_scope(e.get("process_file", ""))]
xss_f["scan_metadata"] = {**xss_f.get("scan_metadata", {}),
                           "scope_filter": list(SCOPE),
                           "original_endpoint_count": len(orig),
                           "filtered_endpoint_count": len(xss_f["endpoint_diagnoses"])}
with open(f"{PREFIX}_xss_inscope.json", "w") as f:
    json.dump(xss_f, f, ensure_ascii=False, indent=2)

# ── Data Protection
with open(f"{PREFIX}_task25.json") as f: t25 = json.load(f)
orig = t25.get("findings", [])
t25_f = copy.deepcopy(t25)
t25_f["findings"] = [f for f in orig if in_scope(f.get("file", ""))]
t25_f["original_finding_count"] = len(orig)
t25_f["filtered_finding_count"] = len(t25_f["findings"])
with open(f"{PREFIX}_task25_inscope.json", "w") as f:
    json.dump(t25_f, f, ensure_ascii=False, indent=2)

# ── File Processing (findings가 없는 경우 원본 그대로 복사)
with open(f"{PREFIX}_task24.json") as f: t24 = json.load(f)
orig = t24.get("findings", [])
t24_f = copy.deepcopy(t24)
t24_f["findings"] = [f for f in orig if in_scope(f.get("file", ""))]
with open(f"{PREFIX}_task24_inscope.json", "w") as f:
    json.dump(t24_f, f, ensure_ascii=False, indent=2)
```

> `task24.json`에 in-scope findings가 0건이면 원본(`task24.json`)을 Phase 4에서 직접 사용해도 무방 (LLM이 생성한 `task24_llm.json`의 "해당없음" finding으로 커버됨).

---

### Phase 3: LLM 수동분석 — _inscope JSON 기준으로 수행

Phase 3 LLM 분석의 **입력은 원본 JSON이 아닌 `_inscope.json`을 사용**한다.

```
입력: <prefix>_injection_inscope.json   →  출력: <prefix>_task22_llm.json
입력: <prefix>_xss_inscope.json        →  출력: <prefix>_task23_llm.json
입력: <prefix>_task24_inscope.json     →  출력: <prefix>_task24_llm.json
입력: <prefix>_task25_inscope.json     →  출력: <prefix>_task25_llm.json
```

**in-scope 필터링 추가 규칙:**

1. LLM이 직접 소스 파일을 읽어 확인할 때도 `DIAGNOSIS_SCOPE` 경로 외 파일은 분석하지 않는다
2. `_inscope.json`에 없는 finding(out-of-scope)을 LLM 독자 발견으로 추가 금지
3. in-scope 내 해당 진단 유형 finding이 0건이면 "해당없음" finding 1건 필수 생성 (findings `[]` 금지)

---

### Phase 4: 보고서 생성 + Confluence 게시 — _inscope JSON 사용

> ⚠️ **필수 실행 순서 (순서 어기면 LLM 분석 결과가 보고서에 반영되지 않음)**
>
> ```
> 1. Phase 3 완료 → _task22_llm.json, _task23_llm.json, _task24_llm.json, _task25_llm.json 모두 생성
> 2. confluence_page_map.json 등록 (supplemental_sources 배열에 각 _llm.json 지정) ← Phase 4 최선행
> 3. generate_finding_report.py 실행  ← confluence_page_map.json 등록 완료 후에만 실행
> 4. publish_confluence.py 실행
> ```
>
> `generate_finding_report.py`는 실행 시점에 `confluence_page_map.json`을 읽어
> `supplemental_sources` 경로를 확인하고 LLM 결과를 보고서에 병합한다.
> page_map 미등록 상태에서 실행하면 LLM 수동분석 결과가 전혀 반영되지 않는다:
> - Injection: 자동스캔 "수동검토 필요" 문구 + 위험도 정보(1) → LLM 양호 판정 미적용
> - XSS: "Lucy 필터 우회됨" 설명 + 위험도 정보 → LLM 양호 판정 미적용
> - 데이터보호(SENSITIVE_LOGGING): 개별 auto-scan 건 그대로 → LLM 병합 결과(DATA-LOG-001/002)로 교체 미적용

#### 보고서 생성

```bash
python3 tools/scripts/generate_finding_report.py \
    <source_dir> \
    state/<prefix>_injection_inscope.json \
    state/<prefix>_xss_inscope.json \
    state/<prefix>_task24_inscope.json \
    state/<prefix>_task25_inscope.json \
    --modules <scope1> <scope2> \
    --asset-info state/<prefix>_task11.json \
    --anchor-style md2cf \
    --page-map tools/confluence_page_map.json \
    -o state/<prefix>_report.md
```

#### confluence_page_map.json 등록 — _inscope 파일로 지정

```json
{
  "title": "테스트NN - 프로젝트명 (모듈명) 정적 진단",
  "entries": [
    {
      "source": "state/<prefix>_report.md",
      "type": "main_report",
      "task_sources": {
        "api":             "state/<prefix>_api_inventory_inscope.json",
        "injection":       "state/<prefix>_injection_inscope.json",
        "xss":             "state/<prefix>_xss_inscope.json",
        "file_handling":   "state/<prefix>_task24_inscope.json",
        "data_protection": "state/<prefix>_task25_inscope.json"
      }
    },
    {
      "source": "state/<prefix>_api_inventory_inscope.json",
      "title": "테스트NN - API 인벤토리 (N 엔드포인트, <모듈명>)",
      "type": "api_inventory"
    },
    {
      "source": "state/<prefix>_injection_inscope.json",
      "supplemental_sources": ["state/<prefix>_task22_llm.json"],
      "title": "테스트NN - 인젝션 취약점 진단 결과 (<모듈명>)",
      "type": "finding"
    },
    {
      "source": "state/<prefix>_xss_inscope.json",
      "supplemental_sources": ["state/<prefix>_task23_llm.json"],
      "title": "테스트NN - XSS 취약점 진단 결과 (<모듈명>)",
      "type": "finding"
    },
    {
      "source": "state/<prefix>_task24_inscope.json",
      "supplemental_sources": ["state/<prefix>_task24_llm.json"],
      "title": "테스트NN - 파일 처리 진단 결과 (<모듈명>)",
      "type": "finding"
    },
    {
      "source": "state/<prefix>_task25_inscope.json",
      "supplemental_sources": ["state/<prefix>_task25_llm.json"],
      "title": "테스트NN - 데이터 보호 진단 결과 (<모듈명>)",
      "type": "finding"
    }
  ]
}
```

> **전체 repo 진단(스코프 미지정)** 시에는 `_inscope` 파일 없이 원본 JSON을 그대로 사용한다.

---

## 실행 순서

### Phase 2: 자동스캔 (스크립트)

> 스코프 지정 여부와 무관하게 **항상 전체 repo를 스캔**한다. 필터링은 Phase 2.5에서 수행.

```bash
# 1. testbed에 소스코드 배치

# 2-a. DTO 카탈로그 선행 추출
python3 tools/scripts/scan_dto.py <source_dir> -o state/<prefix>_dto_catalog.json

# 2-b. API 인벤토리 (전체 repo)
python3 tools/scripts/scan_api.py <source_dir> \
    --dto-catalog state/<prefix>_dto_catalog.json \
    -o state/<prefix>_api_inventory.json

# 3. 자동스캔 — 전체 repo (병렬 가능)
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

# 3-extra. Semgrep SSC 피드백 룰 실행 (semgrep 설치 시 필수)
# TLS 클라이언트 우회 / gRPC 평문 / Redis 직렬화 누락 패턴 탐지
# → Task 3-5 LLM 분석의 Step 8 입력으로 사용
SEMGREP_RULES="skills/sec-audit-static/references/rules/semgrep"
semgrep \
    --config ${SEMGREP_RULES}/ssl-client-bypass.yaml \
    --config ${SEMGREP_RULES}/grpc-plaintext-channel.yaml \
    --config ${SEMGREP_RULES}/redis-template-default-serializer.yaml \
    --config ${SEMGREP_RULES}/entitymanager-native-query-concat.yaml \
    --json <source_dir> \
    > state/<prefix>_ssc_feedback_semgrep.json
# semgrep 미설치 시: state/<prefix>_ssc_feedback_semgrep.json 파일 없음 → Step 8에서 LLM이 감지하여 알림

# 4. SCA 진단 (항상 실행 — 빌드 결과 JAR 있으면 --jar 지정, 없으면 소스 디렉토리 기준)
#
# [빌드 성공 시]
#   python3 tools/scripts/scan_sca.py <source_dir> \
#       --jar state/<prefix>_build_manifest_primary.jar \
#       --project <project-name> \
#       --poc \
#       -o state/<prefix>_sca.json
#
# [빌드 실패 / JAR 없는 경우 — Gradle dep tree 기반]
#   gradlew dependencies --configuration runtimeClasspath > state/<prefix>_dep_tree.log
#   python3 tools/scripts/scan_sca.py <source_dir> \
#       --dep-tree state/<prefix>_dep_tree.log \
#       --project <project-name> \
#       --poc \
#       -o state/<prefix>_sca.json
#
# [기존 dependency-check 리포트 재활용 시]
#   python3 tools/scripts/scan_sca.py <source_dir> \
#       --dc-report state/<prefix>_dc_report.json \
#       --poc \
#       -o state/<prefix>_sca.json
#
# NVD_API_KEY는 .env에서 자동 로드됨.
# 결과 Confluence 게시는 Phase 4에서 별도 페이지로 publish_sca_confluence.py 또는
# scan_sca.py --publish 옵션으로 직접 게시.

# 5. [스코프 지정 시만] Phase 2.5 — _inscope JSON 생성
#    → 위 "진단 범위 제한" 섹션의 필터링 스크립트 실행
#    → state/<prefix>_*_inscope.json 5개 생성
```

### Phase 3: LLM 수동분석 보완 (이 프롬프트의 역할)

**[스코프 미지정 — 전체 repo 진단]**
```
입력: <prefix>_injection.json   →  출력: <prefix>_task22_llm.json
입력: <prefix>_xss.json        →  출력: <prefix>_task23_llm.json
입력: <prefix>_task24.json     →  출력: <prefix>_task24_llm.json
입력: <prefix>_task25.json     →  출력: <prefix>_task25_llm.json
```

**[스코프 지정 — 모듈 단위 진단] Phase 2.5 완료 후**
```
입력: <prefix>_injection_inscope.json   →  출력: <prefix>_task22_llm.json
입력: <prefix>_xss_inscope.json        →  출력: <prefix>_task23_llm.json
입력: <prefix>_task24_inscope.json     →  출력: <prefix>_task24_llm.json
입력: <prefix>_task25_inscope.json     →  출력: <prefix>_task25_llm.json
```

> LLM 출력(`_llm.json`)은 스코프와 무관하게 동일 파일명을 사용한다. `_inscope` 접미사를 붙이지 않는다.

각 task의 상세 분석 기준:
- 인젝션: `task_prompts/task_22_injection_review.md`
- XSS: `task_prompts/task_23_xss_review.md`
- 파일 처리: `task_prompts/task_24_file_handling.md`
- 데이터 보호: `task_prompts/task_25_data_protection.md`

---

### Phase 3 완료 조건 체크리스트 ⚠️ 필수

**각 Task 완료 전 아래 조건을 반드시 자가 검증하라. 조건 미충족 시 해당 Task는 미완료로 간주한다.**

#### Task 3-2: 인젝션 (task22_llm.json)

```
□ injection.json의 needs_review(정보) endpoint 수를 확인
  → python3 -c "import json; d=json.load(open('state/<prefix>_injection.json'));
     eps=[e for e in d.get('endpoint_diagnoses',[]) if e.get('overall_result')=='정보' or e.get('needs_review')];
     print(len(eps), 'info endpoints')"

□ sqli_endpoint_review.total_info_endpoints == 위에서 확인한 수
  (주의: 3건만 검토했는데 126건이면 미완료)

□ diagnosis_type 모든 종류가 group_judgments에 커버됨
  확인 대상 유형: "자동 판정 불가", "DB 접근 미확인", "추적 불가", "외부 의존성 호출", "XML 미발견 패턴 추정"
  → 각 유형별로 1개 이상 group_judgment 존재해야 함

□ MyBatis/iBatis XML ${} 패턴 전수 확인 완료 여부 명시
  → mybatis_xml_check 필드에 결과 기록
```

#### Task 3-3: XSS (task23_llm.json)

```
□ xss.json의 정보 endpoint 수 확인
  → python3 -c "import json; d=json.load(open('state/<prefix>_xss.json'));
     print(d.get('summary',{}))"

□ 잠재적위협(Persistent XSS) 그룹: endpoints_reviewed 배열이 비어있지 않음
  (빈 배열 []이면 실제 분석 미수행)

□ HTML_VIEW 반환 컨트롤러가 있는 경우: 다중 경로 분석 수행 여부 명시
  → 성공 경로 JSP + 실패/오류 경로 JSP 모두 확인
  → 각 JSP에서 사용자 입력 taint 경로 확인

□ WEB-INF 외부 JSP 확인 수행 여부 명시
  → find src/main/webapp -name "*.jsp" ! -path "*/WEB-INF/*"
  → 존재 시: 직접 URL 접근 가능성 + EL/스크립틀릿 사용자 입력 확인

□ 전역 XSS 필터 finding 포함 여부
  → XSS-FILTER-001 또는 동등한 전역 필터 평가 finding 필수
```

#### Task 3-4: 파일처리 (task24_llm.json)

```
□ [모듈 스코프 있는 경우] in-scope 필터링 수행 여부 확인
  → task24.json findings를 파일 경로 기준으로 in-scope / out-of-scope 분류
  → out-of-scope findings는 file_handling_assessment.out_of_scope_finding 섹션에만 요약 기록

□ in-scope finding 0건 여부 확인
  → 0건이면 "해당없음" finding 1건 필수 생성 (findings: [] 금지)
  → FILE-SCOPE-001 패턴 준수 (result: "해당없음", diagnosis_method: SAST+LLM)

□ in-scope finding 1건 이상이면 업로드/다운로드/LFI 항목별 판정 수행
```

#### Task 3-5: 데이터보호 (task25_llm.json)

```
□ [모듈 스코프 있는 경우] in-scope 필터링 수행 여부 확인
  → task25.json findings를 파일 경로 기준으로 in-scope / out-of-scope 분류
  → out-of-scope findings는 data_protection_assessment.out_of_scope 섹션에 요약 기록

□ SENSITIVE_LOGGING 병합: 로그 레벨 기준 2버킷 (모듈별 분리 금지)
  → info/warn/error/fatal 레벨 PII 로깅 전체 → DATA-LOG-001 (Critical) 1건으로 통합
  → debug/trace 레벨 PII 로깅 전체 → DATA-LOG-002 (Medium) 1건으로 통합
  → 여러 모듈에 걸쳐 동일 PII가 있어도 레벨 버킷으로만 분류 (모듈별 분리 금지)
  ⚠️ DATA-LOG-001(shoppingtab), DATA-LOG-002(pointcon) 식 모듈별 분리 → 잘못된 패턴
  ⚠️ SENSITIVE_LOGGING 병합이 보고서에 반영되는 메커니즘:
     - generate_finding_report.py의 "Category-Replace" 로직이 자동 수행
     - task25_llm.json findings의 `category: "SENSITIVE_LOGGING"`이 auto-scan finding의 category와 일치하면
       해당 category의 auto-scan finding 전체 제거 → LLM 병합 finding(DATA-LOG-001/002)으로 교체
     - 단, confluence_page_map.json의 supplemental_sources에 task25_llm.json이 등록되어야 함 (Phase 4 선행 필수)

□ DTO_EXPOSURE: 스크립트 역추적 결과 확인
  → task25.json DTO finding의 affected_endpoints 배열 확인
  → affected_endpoints 비어 있음 → INTERNAL/Consumer DTO → FP 처리
  → affected_endpoints 있음 → Controller 코드 직접 확인 후 Safe by Design 또는 취약 판정

□ data_protection_review 블록 작성 여부
  → 구조: { "hardcoded_secrets": {...}, "pii_logging": {...}, "overall_judgment": "..." }

□ 하드코딩 시크릿: Prod/Stage/Test 환경 판별 명시
  → task25.json의 시크릿 후보들 중 실제 운영 영향 여부 기록

□ PII 로깅: 마스킹 적용 여부 케이스별 판정
  → 케이스 A: 마스킹 완전 적용 → 양호
  → 케이스 B: 일부 마스킹 누락 → 취약
  → 케이스 C: 마스킹 전혀 없음 → 취약
```

---

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
    },
    {
      "source": "state/<prefix>_sca.json",
      "title": "테스트NN - SCA (오픈소스 취약점) 진단 결과",
      "type": "sca"
    }
  ]
}

> **SCA 페이지 (`type: "sca"`) — 라이브러리 취약점 테이블**
>
> `scan_sca.py`의 `--publish` 옵션 또는 별도 스크립트로 게시.
> 상세 진단 기준: `task_prompts/task_sca.md` 참조.
> 출력 형식:
> - 라이브러리 중복 제거 (한 라이브러리 = 한 행)
> - 정렬: CRITICAL → HIGH, 소스관련성 적용 → 제한적 → 조건미충족
> - 열 구성: #, 라이브러리(현재버전), 심각도, CVE 목록(★=KEV), 패치 필요 버전, 소스 관련성, CWE 및 취약 현황(한국어)
> - CWE 5개 이상: 우선순위 상위 4개로 자동 압축 (RCE → 경로탐색 → 인가우회 → DoS)
>
> **SCA 조치 권고 작성 원칙** (`task_sca.md` Rule 1-3 필수 적용):
> - **[Rule 1] Big Bang 방지**: Spring Boot 2→3 권고 시 "단기 패치 + 중장기 마이그레이션 별도 수립" 문구 포함
> - **[Rule 2] BOM 오버라이딩 금지**: Tomcat/Jackson 등 BOM 관리 라이브러리는 개별 강제 버전업 권고 금지, BOM 일괄 업그레이드 권고
> - **[Rule 3] CWE 압축**: 단일 라이브러리 CWE 5개 이상 시 핵심 위협 4개로 자동 요약 (`_compress_cwe_ids()` 자동 처리)
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

---

## Phase 5: SSC 정합성 검증 [선택적]

> **실행 조건**: Fortify SSC에 해당 프로젝트가 등록되어 있고 `.env`에 SSC_TOKEN이 설정된 경우
> Phase 1~4와 무관하게 독립 실행 가능. 전체 절차는 `references/ssc_verification.md` 참조.

```
Phase 5: SSC 정합성 검증
  ├─ Step 5-0: 브랜치/커밋 일치 검증 ⚠️ 필수
  │     python3 tools/scripts/fetch_ssc.py \
  │         --project "<SSC 프로젝트명>" \
  │         --testbed testbed/<project>/<repo>@<branch>@<commit> \
  │         -o state/<prefix>_ssc_findings.json
  │     # MATCH=정상 / PARTIAL=주의 / MISMATCH=버전 불일치 위험 / UNKNOWN=메타정보 없음
  │
  ├─ Step 5-1: SSC High/Critical findings 수집 (5-0과 동시 실행)
  │     → state/<prefix>_ssc_findings.json
  │
  ├─ Step 5-2: LLM 소스코드 교차검증 (finding당 TP/FP 판정)
  │     - issue_name 그룹별 대표 3~5건 소스파일 직접 Read (±30라인 컨텍스트)
  │     - verification.result: "취약" | "양호(FP)" | "검토필요"
  │     - 검토필요 → LLM 추가분석으로 전건 해소 권장
  │     - 검증 결과를 ssc_findings.json에 덮어씀
  │
  ├─ Step 5-3: 보고서 생성 + Confluence 게시
  │     state/<prefix>_ssc_report.md  ← LLM 인라인 생성
  │     보고서 필수 섹션:
  │       1. 요약 (그룹별 TP/FP/검토필요 표)
  │       2. 취약 확인 건 목록 (TP 전건 — 1행 1건, 심각도/파일/라인 명시)
  │       3. 취약 확인 건 상세 (코드 증적 + 테인트 경로 + 조치 방안)
  │       4. 양호 판정 요약 (FP 근거)
  │       5. 추가 검토필요 → LLM 분석 결과
  │       6. 조치 우선순위
  │     심각도 색상: Critical=🔴Red / High=🟡Yellow(amber)
  │       → Markdown에 "Critical"/"High" 그대로 작성하면 게시 시 자동 변환
  │     Confluence 게시 (필수):
  │       confluence_page_map.json에 테스트N 그룹 등록 (type: "doc")
  │       python3 tools/scripts/publish_confluence.py --filter-group "테스트N"
  │
  ├─ Step 5-4: SSC TP → SAST 피드백 환류
  │     - TP 건 SAST 대조 → Type A(미탐 보완) / Type B(신규 탐지) 분류
  │     - LLM 검토 게이트([5-4-2]): 필요성·정합성 검토 후 승인/보류 결정
  │     - 승인 건: Semgrep 룰 추가 / task prompt 체크리스트 보완 적용
  │     - 상세: references/ssc_feedback_ruleset.md
  │
  └─ 완료 기준: ssc_findings.json 전건 판정 + ssc_report.md 생성 + Confluence 게시 완료
```

### 사전 준비

```bash
# .env에 추가
SSC_BASE_URL=https://ssc.skplanet.com/ssc
SSC_TOKEN=<token>      # 웹 UI: /html/ssc/profile → Token Management
```

### 실행

```bash
# 1) 프로젝트 목록 확인 (처음 한 번)
python3 tools/scripts/fetch_ssc.py --list-projects

# 2) findings 수집 + 브랜치 일치 검증 (Step 5-0 + 5-1 동시)
python3 tools/scripts/fetch_ssc.py \
    --project "<SSC 프로젝트명>" \
    --version "<버전명>" \
    --testbed testbed/<project>/<repo>@<branch>@<commit> \
    -o state/<prefix>_ssc_findings.json

# 3) LLM 교차검증 (Step 5-2) → references/ssc_verification.md Step 5-2 절차

# 4) 보고서 생성 (Step 5-3) → state/<prefix>_ssc_report.md
#    confluence_page_map.json에 테스트N 그룹 등록 후:
python3 tools/scripts/publish_confluence.py --filter-group "테스트N"

# 5) SAST 피드백 환류 (Step 5-4) → references/ssc_feedback_ruleset.md
```

---

## 보안 정책

- 고객 DB 자격증명, API 시크릿 등은 AI 프롬프트에 포함 금지
- 고객 PII는 마스킹 없이 AI에 전달 금지
- AI 결과는 반드시 검증 후 최종 보고서에 반영
- 실제 공격 Exploit 코드 생성 금지
