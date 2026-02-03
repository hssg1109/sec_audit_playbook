# AI 보안진단 플레이북 - 디렉터리 구조 및 진단 절차 가이드

---

## 1. 디렉터리 구조 전체 맵

```
playbook/
├── .claude/
│   └── settings.local.json
├── ai/
│   ├── ai-manifest.yaml
│   ├── AI_USAGE_POLICY.md
│   ├── PROMPT_STYLE_GUIDE.md
│   └── REDACTION_RULES.md
├── docs/
│   ├── 00_overview.md
│   ├── 10_asset_identification.md
│   ├── 20_static_analysis.md
│   ├── 21_api_inventory.md
│   ├── 22_injection_review.md
│   ├── 23_xss_review.md
│   ├── 24_file_handling_review.md
│   ├── 25_data_protection_review.md
│   └── PLAYBOOK_GUIDE.md          ← 본 문서
├── prompts/
│   └── static/
│       ├── task_11_asset_identification.md
│       ├── task_21_api_inventory.md
│       ├── task_22_injection_review.md
│       ├── task_23_xss_review.md
│       ├── task_24_file_handling.md
│       └── task_25_data_protection.md
├── schemas/
│   ├── finding_schema.json
│   └── task_output_schema.json
├── state/
│   └── .gitkeep
├── tools/
│   └── scripts/
│       ├── parse_asset_excel.py
│       ├── validate_task_output.py
│       ├── redact.py
│       └── merge_results.py
├── workflows/
│   └── audit_workflow.yaml
└── AI_보안진단_플레이북_가이드.docx
```

---

## 2. 각 디렉터리 및 파일 역할

### 2.1 `ai/` - AI 운영 정책 및 추적

| 파일 | 역할 |
|------|------|
| `ai-manifest.yaml` | AI 세션 추적 매니페스트. 어떤 모델이 어떤 태스크를 수행했고, 어떤 파일을 생성했는지 기록한다. 감사 추적(audit trail)용. |
| `AI_USAGE_POLICY.md` | AI 에이전트가 할 수 있는 일과 금지 사항을 정의한다. 정적 코드 분석 보조는 허용하되, DB 자격증명 포함이나 익스플로잇 코드 생성은 금지한다. |
| `PROMPT_STYLE_GUIDE.md` | 프롬프트 작성 표준. 역할 정의, 입출력 경로, 출력 스키마, 단계별 명령, 금지사항을 포함하는 템플릿 구조를 규정한다. |
| `REDACTION_RULES.md` | 민감 데이터 마스킹 규칙. IP 주소, 이메일, API 키, JWT 토큰, 전화번호, 비밀번호, AWS 키, 주민번호 등 8가지 패턴에 대한 자동 마스킹 규칙을 정의한다. |

### 2.2 `docs/` - 단계별 진단 절차 문서

| 파일 | 역할 |
|------|------|
| `00_overview.md` | 전체 프로세스 개요. 3단계 진단 흐름과 핵심 원칙을 설명한다. |
| `10_asset_identification.md` | Phase 1: 자산 식별. Excel 파싱 기반 자산 목록 생성 절차를 기술한다. |
| `20_static_analysis.md` | Phase 2: 정적 분석 전체 개요. API 인벤토리, 인젝션, XSS, 파일 처리, 데이터 보호 점검 절차를 포괄한다. |
| `21_api_inventory.md` | Task 2-1: API 인벤토리 추출. Spring, Express, Django, FastAPI 등 프레임워크별 엔드포인트 추출 방법을 포함한다. |
| `22_injection_review.md` | Task 2-2: 인젝션 취약점 점검. SQL/NoSQL/Command/LDAP/XML/Template Injection 탐지와 심각도 매트릭스를 제공한다. |
| `23_xss_review.md` | Task 2-3: XSS 취약점 점검. Reflected/Stored/DOM 기반 XSS 탐지와 CSP 검증 방법을 포함한다. |
| `24_file_handling_review.md` | Task 2-4: 파일 처리 취약점 점검. 파일 업로드/다운로드 관련 보안 점검을 다룬다. |
| `25_data_protection_review.md` | Task 2-5: 데이터 보호 검토. CORS 설정, 중요정보 노출, 하드코딩된 민감정보, 관리자 페이지 분리, JWT 보안 점검을 다룬다. |

### 2.3 `prompts/static/` - 태스크별 AI 프롬프트

각 태스크를 수행할 Claude 에이전트에게 전달할 구조화된 프롬프트 템플릿이다.

| 파일 | 대상 태스크 |
|------|------------|
| `task_11_asset_identification.md` | 1-1: 자산 식별 (Excel 파싱 + 소스코드 분석) |
| `task_21_api_inventory.md` | 2-1: API 인벤토리 |
| `task_22_injection_review.md` | 2-2: 인젝션 점검 |
| `task_23_xss_review.md` | 2-3: XSS 점검 |
| `task_24_file_handling.md` | 2-4: 파일 처리 점검 |
| `task_25_data_protection.md` | 2-5: 데이터 보호 점검 |

각 프롬프트는 `{{INPUT_FILE}}`, `{{OUTPUT_FILE}}`, `{{TASK_ID}}`, `{{SESSION_ID}}` 등의 변수를 지원한다.

### 2.4 `schemas/` - 출력 검증 스키마

| 파일 | 역할 |
|------|------|
| `task_output_schema.json` | Task 1-1, 2-1의 표준 출력 스키마. `task_id`, `status`, `findings` 필드가 필수이며, `status`는 `completed`, `failed`, `partial` 중 하나이다. |
| `finding_schema.json` | Task 2-2, 2-3, 2-4, 2-5의 취약점 발견 스키마. 각 finding은 `id`, `title`, `severity`, `category`, `description`, `affected_endpoint`, `evidence`, `cwe_id`(형식: `CWE-XXXX`), `owasp_category`, `recommendation` 등을 포함한다. severity는 `Critical/High/Medium/Low/Info` 5단계이다. |

### 2.5 `state/` - 실행 상태 및 결과 저장소

태스크 실행 결과가 JSON 형식으로 저장되는 디렉터리이다.

- 파일 명명 규칙: `task_XY_result.json` (예: `task_21_result.json`)
- 최종 통합 보고서: `final_report.json`
- 초기 상태에서는 `.gitkeep`만 존재하며, 진단 수행 시 결과 파일이 생성된다.

### 2.6 `tools/scripts/` - 자동화 스크립트

| 파일 | 역할 |
|------|------|
| `parse_asset_excel.py` | 자산 정보 Excel 파싱. openpyxl을 사용하여 한/영 헤더를 자동 인식하고, Excel 데이터를 `task_output_schema.json` 형식의 JSON으로 변환한다. |
| `validate_task_output.py` | JSON 출력 검증. `task_id`에 따라 적절한 스키마를 자동 선택하여 필수 필드, 타입, enum, 정규식 패턴을 검사한다. 검증 실패 시 워크플로우가 중단된다. |
| `redact.py` | 민감 데이터 자동 마스킹. 8가지 패턴(IP, 이메일, API 키, JWT, 전화번호, 비밀번호, AWS 키, 주민번호)을 정규식으로 탐지하여 `[REDACTED_XXX]` 형태로 치환한다. |
| `merge_results.py` | 최종 보고서 생성. `state/*.json` 파일들을 통합하여 취약점 수, 위험 점수(`Critical*10 + High*7 + Medium*4 + Low*1`), 심각도별 정렬된 발견 사항, 태스크 완료 통계를 포함하는 `final_report.json`을 생성한다. |

### 2.7 `workflows/audit_workflow.yaml` - 마스터 워크플로우

전체 진단 프로세스의 태스크 의존성과 실행 순서를 YAML로 정의한다. 3개 Phase, 6개 Task의 의존성 그래프를 관리한다.

### 2.8 기타 파일

| 파일 | 역할 |
|------|------|
| `.claude/settings.local.json` | Claude Code CLI 권한 설정. Python 실행, pip 설치, chmod 등의 권한을 허용한다. |
| `AI_보안진단_플레이북_가이드.docx` | 한글 가이드 문서(Word 형식). |

---

## 3. 진단 절차 - 전체 흐름

이 플레이북은 **3단계(Phase)**, **6개 태스크(Task)** 로 구성된 정적 분석 특화 보안 진단 프로세스를 정의한다. 각 태스크는 독립적인 Claude 에이전트가 수행하며, 의존성에 따라 순차 또는 병렬로 실행된다.

**입력**: 자산 정보 Excel 파일 + 로컬 소스코드

```
┌─────────────────────────────────────────────────────┐
│        Phase 1: ASSET IDENTIFICATION (자산 식별)       │
│                                                     │
│   ┌─────────────────────────────────────┐           │
│   │ Task 1-1                            │           │
│   │ 자산 식별 (Excel 파싱 + 소스코드)     │  ← 순차   │
│   └────────────────────┬────────────────┘           │
└────────────────────────┼────────────────────────────┘
                         ▼
┌─────────────────────────────────────────────────────┐
│          Phase 2: STATIC ANALYSIS (정적 분석)         │
│                                                     │
│   ┌─────────────────────────────────────┐           │
│   │ Task 2-1: API 인벤토리               │  ← 순차   │
│   └──┬──────────┬──────────┬────────────┘           │
│      ▼          ▼          ▼                        │
│   ┌──────┐  ┌──────┐  ┌────────┐  ┌────────┐         │
│   │2-2   │  │2-3   │  │2-4     │  │2-5     │         │
│   │인젝션 │  │XSS   │  │파일처리 │  │데이터  │  ← 병렬 │
│   └──┬───┘  └──┬───┘  └──┬─────┘  └──┬─────┘         │
│      └─────────┼─────────┼───────────┘               │
└────────────────┼────────────────────────────────────┘
                 ▼
┌─────────────────────────────────────────────────────┐
│           Phase 3: REPORTING (보고서 생성)             │
│                                                     │
│   ┌─────────────────────────────────────┐           │
│   │ merge_results.py 자동 실행           │  ← 자동   │
│   └─────────────────────────────────────┘           │
└─────────────────────────────────────────────────────┘
```

---

## 4. 진단 절차 - 단계별 상세

### Phase 1: ASSET IDENTIFICATION (자산 식별)

#### Task 1-1: 자산 식별 (Excel 파싱 + 소스코드 분석)

| 항목 | 내용 |
|------|------|
| **목적** | 고객 제공 Excel에서 자산 정보를 추출하고 소스코드 분석으로 보완한다. |
| **프롬프트** | `prompts/static/task_11_asset_identification.md` |
| **스크립트** | `tools/scripts/parse_asset_excel.py` |
| **출력** | `state/task_11_result.json` |
| **검증 스키마** | `schemas/task_output_schema.json` |

**수행 내용:**
1. `parse_asset_excel.py`로 자산 정보 Excel을 JSON으로 변환
2. 소스코드 프로젝트 구조 분석 (프레임워크, 라이브러리, 런타임 식별)
3. 빌드 설정 파일(build.gradle, pom.xml, package.json 등)에서 기술 스택 확인
4. 설정 파일(application.yaml, .env 등)에서 외부 연동 서비스 파악
5. Excel 파싱 결과와 소스코드 분석 결과를 병합하여 `state/task_11_result.json`에 저장

---

### Phase 2: STATIC ANALYSIS (정적 분석)

#### Task 2-1: API 인벤토리 (선행 필수)

| 항목 | 내용 |
|------|------|
| **선행 조건** | Task 1-1 완료 |
| **목적** | 모든 API 엔드포인트를 추출하여 인벤토리를 생성한다. |
| **프롬프트** | `prompts/static/task_21_api_inventory.md` |
| **출력** | `state/task_21_result.json` |
| **검증 스키마** | `schemas/task_output_schema.json` |
| **중요** | 이 태스크가 완료되어야 2-2, 2-3, 2-4, 2-5가 시작될 수 있다. |

**수행 내용:**
1. 소스 코드에서 모든 HTTP 엔드포인트 추출
2. 프레임워크별 라우터 패턴 인식 (Express: `app.get()`, Spring: `@RequestMapping`, Django: `urlpatterns`, FastAPI: `@app.get()`)
3. 각 엔드포인트의 HTTP 메서드, 경로, 핸들러 함수, 미들웨어 매핑
4. 파라미터 타입(query, body, path, header) 분류
5. 인증/인가 요구사항 표시

#### Task 2-2: 인젝션 취약점 점검 (병렬)

| 항목 | 내용 |
|------|------|
| **선행 조건** | Task 2-1 완료 |
| **목적** | SQL, NoSQL, Command, LDAP, XML, Template Injection 취약점을 탐지한다. |
| **프롬프트** | `prompts/static/task_22_injection_review.md` |
| **출력** | `state/task_22_result.json` |
| **검증 스키마** | `schemas/finding_schema.json` |

**수행 내용:**
1. API 인벤토리 결과를 기반으로 각 엔드포인트의 입력 처리 코드 분석
2. 사용자 입력이 쿼리/명령에 직접 삽입되는 패턴 탐지
3. Prepared Statement, 파라미터 바인딩 사용 여부 확인
4. ORM 사용 시 raw query 호출 탐지
5. 발견된 각 취약점에 CWE ID, OWASP 카테고리, 심각도 부여
6. 구체적인 코드 위치(파일, 라인)와 증거(evidence) 기록

#### Task 2-3: XSS 취약점 점검 (병렬)

| 항목 | 내용 |
|------|------|
| **선행 조건** | Task 2-1 완료 |
| **목적** | Reflected, Stored, DOM 기반 XSS 취약점을 탐지한다. |
| **프롬프트** | `prompts/static/task_23_xss_review.md` |
| **출력** | `state/task_23_result.json` |
| **검증 스키마** | `schemas/finding_schema.json` |

**수행 내용:**
1. 사용자 입력이 HTML/JS 출력에 반영되는 모든 경로 추적
2. 출력 인코딩/이스케이프 처리 여부 확인
3. 템플릿 엔진의 auto-escape 설정 검증
4. CSP(Content Security Policy) 헤더 설정 확인
5. DOM 조작 코드에서 `innerHTML`, `document.write`, `eval` 등 위험 함수 사용 탐지
6. 발견 사항에 XSS 유형, 심각도, CWE/OWASP 매핑 기록

#### Task 2-4: 파일 처리 취약점 점검 (병렬)

| 항목 | 내용 |
|------|------|
| **선행 조건** | Task 2-1 완료 |
| **목적** | 파일 업로드/다운로드 관련 보안 취약점을 탐지한다. |
| **프롬프트** | `prompts/static/task_24_file_handling.md` |
| **출력** | `state/task_24_result.json` |
| **검증 스키마** | `schemas/finding_schema.json` |

**수행 내용:**
1. 파일 업로드 엔드포인트의 확장자/MIME 타입 검증 여부 확인
2. 업로드 경로 조작(Path Traversal) 가능성 분석
3. 파일 크기 제한 및 저장 위치 보안 검토
4. 파일 다운로드 시 경로 조작 취약점 확인
5. 임시 파일 처리 및 정리 로직 검토

#### Task 2-5: 데이터 보호 검토 (병렬)

| 항목 | 내용 |
|------|------|
| **선행 조건** | Task 2-1 완료 |
| **목적** | CORS 설정, 중요정보 노출, 하드코딩된 민감정보, 관리자 페이지 분리, JWT 토큰 보안을 점검한다. |
| **프롬프트** | `prompts/static/task_25_data_protection.md` |
| **출력** | `state/task_25_result.json` |
| **검증 스키마** | `schemas/finding_schema.json` |

**수행 내용:**
1. CORS 전역 설정 및 컨트롤러별 `@CrossOrigin` 설정 검토
2. `allowedOrigins("*")` + `credentials(true)` 동시 설정 여부 확인
3. 소스코드 내 비밀번호, API 키, 토큰 등 하드코딩 여부 검색
4. 응답 DTO에 불필요한 민감 필드 포함 여부 확인
5. 관리자 페이지와 일반 사용자 페이지의 분리 여부 확인
6. JWT 서명 알고리즘, Secret Key 복잡도, 만료 시간 설정 검토

---

### Phase 3: REPORTING (보고서 생성)

Phase 2의 모든 태스크가 완료되면 자동으로 보고서를 생성한다.

```bash
python tools/scripts/merge_results.py
```

**수행 내용:**
1. `state/` 디렉터리의 모든 태스크 결과 JSON 수집
2. `merge_results.py` 스크립트를 통한 통합
3. 위험 점수 산출: `Critical×10 + High×7 + Medium×4 + Low×1`
4. 심각도 순서로 발견 사항 정렬 (Critical → High → Medium → Low → Info)
5. 경영진 요약(Executive Summary) 자동 생성
6. 취약점 분포에 기반한 개선 권고사항 도출
7. 태스크별 완료 통계 포함

---

## 5. 진단 실행 구체적 절차 (실무 가이드)

### 5.1 사전 준비

```bash
# 1. 고객 제공 자산 정보 Excel 파일 준비
# 예: /mnt/g/TARGET_APP/자산정보.xlsx

# 2. 대상 애플리케이션 소스 코드를 접근 가능한 경로에 준비
# 예: /mnt/g/TARGET_APP/source/

# 3. Python 의존성 설치
pip install openpyxl jsonschema

# 4. state 디렉터리 초기화 (이전 결과 제거)
rm -f state/task_*_result.json state/final_report.json
```

### 5.2 Phase 1 실행 (순차)

```
[세션 A] Task 1-1: 자산 식별

  Step 1 - Excel 파싱:
  python tools/scripts/parse_asset_excel.py <excel_file> --output state/task_11_result.json

  Step 2 - 소스코드 분석:
  prompts/static/task_11_asset_identification.md의 프롬프트로 Claude 실행
  - 입력: Excel 파싱 결과 + 소스 코드 경로
  - 출력: state/task_11_result.json (보완)
```

**검증:**
```bash
python tools/scripts/validate_task_output.py state/task_11_result.json
```

### 5.3 Phase 2 실행 (순차 → 병렬)

**먼저 Task 2-1을 순차 실행한다:**

```
[세션 B] prompts/static/task_21_api_inventory.md
  - 입력: 소스 코드 + state/task_11_result.json
  - 출력: state/task_21_result.json
```

**검증 후 Task 2-2, 2-3, 2-4, 2-5를 병렬 실행한다:**

```bash
python tools/scripts/validate_task_output.py state/task_21_result.json
```

```
[세션 C] prompts/static/task_22_injection_review.md
  - 입력: 소스 코드 + state/task_21_result.json
  - 출력: state/task_22_result.json

[세션 D] prompts/static/task_23_xss_review.md
  - 입력: 소스 코드 + state/task_21_result.json
  - 출력: state/task_23_result.json

[세션 E] prompts/static/task_24_file_handling.md
  - 입력: 소스 코드 + state/task_21_result.json
  - 출력: state/task_24_result.json

[세션 F] prompts/static/task_25_data_protection.md
  - 입력: 소스 코드 + state/task_21_result.json
  - 출력: state/task_25_result.json
```

**검증:**
```bash
python tools/scripts/validate_task_output.py state/task_22_result.json
python tools/scripts/validate_task_output.py state/task_23_result.json
python tools/scripts/validate_task_output.py state/task_24_result.json
python tools/scripts/validate_task_output.py state/task_25_result.json
```

### 5.4 Phase 3 실행 (자동)

```bash
# 결과 병합 및 최종 보고서 생성
python tools/scripts/merge_results.py

# 민감 데이터 마스킹
python tools/scripts/redact.py state/final_report.json

# 최종 검증
python tools/scripts/validate_task_output.py state/final_report.json
```

---

## 6. 품질 보증 체크리스트

각 태스크 완료 후 다음을 확인한다:

- [ ] `validate_task_output.py`로 스키마 검증 통과
- [ ] `status` 필드가 `completed`인지 확인
- [ ] `findings` 배열이 비어있지 않은지 확인 (해당되는 경우)
- [ ] 각 finding에 `cwe_id`, `severity`, `evidence`가 포함되어 있는지 확인
- [ ] `redact.py`로 민감 데이터 마스킹 적용
- [ ] `ai-manifest.yaml`에 세션 정보 기록

---

## 7. 위험 점수 해석

최종 보고서의 위험 점수는 다음 공식으로 산출된다:

```
Risk Score = (Critical 수 × 10) + (High 수 × 7) + (Medium 수 × 4) + (Low 수 × 1)
```

| 점수 범위 | 위험 등급 | 권고 조치 |
|-----------|----------|----------|
| 0 ~ 10 | 낮음 | 정기 모니터링 유지 |
| 11 ~ 30 | 보통 | 계획된 일정 내 조치 |
| 31 ~ 70 | 높음 | 우선순위 높게 조치 |
| 71 이상 | 긴급 | 즉시 조치 필요 |

---

## 8. 데이터 흐름 요약

```
자산 정보 Excel + 소스코드
        │
        ▼
┌─────────────────────┐
│ parse_asset_excel.py │  ← Excel → JSON 변환
└────────┬────────────┘
         ▼
┌─────────────────────┐
│ prompts/static/     │  ← 태스크별 프롬프트 템플릿
│ (Claude 에이전트에    │
│  전달할 지시사항)     │
└────────┬────────────┘
         ▼
┌─────────────────────┐
│ Claude 에이전트 실행  │  ← 태스크별 독립 세션
│ (최대 5개 병렬)       │
└────────┬────────────┘
         ▼
┌─────────────────────┐
│ state/*.json        │  ← 태스크별 중간 결과
└────────┬────────────┘
         ▼
┌─────────────────────┐
│ validate_task_      │  ← 스키마 검증 (통과 시 진행)
│ output.py           │
└────────┬────────────┘
         ▼
┌─────────────────────┐
│ merge_results.py    │  ← 결과 통합
└────────┬────────────┘
         ▼
┌─────────────────────┐
│ redact.py           │  ← 민감 데이터 마스킹
└────────┬────────────┘
         ▼
┌─────────────────────┐
│ state/              │
│ final_report.json   │  ← 최종 보고서
└─────────────────────┘
         │
         ▼
┌─────────────────────┐
│ ai/ai-manifest.yaml │  ← 감사 추적 기록
└─────────────────────┘
```

---

## 9. 주의사항

1. **순서 준수**: Task 2-1은 2-2/2-3/2-4/2-5의 필수 선행 태스크이다. Task 1-1이 완료되어야 Phase 2를 시작할 수 있다.
2. **검증 필수**: 각 태스크 완료 후 반드시 `validate_task_output.py`로 출력을 검증한다. 검증 실패 시 해당 태스크를 재실행한다.
3. **마스킹 적용**: 최종 보고서 생성 전 반드시 `redact.py`를 실행하여 민감 데이터를 마스킹한다.
4. **정책 준수**: `AI_USAGE_POLICY.md`에 정의된 금지 사항(익스플로잇 코드 생성, DB 자격증명 포함 등)을 준수한다.
5. **세션 기록**: 모든 AI 세션은 `ai-manifest.yaml`에 기록하여 감사 추적이 가능하도록 한다.
6. **병렬 실행 시**: 각 세션이 동일한 `state/` 디렉터리에 결과를 저장하므로, 파일명 충돌이 없도록 태스크 ID 기반 명명 규칙을 준수한다.
