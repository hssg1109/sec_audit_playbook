# AI 보안진단 플레이북

> AI 에이전트(Claude)를 활용한 소스코드 보안 진단 자동화 프레임워크 — v4.16.0

---

## 신규 서버 설치 가이드

> 이 섹션은 플레이북을 **처음 설치하는 서버**에서 `/sec-audit-static` 을 실행하기 위한 전체 절차를 다룹니다.

### 1단계 — 시스템 요구사항 확인

| 항목 | 최소 | 권장 | 확인 명령 |
|------|------|------|-----------|
| **OS** | Ubuntu 20.04 / WSL2 | Ubuntu 22.04 LTS | `lsb_release -a` |
| **Python** | 3.7+ | 3.9+ | `python3 --version` |
| **Java (JDK)** | 11+ | 17+ | `java -version` |
| **Git** | 2.x | 최신 | `git --version` |
| **npm** | 6+ | 최신 | `npm --version` *(Node.js 프로젝트 스캔 시 필요)* |
| **디스크** | 10 GB+ | 30 GB+ | `df -h` |
| **메모리** | 4 GB+ | 8 GB+ | `free -h` |

```bash
# Java가 없으면 자동 설치 스크립트 사용
bash tools/scripts/setup_linux_jdk.sh
```

---

### 2단계 — 저장소 클론

```bash
git clone <PLAYBOOK_REPO_URL> playbook
cd playbook

# 런타임 디렉터리 생성 (gitignored — 레포에 없으므로 직접 생성)
mkdir -p testbed state
```

> **레포 구조 참고**
> - `skills/`, `tools/`, `CLAUDE.md` 등 **진단 도구 일체**가 레포에 포함됩니다 (수 MB 수준)
> - `testbed/` (진단 대상 소스코드), `state/` (결과물)는 **gitignore** 처리 — 레포에 없으며 위에서 직접 생성합니다
> - 진단 대상 소스코드는 별도로 `testbed/<project-name>/` 에 배치합니다 (7단계 참조)

---

### 3단계 — 환경 변수 설정 (`.env`)

```bash
cp .env.example .env
```

`.env` 파일을 열어 아래 항목을 채웁니다.

#### 3-1. Confluence (보고서 게시 — **필수**)

```bash
# Confluence 서버 주소 (Server/Data Center)
CONFLUENCE_BASE_URL=https://wiki.example.com

# 보고서를 게시할 Confluence 스페이스 키
CONFLUENCE_SPACE_KEY=SECDIG

# 보고서 최상위 부모 페이지 ID (Confluence URL의 pageId= 값)
CONFLUENCE_PARENT_ID=741064663

# PAT 인증 (권장): CONFLUENCE_USER 비워두기 + TOKEN만 설정
CONFLUENCE_USER=
CONFLUENCE_TOKEN=<Personal Access Token>

# Basic 인증을 쓸 경우: CONFLUENCE_USER에 계정명 입력
# CONFLUENCE_USER=your_id
# CONFLUENCE_TOKEN=<your_password_or_token>
```

**Confluence PAT 발급 방법**
1. Confluence → 프로필 아이콘 → `Settings` → `Personal Access Tokens`
2. `Create token` → 이름 입력 → `Create`
3. 발급된 토큰을 `CONFLUENCE_TOKEN`에 입력

---

#### 3-2. Bitbucket (결과 팀 공유 — 선택)

```bash
# Bitbucket HTTP Access Token (audit_result 레포 push 권한 필요)
BITBUCKET_TOKEN=<HTTP Access Token>

# 진단 대상 소스 레포 읽기용 토큰 (fetch_bitbucket.py 사용 시)
CUSTOMER_BB_TOKEN=<Customer Repo Token>

# 대상 Bitbucket 서버 주소 (기본값: http://code.skplanet.com)
# CUSTOMER_BB_BASE=http://code.example.com
```

**Bitbucket HTTP Access Token 발급 방법**
1. Bitbucket → 프로필 아이콘 → `Manage account` → `HTTP access tokens`
2. `Create token` → Permissions: `Project read` + `Repository write` → `Create`

---

#### 3-3. Fortify SSC (위험도 교차검증 — 선택, Phase 5)

```bash
# SSC 서버 주소
SSC_BASE_URL=https://ssc.example.com/ssc

# CIToken 방식 (권장)
SSC_TOKEN=<CIToken>

# 또는 계정/비밀번호 방식 (fallback)
# SSC_USERNAME=your_id
# SSC_PASSWORD=your_password
```

---

#### 3-4. NVD API Key (SCA 성능 향상 — 선택)

```bash
# 없으면 공개 API 폴백 (속도 제한 있음)
NVD_API_KEY=<NIST NVD API Key>
```

**NVD API Key 발급**: https://nvd.nist.gov/developers/request-an-api-key

---

### 4단계 — Claude Code CLI 설치 및 AI 연결

`/sec-audit-static` 스킬은 **Claude Code CLI** 환경에서 실행됩니다.

```bash
# Claude Code CLI 설치
npm install -g @anthropic-ai/claude-code

# 또는 공식 설치 스크립트 사용
curl -fsSL https://claude.ai/install.sh | bash
```

```bash
# Anthropic API 인증 (최초 1회)
claude login
# 브라우저가 열리면 Anthropic 계정으로 로그인 후 승인
```

```bash
# 플레이북 디렉터리에서 Claude Code 실행
cd /path/to/playbook
claude
```

> **기업 환경 주의**: 방화벽으로 `api.anthropic.com` 접근이 막혀 있으면 프록시 설정이 필요합니다.
> ```bash
> export HTTPS_PROXY=http://proxy.example.com:8080
> ```

---

### 5단계 — Python 패키지 설치

대부분의 스크립트는 Python 표준 라이브러리만 사용합니다. 선택적 패키지:

```bash
# Excel 파일 파싱 (자산 식별 시 필요)
pip3 install openpyxl

# JSON 스키마 검증
pip3 install jsonschema
```

---

### 6단계 — 동작 확인 (Smoke Test)

```bash
# Confluence 연결 확인 (실제 게시 없이 드라이런)
python3 tools/scripts/publish_confluence.py --dry-run

# Python 버전 확인
python3 -c "import sys; print('Python', sys.version)"

# Java 확인
java -version
```

---

### 7단계 — 첫 진단 실행

```bash
# 1. 진단 대상 소스코드를 testbed에 배치
cp -r /path/to/target-project testbed/<project-name>/

# 2. Claude Code를 플레이북 디렉터리에서 실행
cd /path/to/playbook
claude

# 3. 슬래시 명령으로 전체 워크플로 실행
/sec-audit-static
```

Phase 1(자산 식별) → Phase 2(자동 스캔) → Phase 3(LLM 심층 진단) → Phase 4(Confluence 게시) 순으로 **무중단 자동 완주**합니다.

---

### 환경 변수 전체 요약

| 변수명 | 필수 | 용도 |
|--------|------|------|
| `CONFLUENCE_BASE_URL` | **필수** | Confluence 서버 주소 |
| `CONFLUENCE_SPACE_KEY` | **필수** | 보고서 게시 스페이스 |
| `CONFLUENCE_PARENT_ID` | **필수** | 보고서 부모 페이지 ID |
| `CONFLUENCE_TOKEN` | **필수** | Confluence PAT 또는 비밀번호 |
| `CONFLUENCE_USER` | 선택 | Basic 인증 시 계정명 (PAT 사용 시 빈값) |
| `BITBUCKET_TOKEN` | 선택 | audit_result 레포 push 토큰 |
| `CUSTOMER_BB_TOKEN` | 선택 | 진단 대상 소스 fetch 토큰 |
| `CUSTOMER_BB_BASE` | 선택 | 대상 Bitbucket URL (기본: skplanet) |
| `SSC_BASE_URL` | 선택 | Fortify SSC 서버 (Phase 5) |
| `SSC_TOKEN` | 선택 | SSC CIToken |
| `SSC_USERNAME` / `SSC_PASSWORD` | 선택 | SSC 계정 인증 (fallback) |
| `NVD_API_KEY` | 선택 | NIST NVD API Key (SCA 가속) |

---

### 설치 체크리스트

- [ ] Python 3.9+ 설치 완료
- [ ] Java 17+ 설치 완료 (`java -version`)
- [ ] Git 설치 완료
- [ ] Claude Code CLI 설치 완료 (`claude --version`)
- [ ] `.env` 파일 생성 및 `CONFLUENCE_*` 항목 입력
- [ ] `claude login` 인증 완료
- [ ] `testbed/`, `state/` 디렉터리 생성
- [ ] `publish_confluence.py --dry-run` 통과
- [ ] 진단 대상 소스코드를 `testbed/<project-name>/` 에 배치
- [ ] `/sec-audit-static` 첫 실행 성공

---

## 개요

웹 애플리케이션 소스 코드를 대상으로 **Controller → Service → Repository 호출 그래프 추적** 기반의 정적 보안 분석을 수행합니다.
SQL Injection을 비롯한 주요 취약점을 자동 탐지하고, Confluence 보고서 게시까지 일관된 파이프라인을 제공합니다.

> **현재 집중 영역: `skills/sec-audit-static` (SAST)**

### 핵심 원칙

- **호출 그래프 기반 진단** — HTTP 파라미터에서 SQL 실행까지 taint 전파 경로를 추적
- **재현 가능** — 동일 입력에 동일 결과를 보장하는 스키마 기반 파이프라인 (SHA-256 검증)
- **AI 거버넌스** — 데이터 분류, 민감정보 마스킹, 프롬프트 표준화, 감사 추적
- **Self-Contained Skills** — 진단 기준·스키마·룰·프롬프트가 `skills/` 디렉터리 단위로 독립 관리

---

## 빠른 시작

```bash
# 1. 대상 소스코드를 testbed에 배치
cp -r <project-source> testbed/<project-name>/

# 2. 환경 변수 설정
cp .env.example .env    # CONFLUENCE_TOKEN, BITBUCKET_TOKEN 등 입력

# 3. 슬래시 명령으로 전체 워크플로 실행 (현재 운영 중)
/sec-audit-static
```

또는 스크립트를 단계별로 직접 실행:

```bash
# API 인벤토리 추출
python tools/scripts/scan_api.py --source testbed/<project-name>/

# SQL Injection 진단 (호출 그래프 추적)
python tools/scripts/scan_injection_enhanced.py \
  --source testbed/<project-name>/ \
  --output state/<project>_sqli.json

# Confluence 게시
python tools/scripts/publish_confluence.py

# Bitbucket 동기화 (skills/tools 팀 공유)
python tools/scripts/push_bitbucket.py
```

---

## 스킬 구성

| 슬래시 명령 | 스킬 | 상태 |
|------------|------|------|
| `/sec-audit-static` | 정적 코드 분석 (SAST) | **운영 중** |

---

## `sec-audit-static` 워크플로

`/sec-audit-static` 실행 시 아래 4개 Phase를 순서대로 진행합니다.

```
Phase 1: 자산 식별
  └── Task 1-1  자산 식별 (Excel → JSON)

Phase 2: 정적 분석 (자동스캔)
  └── Task 2-1  API 인벤토리          ← scan_api.py (script-first)
      └── 글로벌 필터·인터셉터 확인
      └── 병렬 실행 ──┬── Task 2-2  인젝션 검토 (SQL / OS Command / SSI)
                      │                ← scan_injection_enhanced.py → LLM 교차검증
                      ├── Task 2-3  XSS 검토 (Persistent / Reflected / DOM / Redirect)
                      │                ← scan_xss.py (v2.4.0) → LLM 보조
                      ├── Task 2-4  파일 처리 검토 (Upload / Download / LFI / RFI)
                      │                ← scan_file_processing.py (v1.0) → LLM 보조
                      └── Task 2-5  데이터 보호 검토 (CORS / Secrets / JWT / Crypto / Logging)
                                       ← scan_data_protection.py (v1.1.0) → LLM 보조
  └── ⚠️ SCA [항상 필수]  오픈소스 의존성 CVE 진단
        Gradle: scan_sca_gradle_tree.py (전이적 의존성 트리 기반)
        npm:    scan_sca_gradle_tree.py (package-lock.json v3 기반)
        JAR:    scan_sca.py --jar (레거시)

Phase 3: LLM 수동분석 보완
  ├── Phase 3-1: 자동 탐지 "취약" 판정 → 수동 교차검증
  │     Controller → Service → Repository → SQL Builder 데이터 흐름 추적
  │     사용자 입력 도달 가능성 / 타입 안전성 / 코드 활성화 여부 / 분기 경로 검증
  ├── Phase 3-2: "정보/수동검토" 판정 → LLM 심층진단
  │     manual_review_prompt.md 기준 역추적 (DTO 래핑 / 동적 SQL ID 등)
  └── ⚠️ Phase 3-SCA [정기진단 필수]: SCA CVE 관련성 검토
        각 라이브러리별 소스코드 grep → 발생조건 검증
        판정: 적용 / 제한적 / 조건미충족(FP) / 확인불가
        한국어 CVE 설명 (description_ko, impact_ko, condition_ko) 작성
        절차: task_sca_llm_review.md

Phase 4: 보고서 생성 + Confluence 게시 [필수]
  └── generate_finding_report.py  → Markdown 보고서 (--anchor-style md2cf)
  └── publish_confluence.py       → Confluence 게시
        SCA: <prefix>_sca.json + supplemental_sources: [<prefix>_sca_llm.json]

Phase 5: SSC 정합성 검증 [정기진단 필수]
  └── fetch_ssc.py → LLM 교차검증 → <prefix>_ssc_report.md → Confluence 게시
```

### `sec-audit-static` 내부 구조

```
skills/sec-audit-static/
├── SKILL.md                          # 스킬 진입점 (워크플로 정의)
└── references/
    ├── workflow.md                   # Phase/Task 실행 맵, 보안 정책
    ├── injection_diagnosis_criteria.md  # SQL/OS/SSI 프레임워크별 진단 기준
    │                                    # (MyBatis / JPA / JDBC / Kotlin / R2DBC)
    ├── taint_tracking.md             # Source→Sink taint 추적 (Kotlin 포함)
    ├── cross_verification.md         # Phase 3-1 교차검증 + Phase 3-2 LLM 심층진단 절차
    ├── manual_review_prompt.md       # LLM 수동진단 페르소나, 진단기준, 역추적 프롬프트
    ├── global_filters.md             # 글로벌 필터·인터셉터 확인
    ├── output_schemas.md             # JSON 출력 스키마
    ├── severity_criteria.md          # 심각도 판정 기준
    ├── static_scripts.md             # 사용 가능 자동화 스크립트 목록
    ├── vuln_automation_principles.md # 발견/분석 분리 원칙
    ├── secret_scanning.md            # Gitleaks 기반 시크릿 탐지
    ├── poc_policy.md                 # PoC 생성 정책
    ├── seed_usage.md                 # Semgrep/Joern 시드 규칙
    ├── tooling.md                    # 코드 탐색 도구 (rg/ctags)
    ├── task_prompts/                 # 태스크별 진단 프롬프트
    │   ├── task_11_asset_identification.md
    │   ├── task_21_api_inventory.md
    │   ├── task_22_injection_review.md
    │   ├── task_23_xss_review.md
    │   ├── task_24_file_handling.md
    │   ├── task_25_data_protection.md
    │   ├── task_sca.md               #   SCA 진단 절차
    │   └── task_sca_llm_review.md    #   Phase 3-SCA LLM 관련성 검토 절차 ★
    ├── schemas/                      # JSON 스키마 (validate_task_output.py 연동)
    │   ├── finding_schema.json
    │   └── task_output_schema.json
    └── rules/                        # 탐지 룰
        ├── semgrep/                  #   Semgrep YAML 룰 (7개)
        └── joern/                    #   Joern taint 쿼리 (2개)
```

---

## 디렉터리 구조

```
playbook/
├── skills/                          # Self-Contained 스킬 정의
│   ├── sec-audit-static/            #   ★ 정적 분석 (SAST) — 현재 운영 중
│   ├── SEVERITY_CRITERIA_DETAIL.md  #   심각도 판정 기준 (공통)
│   └── USAGE_EXAMPLES.md            #   사용 예시
│
├── tools/
│   ├── confluence_page_map.json     # Confluence 페이지 매핑 (정합성 검증 이력)
│   └── scripts/
│       ├── scan_api.py              #   API 엔드포인트 인벤토리 추출
│       ├── scan_dto.py              #   DTO/타입 카탈로그 추출 (scan_api.py 연동)
│       ├── scan_injection_enhanced.py  #   SQL Injection 진단 엔진 ★
│       ├── scan_injection_patterns.py  #   패턴 상수 모음 (scan_injection_enhanced 의존)
│       ├── scan_xss.py              #   XSS 진단 엔진 (v2.4.0) ★
│       ├── scan_file_processing.py  #   파일 처리 취약점 진단 (v1.0) ★
│       ├── scan_data_protection.py  #   데이터 보호 진단 — 7개 모듈 (v1.1.0) ★
│       ├── scan_sca_gradle_tree.py  #   SCA v2 — Gradle/npm 전이적 의존성 CVE 진단 ★
│       ├── scan_sca.py              #   SCA v1 — JAR 기반 (레거시)
│       ├── setup_linux_jdk.sh       #   WSL2 Linux-native JDK 자동 설치
│       ├── publish_confluence.py    #   Confluence 보고서 게시
│       ├── push_bitbucket.py        #   Bitbucket 팀 공유 (증분 커밋)
│       ├── generate_finding_report.py  #   Markdown 보고서 생성
│       ├── generate_reporting_summary.py  #  크로스 스킬 요약 보고서 생성
│       ├── merge_results.py         #   다중 태스크 결과 집계
│       ├── parse_asset_excel.py     #   자산 Excel → JSON 변환
│       ├── validate_task_output.py  #   스키마 유효성 검증
│       ├── redact.py                #   민감정보 마스킹
│       └── run_gitleaks.sh          #   시크릿 스캔 (Gitleaks)
│
├── docs/
│   └── 정책보고서.md                # SCM-2026-001 형상관리 정책 (GitHub/Bitbucket 이원화)
│
├── RELEASENOTE.md                   # 버전 이력 (SemVer)
├── TODO.md                          # 작업 목록 (우선순위·상태·담당)
├── CLAUDE.md                        # Claude Code 프로젝트 지침
├── .env                             # 환경 변수 (gitignored)
├── testbed/                         # 진단 대상 소스코드 (gitignored)
└── state/                           # 진단 결과 JSON/MD (gitignored)
```

---

## 핵심 스크립트 상세

### `scan_injection_enhanced.py` — SQL Injection 진단 엔진

Controller → Service → Repository 호출 그래프를 추적하여 HTTP 파라미터의 SQL 삽입 경로를 분석합니다.

```bash
python tools/scripts/scan_injection_enhanced.py \
  --source testbed/<project>/ \
  --output state/<project>_sqli.json
```

**판정 방식:**

| 판정 | 의미 | 예시 |
|------|------|------|
| `[실제] SQL Injection` | HTTP 파라미터 → SQL taint 경로 확인 | `${}` / `$param$` 직접 삽입 |
| `[잠재] 취약한 쿼리 구조` | 취약 구조이나 taint 미확인 | 동적 쿼리 조합 패턴 |
| `양호` | JPA·MyBatis `#{}` 바인딩 / DB 미접근 | `@Query`, `#{}`, JPA builtin |
| `정보` | 외부 모듈·XML 미발견·추적 불가 | 외부 라이브러리 위임 |

**지원 기술 스택:** Java / Kotlin · Spring · MyBatis · iBatis · JPA / Hibernate · QueryDSL · R2DBC

**주요 기능:**
- Phase 24 Positional Index Taint Tracking (HTTP param → Service → Repository 계층간 전파)
- MyBatis `<include>` 인라인 치환 (`_resolve_sql_text` — 순환 참조 방지 + 중첩 include)
- iBatis `<sqlMap>` namespace 없는 파일 인식 (stem 폴백)
- DTO 래핑 taint 추적 (DTO 접근자 패턴 + `conservative_fallback`)
- HTTP 클라이언트 서비스 자동 양호 확정 (`RestTemplate`, `WebClient`, `FeignClient` 등)
- `@Query nativeQuery=true` 판별 + `+` 연결 취약 탐지
- QueryDSL `Expressions.stringTemplate()` `{0}` 플레이스홀더 vs `+` 연결 구분

### `scan_xss.py` (v2.4.0) — XSS 진단 엔진

Persistent XSS (DB 저장 후 출력) / Reflected XSS (Taint Flow 검증) / DOM XSS / Open Redirect를 탐지합니다.

```bash
python tools/scripts/scan_xss.py <source_dir> \
  --api-inventory state/<project>_api_inventory.json \
  -o state/<project>_task23.json
```

### `scan_file_processing.py` (v1.0) — 파일 처리 취약점 진단

Upload / Download / LFI / RFI(SSRF) 엔드포인트를 탐지하고 보안 검증 여부를 판정합니다.

```bash
python tools/scripts/scan_file_processing.py <source_dir> \
  --api-inventory state/<project>_api_inventory.json \
  -o state/<project>_task24.json
```

### `scan_data_protection.py` (v1.1.0) — 데이터 보호 진단 엔진

CORS·하드코딩 시크릿·민감정보 로깅·취약 암호화·JWT·DTO 과다노출·보안 헤더 등 7개 모듈을 자동 스캔합니다.

```bash
python tools/scripts/scan_data_protection.py <source_dir> \
  --api-inventory state/<project>_api_inventory.json \
  -o state/<project>_task25.json \
  [--skip logging]  # 특정 모듈 제외
```

### `publish_confluence.py` — Confluence 게시

```bash
python tools/scripts/publish_confluence.py [--dry-run] [--filter <file>]
```

### `push_bitbucket.py` — Bitbucket 팀 공유

`skills/`, `tools/`, `docs/`, `RELEASENOTE.md`, `TODO.md`를 증분 커밋으로 push합니다.

```bash
# 일반 push
python tools/scripts/push_bitbucket.py

# PR 모드 (develop → main)
python tools/scripts/push_bitbucket.py --pr
```

---

## 위험 점수 산정

`merge_results.py`에서 아래 가중치로 위험 점수(0~100)를 산정합니다.

| 심각도 | 가중치 | 예시 |
|--------|--------|------|
| Critical | ×10 | RCE, 인증 우회 |
| High | ×7 | SQLi, 민감정보 평문 저장 |
| Medium | ×4 | CORS 설정 오류, 캐시 키 충돌 |
| Low | ×1 | 불필요한 정보 노출 |

---

## AI 거버넌스

### 데이터 분류

| 등급 | 예시 | AI 전달 |
|------|------|---------|
| Public | 오픈소스 코드 | 허용 |
| Internal | 사내 소스 코드 | 마스킹 후 허용 |
| Confidential | DB 비밀번호, API 시크릿 | 금지 |
| Top Secret | 고객 PII, 금융 데이터 | 금지 |

### 자동 마스킹 대상

IP 주소, 이메일, API 키, JWT 토큰, 전화번호, 비밀번호, 인증서 등 8개 패턴을 `redact.py`가 자동 치환합니다.

### 감사 추적

`ai/ai-manifest.yaml`에 모든 AI 세션 ID, 모델명, 생성 파일, 검증 상태가 기록됩니다.

---

## 스키마 구조

### 태스크 출력 (`task_output_schema.json`)

```json
{
  "task_id": "2-2",
  "status": "completed",
  "findings": [...],
  "executed_at": "2026-02-25T00:00:00Z",
  "claude_session": "session-id"
}
```

### 취약점 항목 (`finding_schema.json`)

```json
{
  "id": "INJ-001",
  "title": "SQL Injection — 동적 쿼리 직접 삽입",
  "severity": "High",
  "category": "Injection / SQL Injection",
  "description": "...",
  "affected_endpoint": "/api/search",
  "evidence": { "file": "...", "lines": "64-96", "code_snippet": "..." },
  "cwe_id": "CWE-89",
  "owasp_category": "A03:2021 Injection",
  "recommendation": "PreparedStatement 또는 #{} 바인딩 파라미터 사용"
}
```

---

## 기술 스택

- **언어:** Python 3, YAML, JSON, Markdown
- **AI:** Claude Sonnet (Anthropic) — Claude Code CLI 환경
- **진단 대상:** Java / Kotlin · Spring Boot · MyBatis · iBatis · JPA · QueryDSL
- **라이브러리:** openpyxl (Excel), jsonschema (검증), urllib (Confluence API)
- **게시:** Confluence Server/DC REST API, Bitbucket Server REST API

---

## 버전 관리

현재 버전: **v4.9.4** — [RELEASENOTE.md](RELEASENOTE.md) 참조

진행 중 과제: [TODO.md](TODO.md) 참조

---

## 라이선스

이 프로젝트는 내부 보안 진단 목적으로 사용됩니다.
