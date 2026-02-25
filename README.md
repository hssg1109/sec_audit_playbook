# AI 보안진단 플레이북

> AI 에이전트(Claude)를 활용한 소스코드 보안 진단 자동화 프레임워크 — v4.5.2

## 개요

웹 애플리케이션 소스 코드를 대상으로 **Controller → Service → Repository 호출 그래프 추적** 기반의 정적 보안 분석을 수행합니다.
SQL Injection을 비롯한 주요 취약점을 자동 탐지하고, Confluence 보고서 게시까지 일관된 파이프라인을 제공합니다.

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

# 3. API 인벤토리 추출
python tools/scripts/scan_api.py --source testbed/<project-name>/

# 4. SQL Injection 진단 (호출 그래프 추적)
python tools/scripts/scan_injection_enhanced.py \
  --source testbed/<project-name>/ \
  --output state/<project>_sqli.json

# 5. Confluence 게시
python tools/scripts/publish_confluence.py

# 6. Bitbucket 동기화 (skills/tools 팀 공유)
python tools/scripts/push_bitbucket.py --tag v4.5.2
```

또는 슬래시 명령으로 전체 워크플로 실행:

```
/sec-audit-static      정적 코드 분석 (SAST)
/sec-audit-dast        동적 애플리케이션 테스트 (DAST)
/external-software-analysis  외부 패키지·소프트웨어 분석
```

---

## 워크플로 구조

```
Phase 1: 자산 식별
  └── Task 1-1  자산 식별 (Excel → JSON)

Phase 2: 정적 분석
  └── Task 2-1  API 인벤토리 (선행 태스크)
      └── 병렬 실행 ──┬── Task 2-2  인젝션 취약점 검토  ← scan_injection_enhanced.py
                      ├── Task 2-3  XSS 취약점 검토
                      ├── Task 2-4  파일 처리 검토
                      └── Task 2-5  데이터 보호 검토

Phase 3: 보고
  └── generate_finding_report.py → Markdown 보고서
  └── publish_confluence.py      → Confluence 게시
  └── push_bitbucket.py          → Bitbucket 팀 공유
```

---

## 디렉터리 구조

```
playbook/
├── skills/                          # Self-Contained 스킬 정의
│   ├── sec-audit-static/            #   정적 분석 (SAST) 스킬
│   │   ├── SKILL.md                 #     스킬 진입점
│   │   ├── agents/openai.yaml       #     에이전트 설정
│   │   └── references/              #     진단 기준, 스키마, 룰, 프롬프트
│   ├── sec-audit-dast/              #   동적 분석 (DAST) 스킬
│   ├── external-software-analysis/  #   외부 소프트웨어 분석 스킬
│   ├── SEVERITY_CRITERIA_DETAIL.md  #   심각도 판정 기준 (공통)
│   └── USAGE_EXAMPLES.md            #   사용 예시
│
├── tools/
│   ├── confluence_page_map.json     # Confluence 페이지 매핑 (정합성 검증 이력)
│   └── scripts/
│       ├── scan_api.py              #   API 엔드포인트 인벤토리 추출
│       ├── scan_injection_enhanced.py  #   SQL Injection 진단 엔진 (v4.5.2) ★
│       ├── scan_injection_patterns.py  #   패턴 기반 취약점 탐지
│       ├── scan_dto.py              #   DTO 구조 분석
│       ├── publish_confluence.py    #   Confluence 보고서 게시
│       ├── push_bitbucket.py        #   Bitbucket 팀 공유 (증분 커밋, 태그)
│       ├── generate_finding_report.py  #   Markdown 보고서 생성
│       ├── generate_reporting_summary.py  #  요약 보고서 생성
│       ├── merge_results.py         #   다중 태스크 결과 집계
│       ├── parse_asset_excel.py     #   자산 Excel → JSON 변환
│       ├── validate_task_output.py  #   스키마 유효성 검증
│       ├── redact.py                #   민감정보 마스킹
│       ├── asm_findings_to_csv.py   #   ASM 취약점 CSV 변환
│       ├── sarif_from_csv.py        #   SARIF 포맷 변환
│       ├── extract_endpoints_rg.py  #   ripgrep 기반 엔드포인트 추출
│       └── run_gitleaks.sh          #   시크릿 스캔 (Gitleaks)
│
├── docs/                            # 절차서 문서
│   ├── 00_overview.md
│   ├── 10_asset_identification.md
│   ├── 20_static_analysis.md
│   ├── 21_api_inventory.md ~ 25_data_protection_review.md
│   ├── PLAYBOOK_GUIDE.md
│   └── 정책보고서.md
│
├── schemas/                         # JSON 유효성 검증 스키마
│   ├── finding_schema.json
│   ├── task_output_schema.json
│   └── reporting_summary_schema.json
│
├── ai/                              # AI 거버넌스 정책
│   ├── ai-manifest.yaml             #   세션 추적 매니페스트
│   ├── AI_USAGE_POLICY.md
│   ├── PROMPT_STYLE_GUIDE.md
│   └── REDACTION_RULES.md
│
├── RELEASENOTE.md                   # 버전 이력 (SemVer)
├── TODO.md                          # 작업 목록 (우선순위·상태·담당)
├── CLAUDE.md                        # Claude Code 프로젝트 지침
├── .env                             # 환경 변수 (gitignored)
│
├── testbed/                         # 진단 대상 소스코드 (gitignored)
└── state/                           # 진단 결과 JSON/MD (gitignored)
```

---

## 핵심 스크립트 상세

### `scan_injection_enhanced.py` (v4.5.2) — SQL Injection 진단 엔진

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
| `양호` | JPA·MyBatis `#{}` 바인딩 / DB 미접근 | `@Query`, `#{}`, JPA |
| `정보` | 외부 모듈·XML 미발견·추적 불가 | 외부 라이브러리 위임 |

**지원 기술 스택:** Java / Kotlin · Spring · MyBatis · iBatis · JPA / Hibernate

### `publish_confluence.py` — Confluence 게시

```bash
python tools/scripts/publish_confluence.py [--dry-run] [--filter <file>]
```

### `push_bitbucket.py` — Bitbucket 팀 공유

`skills/`, `tools/`, `RELEASENOTE.md`, `TODO.md`를 증분 커밋으로 push합니다.

```bash
# 일반 push
python tools/scripts/push_bitbucket.py

# 버전 태그 생성 (RELEASENOTE.md 자동 추출)
python tools/scripts/push_bitbucket.py --tag v4.5.2

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
- **진단 대상:** Java / Kotlin · Spring Boot · MyBatis · JPA
- **라이브러리:** openpyxl (Excel), jsonschema (검증), urllib (Confluence API)
- **게시:** Confluence Server/DC REST API, Bitbucket Server REST API
- **워크플로:** YAML 기반 태스크 오케스트레이션

---

## 버전 관리

현재 버전: **v4.5.2** — [RELEASENOTE.md](RELEASENOTE.md) 참조

진행 중 과제: [TODO.md](TODO.md) 참조

---

## 라이선스

이 프로젝트는 내부 보안 진단 목적으로 사용됩니다.
