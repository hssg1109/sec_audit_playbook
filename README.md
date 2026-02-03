# AI 보안진단 플레이북

> AI 에이전트(Claude)를 활용한 정적 코드 보안 진단 자동화 프레임워크

## 개요

이 프로젝트는 웹 애플리케이션 소스 코드에 대한 **정적 보안 분석**을 체계적으로 수행하기 위한 플레이북입니다.
3단계(Phase) / 6개 태스크(Task) 구조의 워크플로를 통해, 자산 식별부터 취약점 진단, 보고서 생성까지 일관된 프로세스를 제공합니다.

### 핵심 원칙

- **정적 분석 전용** — 런타임 테스트 없이 소스 코드만 검사
- **재현 가능** — 동일 입력에 동일 결과를 보장하는 스키마 기반 파이프라인
- **AI 거버넌스** — 데이터 분류, 민감정보 마스킹, 프롬프트 표준화, 감사 추적

---

## 워크플로 구조

```
Phase 1: 자산 식별
  └── Task 1-1  자산 식별 (Excel → JSON)

Phase 2: 정적 분석
  └── Task 2-1  API 인벤토리 (선행 태스크)
      └── 병렬 실행 ──┬── Task 2-2  인젝션 취약점 검토
                      ├── Task 2-3  XSS 취약점 검토
                      ├── Task 2-4  파일 처리 검토
                      └── Task 2-5  데이터 보호 검토

Phase 3: 보고
  └── merge_results.py → 최종 보고서 (final_report.json)
  └── publish_confluence.py → Confluence 게시 (선택)
```

---

## 디렉터리 구조

```
playbook/
├── ai/                         # AI 거버넌스 정책
│   ├── ai-manifest.yaml        #   세션 추적 매니페스트
│   ├── AI_USAGE_POLICY.md      #   AI 사용 정책
│   ├── PROMPT_STYLE_GUIDE.md   #   프롬프트 작성 표준
│   └── REDACTION_RULES.md      #   민감정보 마스킹 규칙
│
├── docs/                       # 절차서 문서 (9개)
│   ├── 00_overview.md          #   진단 프로세스 개요
│   ├── 10_asset_identification.md
│   ├── 20_static_analysis.md   #   정적 분석 개요 (21~25 상위)
│   ├── 21_api_inventory.md
│   ├── 22_injection_review.md
│   ├── 23_xss_review.md
│   ├── 24_file_handling_review.md
│   ├── 25_data_protection_review.md
│   └── PLAYBOOK_GUIDE.md       #   마스터 가이드
│
├── prompts/static/             # AI 태스크 프롬프트 (6개)
│   ├── task_11_asset_identification.md
│   ├── task_21_api_inventory.md
│   ├── task_22_injection_review.md
│   ├── task_23_xss_review.md
│   ├── task_24_file_handling.md
│   └── task_25_data_protection.md
│
├── schemas/                    # JSON 유효성 검증 스키마
│   ├── finding_schema.json
│   └── task_output_schema.json
│
├── state/                      # 태스크 실행 결과 (JSON)
│   ├── task_11_result.json
│   ├── task_21_result.json
│   ├── task_22_result.json
│   ├── task_23_result.json
│   ├── task_24_result.json
│   ├── task_25_result.json
│   └── final_report.json
│
├── tools/                      # 자동화 도구
│   ├── confluence_page_map.json
│   └── scripts/
│       ├── parse_asset_excel.py     # Excel → JSON 변환
│       ├── validate_task_output.py  # 스키마 유효성 검증
│       ├── redact.py                # 민감정보 마스킹
│       ├── merge_results.py         # 결과 집계 → 최종 보고서
│       └── publish_confluence.py    # Confluence 게시
│
├── workflows/
│   └── audit_workflow.yaml     # 워크플로 정의 (v2.0)
│
└── 1-oiam/                     # 진단 대상 소스 코드
```

---

## 실행 방법

### 1. 자산 식별 (Phase 1)

```bash
# 고객 제공 Excel 자산 목록을 JSON으로 변환
python tools/scripts/parse_asset_excel.py \
  --input 1-oiam/자산정보.xlsx \
  --output state/task_11_result.json
```

### 2. 정적 분석 (Phase 2)

각 태스크는 `prompts/static/` 의 프롬프트를 AI 에이전트에 전달하여 실행합니다.

```bash
# Task 2-1: API 인벤토리 (선행)
#   입력: 소스 코드 + state/task_11_result.json
#   출력: state/task_21_result.json

# Task 2-2~2-5: 취약점 검토 (2-1 완료 후 병렬)
#   입력: 소스 코드 + state/task_21_result.json
#   출력: state/task_2X_result.json
```

### 3. 보고서 생성 (Phase 3)

```bash
# 전체 태스크 결과를 하나의 최종 보고서로 집계
python tools/scripts/merge_results.py

# 민감정보 마스킹 (공유 전)
python tools/scripts/redact.py state/final_report.json

# 스키마 유효성 검증
python tools/scripts/validate_task_output.py state/final_report.json
```

### 4. Confluence 게시 (선택)

```bash
# .env 설정
cp .env.example .env
# CONFLUENCE_TOKEN 등 값 입력

# 전체 게시 (dry-run)
python tools/scripts/publish_confluence.py --dry-run

# 실제 게시
python tools/scripts/publish_confluence.py

# 특정 파일만 게시
python tools/scripts/publish_confluence.py --filter docs/00_overview.md
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
  "executed_at": "2026-01-29T05:50:00Z",
  "claude_session": "session-id"
}
```

### 취약점 항목 (`finding_schema.json`)

```json
{
  "id": "INJ-001",
  "title": "IP 기반 ACL 우회",
  "severity": "High",
  "category": "Injection / Header Manipulation",
  "description": "...",
  "affected_endpoint": "/api/auth",
  "evidence": { "file": "...", "lines": "64-96", "code_snippet": "..." },
  "cwe_id": "CWE-290",
  "owasp_category": "A01:2021 Broken Access Control",
  "recommendation": "..."
}
```

---

## 기술 스택

- **언어:** Python 3, YAML, JSON, Markdown
- **AI:** Claude (Anthropic)
- **라이브러리:** openpyxl (Excel), jsonschema (검증), urllib (Confluence API)
- **게시:** Confluence Server/DC REST API
- **워크플로:** YAML 기반 태스크 오케스트레이션

---

## 라이선스

이 프로젝트는 내부 보안 진단 목적으로 사용됩니다.
