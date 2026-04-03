# Task 2-6 / Task 3-6: 프론트엔드 클라이언트 사이드 보안 진단

> **적용 조건**: 진단 대상 repo가 프론트엔드 앱(TypeScript/JavaScript)인 경우 본 Task를 수행한다.
>
> **프론트엔드 판정 기준** (Phase 1 Task 1-1에서 확정):
> - `package.json` 존재
> - `.java`, `.kt` 파일 0건
> - 주 언어: TypeScript / JavaScript / JSX / TSX
>
> **지원 프레임워크**: React (Webpack/Vite), Next.js, React + Turborepo monorepo

---

## 진단 범위 (5대 항목)

| # | 항목 | 설명 |
|---|---|---|
| FE-XSS | 클라이언트 사이드 XSS | dangerouslySetInnerHTML / innerHTML / eval() / document.write() |
| FE-SECRET | 하드코딩 시크릿 | .env 파일 커밋, 소스코드 내 API 키/토큰 하드코딩 |
| FE-STORAGE | 민감 데이터 브라우저 저장소 노출 | localStorage/sessionStorage에 인증 토큰·PII 저장 |
| FE-LOG | PII 콘솔 로그 | console.log/console.error에 사용자 개인정보 포함 |
| FE-SCA | npm 의존성 취약점 | package-lock.json CVE 점검 (scan_sca_gradle_tree.py) |

---

## Phase 2-6: 자동 탐지 (스크립트 + LLM grep)

### FE-XSS: 위험 패턴 검색

```bash
# dangerouslySetInnerHTML
rg "dangerouslySetInnerHTML" <src> -l

# innerHTML / outerHTML 직접 대입
rg "\.innerHTML\s*=" <src> -l
rg "\.outerHTML\s*=" <src> -l

# eval / Function 동적 실행
rg "\beval\s*\(" <src> --type ts --type js -l
rg "new Function\s*\(" <src> -l

# document.write
rg "document\.write\s*\(" <src> -l
```

**판정 기준**:
- `dangerouslySetInnerHTML={{ __html: variable }}` — 변수가 외부 입력이면 취약, 정적 문자열이면 양호
- `innerHTML = userInput` — 무조건 취약 (XSS 직접 주입)
- `eval(userInput)` — 무조건 취약 (Code Injection)
- `dangerouslySetInnerHTML={{ __html: t('...') }}` — i18n 정적 키이면 양호

### FE-SECRET: 하드코딩 시크릿 탐지

```bash
# .env 파일 존재 여부 (커밋된 경우)
find <src> -name ".env" -not -name ".env.example" -not -name ".env.template"
find <src> -name ".env.local" -o -name ".env.production" -o -name ".env.real"

# 소스코드 내 API 키 패턴
rg "(api[_-]?key|apiKey|API_KEY|secret[_-]?key|secretKey|ACCESS_TOKEN|access_token)\s*[:=]\s*['\"][^'\"]{8,}" <src> --type ts --type js -l

# 하드코딩 토큰 (Bearer, Basic 인증)
rg "(Bearer|Basic)\s+[A-Za-z0-9+/]{20,}" <src> -l

# NEXT_PUBLIC_ 환경변수 서버 시크릿 노출 (Next.js)
rg "NEXT_PUBLIC_(SECRET|KEY|TOKEN|PASSWORD|PWD|DB)" <src> -i -l
```

**판정 기준**:
- `.env` 파일이 repo에 커밋되어 있고 실제 키 값이 있으면 취약 (High)
- `.env.example`은 템플릿이므로 양호
- `NEXT_PUBLIC_` prefix 변수는 클라이언트 번들에 포함되므로 시크릿 키 절대 사용 금지

### FE-STORAGE: 민감 데이터 저장소 노출

```bash
# localStorage / sessionStorage 저장 패턴
rg "(localStorage|sessionStorage)\.setItem" <src> --type ts --type js -n

# 저장 값에 token, password, mdn, phone, email, ssn 포함 여부
rg "(localStorage|sessionStorage)\.setItem.*\b(token|password|passwd|mdn|phone|email|birth|ssn|주민)\b" <src> -i --type ts --type js -l
```

**판정 기준**:
- `localStorage.setItem('token', jwt)` — 인증 토큰 저장은 관행이나, HTTPOnly 쿠키 권장 사항으로 Info 수준
- `localStorage.setItem('password', pwd)` — 패스워드 평문 저장은 High
- `localStorage.setItem('mdn', phone)` — 전화번호 등 PII 저장은 Medium

### FE-LOG: PII 콘솔 로그

```bash
# console.log에 사용자 데이터 포함
rg "console\.(log|error|warn|info)\s*\(" <src> --type ts --type js -n | grep -i "mdn\|phone\|email\|mbr\|user\|password\|token\|name\|birth"
```

**판정 기준**:
- 개발용 `console.log` 제거 여부 확인 (운영 빌드에 포함 여부)
- PII(전화번호, 이메일, 이름, 회원ID) 포함 시 Medium

---

## Phase 3-6: LLM 수동분석 (심층 검증)

### 검토 우선순위

1. **FE-XSS 후보**: `dangerouslySetInnerHTML`/`innerHTML` 발견 시 → 해당 컴포넌트 전체 코드 확인
   - Props/State 경유인지, API 응답값 직접 삽입인지, DOMPurify 등 sanitize 적용 여부
2. **FE-SECRET 후보**: API 키 패턴 발견 시 → 실제 시크릿 키인지 vs. 환경변수 키 이름만 있는지
3. **nginx 설정 (nginx.conf)**: CSP(Content-Security-Policy), X-Frame-Options, X-Content-Type-Options 헤더 누락 확인

### nginx 보안 헤더 체크 (해당 repo에 nginx.conf 포함 시)

```bash
find <src> -name "nginx.conf" -o -name "*.conf" | xargs rg "Content-Security-Policy|X-Frame-Options|X-Content-Type-Options" 2>/dev/null
```

**보안 헤더 누락 판정**: 모두 없으면 Info 수준으로 기록.

---

## 출력 형식

```json
{
  "task_id": "3-6",
  "status": "completed",
  "diagnosis_method": "수동진단(LLM)",
  "target": "<repo-name>",
  "framework": "React / Next.js / React+Turborepo",
  "findings": [
    {
      "id": "FE-001",
      "title": "...",
      "severity": "High | Medium | Low | Info",
      "category": "프론트엔드 보안 (Frontend Security)",
      "subcategory": "FE-XSS | FE-SECRET | FE-STORAGE | FE-LOG | FE-HEADER",
      "result": "취약 | 양호 | 해당없음",
      "needs_review": false,
      "diagnosis_method": "수동진단(LLM)",
      "evidence": {
        "file": "src/components/...",
        "line": 42,
        "code_snippet": "..."
      },
      "description": "한국어 설명",
      "recommendation": "조치 방안"
    }
  ],
  "frontend_assessment": {
    "xss_client_side": {"result": "양호 | 취약 (FE-001)"},
    "hardcoded_secret": {"result": "양호 | 취약"},
    "sensitive_storage": {"result": "양호 | 취약 | 해당없음"},
    "pii_logging": {"result": "양호 | 취약 | 해당없음"},
    "security_headers": {"result": "양호 | 누락 | 해당없음"}
  },
  "sca_covered": true,
  "executed_at": "YYYY-MM-DD",
  "claude_session": "..."
}
```

---

## SCA (npm 의존성 취약점)

`scan_sca_gradle_tree.py`는 `package-lock.json`을 자동 감지하여 npm 의존성 CVE 조회를 수행한다.

```bash
python3 tools/scripts/scan_sca_gradle_tree.py <src> --project <name> -o state/<prefix>/sca.json
```

- Phase 4 SCA 페이지에 통합 게시 (Java/Kotlin repo와 동일 절차)

---

## Confluence 게시 구조

프론트엔드 repo는 Java/Kotlin 대비 진단 항목이 적으므로 단일 보고서 페이지 구조 사용:

```
{서비스명}_ai자동진단_보고서  ← 메인 (client-side + data protection 통합)
  ├─ {서비스명}_ai자동진단_SCA
  └─ {서비스명}_ai자동진단_SSC검증  (SSC 프로젝트 존재 시)
```

> **⚠️ 인젝션/XSS(서버사이드)/파일처리 하위 페이지는 생성하지 않음** — 프론트엔드에 해당 없음.
