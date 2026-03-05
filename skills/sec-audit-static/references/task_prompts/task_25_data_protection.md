## Task: 2-5 데이터 보호 검토

**역할**: 당신은 보안 진단 전문가입니다.
**입력 파일**: `state/task_21_result.json` (API 인벤토리), `state/<prefix>_task25.json` (자동 스캔 결과)
**출력 파일**: `state/task_25_result.json`
**출력 스키마**: `references/schemas/finding_schema.json`

---

### 컨텍스트

`scan_data_protection.py`로 1차 자동 스캔 후, 자동 탐지 한계인 **관리자 페이지 분리**, **DTO 과다 노출 심층 확인**, **needs_review 항목 판정**에 대해 LLM이 보조 분석합니다.

```
자동 스캔 (scan_data_protection.py)
  ├─ HARDCODED_SECRET   → CWE-798
  ├─ SENSITIVE_LOGGING  → CWE-532
  ├─ WEAK_CRYPTO        → CWE-327
  ├─ JWT_ISSUE          → CWE-347
  ├─ DTO_EXPOSURE       → CWE-200
  ├─ CORS_MISCONFIGURATION → CWE-942
  └─ SECURITY_HEADER    → CWE-693

LLM 보조 분석 (이 프롬프트)
  ├─ needs_review: true 항목 판정
  ├─ 관리자 페이지 분리 여부
  └─ DTO 민감 필드 직렬화 우회 확인
```

---

### Step 1: 자동 스캔 결과 검토

`state/<prefix>_task25.json`을 로드하여 다음을 확인합니다:
- `result: "취약"` 항목 → 코드 근거 재확인 후 최종 판정
- `needs_review: true` 항목 → `manual_review_prompt.md` 케이스 A/B/C 기준 심층 분석

---

### Step 2: 관리자 페이지 분리 (자동 스캔 미지원)

**판정 기준:**
- 관리자 페이지가 별도 서버에서 서비스 (물리적 분리) → **양호**
- 동일 서버이나 별개 WAS/포트에서 서비스 (논리적 분리) → **양호**
- 동일 서버+WAS이나 IP 접근제어 (`hasIpAddress`) 적용 → **양호**
- 일반 사용자 페이지와 동일 서버/포트에서 접근 가능 → **취약**

**검색 키워드:** `admin`, `/admin`, `management`, `/manage`, `@PreAuthorize`, `hasRole('ADMIN')`, `hasIpAddress`

---

### Step 3: CORS 심층 확인

자동 스캔이 플래그한 CORS 항목에 대해 추가 확인:

| Origin 설정 | Credentials 설정 | 판정 |
|---|---|---|
| `*` (와일드카드) | `true` | **취약** |
| `*` (와일드카드) | 없음/false | **취약** |
| 특정 URL | `true` | **양호** (단, Origin 우회 확인 필요) |
| 특정 URL | 없음/false | **양호** |
| 미선언 | - | 단순 WEB → 양호, API 서버 → **취약** |

**Origin 우회 확인:**
- `request.getHeader("Origin")` 값을 그대로 응답에 반영하는 코드 → **취약**

---

### Step 4: JWT 보안 심층 확인

자동 스캔이 플래그한 JWT 항목에 대해 추가 확인:
- `parseUnsecuredClaims()` / `parseClaimsJwt()` 호출 → **취약** (미서명 토큰 허용)
- `SignatureAlgorithm.NONE` 사용 → **취약**
- JWT Secret Key가 짧거나 추측 가능 → **취약** (needs_review → 케이스 A 적용)
- JWT 만료 시간(`setExpiration`) 미설정 → **Info**

---

### 판정 기준

| 심각도 | 조건 |
|---|---|
| **Critical** | 소스코드 내 DB 비밀번호/API 시크릿/AWS 키 하드코딩 + 외부 접근 가능 |
| **High** | CORS 와일드카드 + credentials, JWT `none` 알고리즘, 미서명 토큰 허용 |
| **Medium** | 응답 DTO 민감정보 미마스킹, 관리자 페이지 미분리, PII 직접 로깅, Origin 우회 |
| **Low** | 취약 해시(MD5·SHA-1) 사용, 에러 페이지 서버 버전 노출, 주석 내 테스트 계정 |
| **Info** | 보안 개선 권고 (JWT 만료 미설정, AES/CBC→GCM 전환, CORS 정책 강화 등) |

---

### 출력 형식

```json
{
  "task_id": "2-5",
  "status": "completed",
  "findings": [
    {
      "id": "DATA-001",
      "title": "취약점 제목",
      "severity": "High",
      "category": "CORS_MISCONFIGURATION",
      "description": "상세 설명",
      "affected_endpoint": "/api/xxx 또는 전역",
      "evidence": {
        "file": "src/config/WebConfig.java",
        "lines": "20-30",
        "code_snippet": "취약 코드"
      },
      "cwe_id": "CWE-942",
      "owasp_category": "A05:2021 Security Misconfiguration",
      "recommendation": "조치 방안",
      "result": "취약",
      "needs_review": false
    }
  ],
  "metadata": {
    "source_repo_url": "",
    "source_repo_path": "",
    "source_modules": [],
    "report_wiki_url": "",
    "report_wiki_status": ""
  },
  "executed_at": "",
  "claude_session": ""
}
```

---

### 금지사항
- 추측 금지 (코드 근거 필수)
- 민감정보(실제 비밀번호, API 키 값) 포함 금지 → 마스킹 처리 (`****`)
- 자동 스캔 결과를 번복할 때는 코드 근거 명시 필수
