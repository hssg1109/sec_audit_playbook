## Task: 2-5 데이터 보호 검토

**역할**: 당신은 보안 진단 전문가입니다.
**입력 파일**: `state/task_21_result.json` (API 인벤토리), `state/<prefix>_task25.json` (자동 스캔 결과)
**출력 파일**: `state/task_25_result.json`
**출력 스키마**: `schemas/finding_schema.json`

> **참고**: 상세 진단 기준은 `skills/sec-audit-static/references/task_prompts/task_25_data_protection.md` 참조

---

### 컨텍스트

`scan_data_protection.py`로 1차 자동 스캔(7개 모듈) 후, 자동 탐지 한계인 **관리자 페이지 분리**, **DTO 과다 노출 심층 확인**, **needs_review 항목 판정**에 대해 LLM이 보조 분석합니다.

**자동 스캔 실행:**
```bash
python tools/scripts/scan_data_protection.py <source_dir> \
    --api-inventory state/<prefix>_api_inventory.json \
    -o state/<prefix>_task25.json
```

**자동 스캔 모듈 (7개):**

| 카테고리 | 대상 | CWE |
|---|---|---|
| `HARDCODED_SECRET` | 하드코딩된 비밀번호·API키·AWS 자격증명 | CWE-798 |
| `SENSITIVE_LOGGING` | PII(주민번호·전화번호·카드번호) 직접 로깅 | CWE-532 |
| `WEAK_CRYPTO` | MD5·SHA-1 해시, DES·AES/ECB 암호화 | CWE-327 |
| `JWT_ISSUE` | 미서명 토큰 허용, `SignatureAlgorithm.NONE` | CWE-347 |
| `DTO_EXPOSURE` | 응답 DTO 내 민감 필드 `@JsonIgnore` 미적용 | CWE-200 |
| `CORS_MISCONFIGURATION` | 와일드카드 Origin, Origin 헤더 직접 반영 | CWE-942 |
| `SECURITY_HEADER` | `.headers().disable()`, CSRF 비활성화 | CWE-693 |

---

### Step 1: 자동 스캔 결과 검토

`state/<prefix>_task25.json`을 로드하여 확인:
- `result: "취약"` → 코드 근거 재확인 후 최종 판정
- `needs_review: true` → `manual_review_prompt.md` 케이스 A/B/C 기준 심층 분석

---

### Step 2: 관리자 페이지 분리 (수동 확인 필요)

**판정 기준:**
- 별도 서버/포트 분리 (물리적·논리적) → **양호**
- `hasIpAddress` IP 접근제어 적용 → **양호**
- 동일 서버/포트에서 접근 가능 → **취약**

**검색 키워드:** `admin`, `/admin`, `management`, `/manage`, `@PreAuthorize`, `hasRole('ADMIN')`, `hasIpAddress`

---

### 판정 기준

| 심각도 | 조건 |
|---|---|
| **Critical** | 소스코드 내 DB 비밀번호/API 시크릿/AWS 키 하드코딩 + 외부 접근 가능 |
| **High** | CORS 와일드카드 + credentials, JWT `none` 알고리즘, 미서명 토큰 허용 |
| **Medium** | 응답 DTO 민감정보 미마스킹, 관리자 페이지 미분리, PII 직접 로깅, Origin 우회 |
| **Low** | 취약 해시(MD5·SHA-1) 사용, 에러 페이지 서버 버전 노출, 주석 내 테스트 계정 |
| **Info** | 보안 개선 권고 (JWT 만료 미설정, AES/CBC→GCM 전환 등) |

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
    "source_repo_url": "http://code.example.com/projects/PROJ/repos/repo/",
    "source_repo_path": "/path/to/local/repo",
    "source_modules": ["module-a"],
    "report_wiki_url": "https://wiki.example.com/pages/viewpage.action?pageId=123",
    "report_wiki_status": "published"
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
