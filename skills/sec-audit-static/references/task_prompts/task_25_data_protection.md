## Task: 2-5 데이터 보호 검토 (LLM 수동분석 보완)

**역할**: 당신은 보안 진단 전문가입니다.
**입력 파일**: `state/<prefix>_task25.json` (scan_data_protection.py 자동스캔 결과)
**출력 파일**: `state/<prefix>_task25_llm.json` (LLM 수동분석 보완 — supplemental)
**게시 방식**: 별도 Confluence 페이지 X → `<prefix>_task25.json` finding 페이지의 `supplemental_sources`로 통합

> ⚠️ **이 JSON은 자동스캔 페이지에 통합 렌더링된다.** 독립 보고서가 아님.
> `confluence_page_map.json`의 data_protection finding 항목에 `supplemental_sources` 배열로 추가할 것.

---

### 컨텍스트

`scan_data_protection.py`로 1차 자동 스캔 후, 자동 탐지 한계인 **관리자 페이지 분리**, **DTO 과다 노출 심층 확인**, **needs_review 항목 판정**에 대해 LLM이 보조 분석합니다.
또한 개별 탐지 건수가 많은 카테고리(HARDCODED_SECRET, SENSITIVE_LOGGING)는 **파일/환경/심각도 단위로 병합**하여 최종 보고서 가독성을 높입니다.

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
  ├─ needs_review: true 항목 판정 (케이스 A/B/C)
  ├─ 관리자 페이지 분리 여부
  ├─ DTO 민감 필드 직렬화 우회 확인
  ├─ [병합] HARDCODED_SECRET: 파일/환경 단위 그룹화
  └─ [병합] SENSITIVE_LOGGING: 심각도 단위 그룹화 + FP 노트
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

### Step 5: HARDCODED_SECRET — 파일/환경 단위 병합

자동 스캔의 개별 findings를 **파일 경로 및 배포 환경 단위**로 그룹화하여 가독성을 높입니다.

**병합 기준표:**

| 우선순위 | 그룹 기준 | 심각도 상한 |
|---|---|---|
| 1 | 운영 코드(Java/Kotlin 소스) 내 리터럴 → 파일별 1건 | Critical |
| 2 | `src/main/resources/` (공통 설정) → 파일별 1건 | High |
| 3 | `src/main/resources-ccalp/` (ALP/운영 유사) → 파일별 1건 | High |
| 4 | `src/main/resources-cc*/` (개발/스테이지) → 환경별 파일 유형 그룹 | Medium |
| 5 | `src/main/resources-local-*/` (로컬 개발) → 1건 | Low |

**병합 규칙:**
1. 동일 파일 내 여러 라인 → 1개 finding, `lines` 배열에 전체 라인 번호 나열
2. 동일 환경의 동일 유형 파일 (예: ccdev/*.properties 3파일) → 1개 finding, `file` 필드에 쉼표 구분 나열
3. 병합 시 가장 높은 severity 유지
4. `evidence.code_snippet`에 대표 1건만 기재, 나머지는 "외 N건" 표기
5. **운영 자격증명 확정 근거** (`newocbpushreal` 'real' 접미사, `IS_DEBUG=false` 분기 등)는 `manual_review_note`에 명시

**LLM 심각도 상향 조건 (케이스 A):**
- 소스 경로가 `src/main/java/` (운영 코드) → 운영 키 확정 시 **Critical** 상향 권고
- 설정 파일명에 `real`, `prod`, `운영` 포함 → **운영 자격증명 확정**, `needs_review: false`

---

### Step 6: SENSITIVE_LOGGING — 심각도 단위 병합

자동 스캔의 개별 findings를 **로그 레벨(심각도) 기준 2개**로 통합합니다.

**병합 규칙:**

| 버킷 | 조건 | finding 1건으로 통합 | 결과 | 심각도 |
|---|---|---|---|---|
| `high` | `info/warn/error/fatal` 레벨 PII 로깅 | 전체 파일 × 라인 집계 | **취약** | **Critical** |
| `low` | `debug/trace` 레벨 PII 로깅 | 전체 파일 × 라인 집계 | 정보 | Info |

**evidence 기재 방법:**
```
"file": "대표 파일 외 N개 파일 (총 M건)",
"lines": "대표 라인 번호 (대표 샘플)",
"code_snippet": "대표 2~3건 샘플 코드 + (※ 컨설턴트 Note: FP 가능성 있는 항목 명시)"
```

**FP 컨설턴트 노트 기재 기준:**
- Kotlin 문자열 보간(`$hmacSignature`) — 변수명이 PII 패턴에 일치하나 실제로는 서명값인 경우
- 로그 메시지 내 문자열 리터럴(예: `"Auth Fail"`)에 PII 키워드 포함된 경우
- FP 가능성이 있으면 `code_snippet` 하단에 아래 형식으로 반드시 기재:
  ```
  (※ 컨설턴트 Note: [파일명:라인]의 [코드 패턴]은 FP(오탐) 가능성이 있으나,
  [다른 파일:라인]의 mbrId 직접 바인딩은 명백한 취약점(TP)입니다.)
  ```

**대응 방안 필수 포함 항목:**
1. 즉시 조치: `MaskingUtils.mask()` 적용 리팩토링
2. 근본 조치: Logback `MessageConverter` 커스텀 구현으로 전역 자동 마스킹 아키텍처 도입

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

자동스캔 결과(`<prefix>_task25.json`)를 기반으로, **병합·확정된 findings 전체**를 출력합니다.
HARDCODED_SECRET / SENSITIVE_LOGGING은 Step 5/6 병합 규칙을 적용하여 통합 finding으로 출력하고,
WEAK_CRYPTO / CORS / JWT 등 나머지 카테고리는 자동스캔 확정 항목만 포함합니다.

```json
{
  "task_id": "2-5",
  "status": "completed",
  "findings": [
    {
      "id": "DATA-SEC-NNN",
      "title": "[병합 그룹 제목] — 파일명 (N건 병합)",
      "severity": "Critical / High / Medium / Low",
      "category": "HARDCODED_SECRET",
      "description": "(LLM 확정 또는 자동스캔 확인) 상세 설명. 운영 키 확정 근거 포함.",
      "affected_endpoint": "전역 또는 특정 엔드포인트",
      "evidence": {
        "file": "src/main/resources/config.properties",
        "lines": "214, 1054, 1162, ...",
        "code_snippet": "// 대표 코드 스니펫 (마스킹 처리)\n// 외 N건 — 원본 스캐너 report 참조"
      },
      "cwe_id": "CWE-798",
      "owasp_category": "A02:2021 Cryptographic Failures",
      "diagnosis_method": "자동스캔(SAST) + 수동진단(LLM)",
      "result": "취약",
      "needs_review": false,
      "manual_review_note": "[케이스 A 확정] 운영 키 판별 근거 기재",
      "recommendation": "조치 방안 (환경별 단계별 제시)"
    },
    {
      "id": "DATA-LOG-001",
      "title": "운영 환경(info/error) 로그 내 PII 평문 노출 — N건 병합",
      "severity": "Critical",
      "category": "SENSITIVE_LOGGING",
      "description": "운영 활성 로그 레벨에 mbrId/mdn 등 PII가 마스킹 없이 출력됨. PIPA 위반 가능.",
      "affected_endpoint": "서비스 전반",
      "evidence": {
        "file": "대표 파일 외 N개 파일 (총 N건)",
        "lines": "대표 라인 번호",
        "code_snippet": "// 대표 샘플\nlog.info(\"mbrId={}\", mbrId);\n\n// (※ 컨설턴트 Note: FP 가능성 있는 항목은 여기에 명시)"
      },
      "cwe_id": "CWE-532",
      "owasp_category": "A09:2021 Security Logging and Monitoring Failures",
      "diagnosis_method": "자동스캔(SAST) + 수동진단(LLM)",
      "result": "취약",
      "needs_review": false,
      "manual_review_note": "[케이스 B 확정] info/error 레벨 PII 직접 바인딩 확인. MaskingUtil 미적용.",
      "recommendation": "1) MaskingUtils.mask() 전면 적용.\n2) Logback MessageConverter 커스텀 구현으로 전역 자동 마스킹 아키텍처 도입."
    }
  ],
  "data_protection_assessment": {
    "admin_page_separation": "물리적 분리 / 논리적 분리 / 미분리 / 미확인 중 하나",
    "cors_wildcard": false,
    "jwt_unsigned_allowed": false,
    "hardcoded_secret_consolidated_count": 8,
    "hardcoded_secret_original_findings": 23,
    "sensitive_logging_critical_count": 117,
    "sensitive_logging_info_count": 80,
    "sensitive_logging_consolidated_count": 2,
    "weak_crypto_count": 2
  },
  "consolidation_note": "자동스캔 N건을 파일/심각도 단위로 병합. 원본 개별 findings는 state/<prefix>_task25.json에 증적 보존.",
  "executed_at": "",
  "claude_session": ""
}
```

**ID 명명 규칙:**
- `DATA-SEC-NNN` — HARDCODED_SECRET 병합 그룹 (환경/파일 단위, 001부터 순차 부여)
- `DATA-LOG-001` — SENSITIVE_LOGGING Critical 병합 (운영 로그 레벨)
- `DATA-LOG-002` — SENSITIVE_LOGGING Info 병합 (개발 로그 레벨)
- `DATA-LLM-NNN` — 기타 LLM 단독 발견 (WEAK_CRYPTO, DTO 등)

**주의**:
- 원본 자동스캔 JSON(`<prefix>_task25.json`)은 수정하지 않는다. 증적 보존용.
- 병합 findings는 모두 이 LLM 파일(`<prefix>_task25_llm.json`)에만 작성한다.
- findings 배열이 비어 있으면(`[]`) 파일을 저장하되 `supplemental_sources`에서 자동으로 무시된다.

---

### 금지사항
- 추측 금지 (코드 근거 필수)
- 민감정보(실제 비밀번호, API 키 값) 포함 금지 → 마스킹 처리 (`****`)
- 자동 스캔 결과를 번복할 때는 코드 근거 명시 필수
- 스크립트가 이미 판정한 "양호" 항목은 재검토 불필요
- 병합 시 원본 findings의 증적(라인 번호, 파일 경로)을 누락하지 않는다
