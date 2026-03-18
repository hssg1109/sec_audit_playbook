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
- 소스 경로가 `src/main/java/` 또는 `src/main/kotlin/` (운영 코드) → **케이스 A 자동 확정**: `severity: Critical`, `needs_review: false` 강제. 별도 확인 불필요.
- 설정 파일명에 `real`, `prod`, `운영` 포함 → **운영 자격증명 확정**: `needs_review: false` 강제.

> ⚠️ **주의**: `src/main/java/` 경로 findings에 `needs_review: true`를 절대 남기지 않는다. 운영 코드 내 리터럴은 코드 경로만으로 운영 키 확정 근거가 된다.

---

### Step 5-FE: 프론트엔드(JS/React/Vue) 소스 특수 진단 기준

> 진단 대상이 **프론트엔드(SPA/MPA) 소스코드**인 경우, 아래 추가 기준을 적용한다.
> Java/Kotlin 백엔드 대상에는 해당 없음.

#### HARDCODED_SECRET — 프론트엔드 환경 심각도 및 대응방안

| 상황 | 심각도 | 대응방안 |
|---|---|---|
| 외부 API용 토큰/키가 JS 소스코드에 하드코딩 | **Critical** | BFF 아키텍처 전환 (아래 참조) |
| `.env` 파일이 git 추적 + 빌드 번들 참조 | **High** | `.gitignore` 추가 + CI/CD 환경변수 주입 |
| `.env` 파일이 git 추적이나 소스코드 미참조 | **Medium** | 잔존값 여부 확인 후 `.gitignore` 추가 |

**⚠️ 프론트엔드 환경변수는 시크릿 보관 수단이 아님 (중요)**
- React(`REACT_APP_*`) · Vite(`VITE_*`) 환경변수는 **빌드 시점에 JS 번들에 평문 삽입**됨
- 환경변수로 전환해도 브라우저 다운로드 번들에 노출 → 백엔드 `@Value("${...}")`와 완전히 다른 상황
- `"토큰은 환경변수 또는 Runtime에서 주입"` 문구를 FE 컨텍스트에 **절대 사용 금지**

**올바른 대응 — BFF(Backend For Frontend) 아키텍처:**
```
[AS-IS] 프론트엔드 → 토큰 하드코딩 → 외부 API 직접 호출
[TO-BE] 프론트엔드 → 자사 BFF API → (서버측 환경변수에서 토큰 로드) → 외부 API 대리 요청
```
recommendation 문구 예시:
```
"[아키텍처 전환 필수] 프론트엔드에서 외부 API로 직접 호출하는 구조를 제거하고
자사 백엔드(BFF: Backend For Frontend)를 경유하도록 변경.
BFF 서버가 서버사이드 환경변수에서 토큰을 로드하여 외부 API에 대리 요청 후 결과만 반환.
※ React/Vite 환경변수(REACT_APP_*/VITE_*)는 빌드 시 번들에 평문 포함되므로 시크릿 보관 불가."
```

#### SENSITIVE_LOGGING — 프론트엔드 console.log 특수 기준

| 상황 | 심각도 | 대응방안 |
|---|---|---|
| `console.log`에 세션 ID / 인증 헤더 / PII 출력 | **Info** | 직접 제거 + 빌드 파이프라인 자동 제거 설정 |

**빌드 파이프라인 자동 제거 설정 (recommendation 필수 포함):**
- Webpack: `TerserPlugin` 옵션 `drop_console: true` 적용
- Vite: `build.terserOptions.compress.drop_console = true`
- 수동 제거만으로는 재발 위험 — 빌드 파이프라인 설정을 근본 조치로 제안

---

### Step 6: SENSITIVE_LOGGING — 심각도 단위 병합

자동 스캔의 개별 findings를 **로그 레벨(심각도) 기준 2개**로 통합합니다.

**병합 규칙:**

| 버킷 | 조건 | finding 1건으로 통합 | 결과 | 심각도 |
|---|---|---|---|---|
| `high` | `info/warn/error/fatal` 레벨 PII 로깅 | 전체 파일 × 라인 집계 | **취약** | **Critical** |
| `low` | `debug/trace` 레벨 PII 로깅 | 전체 파일 × 라인 집계 | 정보 | **Medium** |

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

### Step 7: DTO_EXPOSURE FP 방지 룰

자동 스캐너가 `DTO_EXPOSURE`로 플래그한 항목 중 아래 패턴은 **코드 직접 확인 후 FP 처리**하십시오.

#### 7-1. 스캐너 한글 주석 파싱 버그

스캐너가 필드 선언 끝에 위치한 한글 주석을 **필드명·타입으로 오인**하는 버그가 있음.

| 버그 패턴 | 예시 코드 | 잘못된 스캐너 출력 | 실제 의미 |
|:---------|:---------|:-----------------|:---------|
| 빈 주석 `//` | `private String addr; //` | "민감 필드(//)" | 주석 없음 (FP) |
| 괄호 포함 주석 끝 | `// 카드번호 대용으로 사용되는 MDN 전화번호 (HP포인트 용)` | "민감 필드(용))" | MDN 전화번호 설명 (FP) |
| 키워드 포함 주석 | `// oneIdPass Token` | "민감 필드(Token)" | 주석 내 단어 (FP) |

**판정 기준:**
- `description`에 `민감 필드(//)`가 있으면 빈 주석 파싱 버그 → **FP**
- `description`에 `민감 필드(한글단어)` 형태에서 해당 단어가 Java 타입/필드명이 아닌 한글이면 주석 추출 버그 → **FP**

#### 7-2. 가맹점/비즈니스 주소 vs 고객 개인 주소 구분

`addr` 필드가 고객 PII(개인 주소)인지 비즈니스 데이터(가맹점 주소)인지 **컨텍스트 확인 필수**.

```
확인 절차:
1. 해당 DTO 클래스의 다른 필드 확인 → 쿠폰/가맹점 관련 필드(code, bizNm, couponSeq 등) = 가맹점 주소 → FP
2. 클래스명 확인 → SearchCoupon*, Partner*, Store* 계열 = 비즈니스 데이터 → FP
3. 고객 개인 주소가 포함된 DTO = UserAddress*, OrderDelivery* 계열 = 고객 PII → TP
```

#### 7-3. Safe by Design — 본인 정보 반환

**회원 본인에게 본인 정보를 반환하는 것은 정상 비즈니스 로직**이며 DTO 노출 취약점이 아님.

| 패턴 | 판정 |
|:-----|:---:|
| 인증된 세션 사용자에게 본인 `mbrId` 반환 | **양호 (Safe by Design)** |
| 로그인 응답에 본인 프로필 필드 포함 | **양호 (Safe by Design)** |
| **타인의** `mbrId`/개인정보가 응답에 포함 | **취약** |

#### 7-4. 세션/내부 객체 vs 응답 DTO 구분

스캐너가 모든 클래스를 응답 DTO로 취급하는 경우가 있음. `*Response`, `*Dto`, `*Vo`(응답용)가 아닌 세션 저장/내부 처리 객체는 FP 가능성 점검 필수.

```
확인 절차:
1. 클래스명 확인: UserInfo, SessionHolder, Context* 계열 = 내부 객체 → FP 가능성
2. 패키지 확인: util/session/helper 패키지 = 내부 객체 → FP 가능성
3. @RestController/@Controller 응답 타입 확인: 해당 DTO가 직접 직렬화되는지 확인
4. JSON 직렬화 경로에 없으면 → FP
```

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

> **`affected_endpoints` 작성 규칙 (전체 Task 공통)**
>
> 각 finding에서 실제로 영향을 받는 API 엔드포인트를 `affected_endpoints` 배열로 명시하십시오.
> 보고서 렌더링 시 이 목록은 `<details>` 펼치기 섹션 또는 Confluence Expand 매크로로 자동 출력됩니다.
>
> | 필드 | 필수 | 설명 |
> |---|:---:|---|
> | `method` | 권장 | HTTP 메서드 (GET/POST/PUT/DELETE 등). 전역 영향 시 생략 가능 |
> | `path` | **필수** | Request Mapping 경로 (예: `/api/v1/user/login`). 전역 영향 시 "전역 (전체 API)" |
> | `controller` | 권장 | 클래스명.메서드명() (예: `UserController.login()`) |
> | `description` | 권장 | 해당 엔드포인트에서 취약점이 어떻게 발현되는지 한 줄 설명 |
>
> - 특정 엔드포인트에 취약점이 한정되는 경우: 해당 엔드포인트만 기재
> - HARDCODED_SECRET 등 전역 영향: `"path": "전역 (시크릿 참조 전체 API)"` 1건 기재
> - SENSITIVE_LOGGING 다건 병합: 대표 2-3건만 기재하고 `description`에 "외 N건" 표기

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
      "affected_endpoints": [
        {
          "method": "",
          "path": "전역 (시크릿 참조 전체 API)",
          "controller": "",
          "description": "해당 자격증명을 사용하는 모든 외부 연동 엔드포인트에 영향"
        }
      ],
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
      "affected_endpoints": [
        {
          "method": "POST",
          "path": "/api/v1/user/login",
          "controller": "UserController.login()",
          "description": "mbrId가 log.info()에 직접 바인딩됨"
        },
        {
          "method": "GET",
          "path": "/api/v1/order/list",
          "controller": "OrderController.list()",
          "description": "cardNo가 log.error() 스택트레이스에 포함됨"
        }
      ],
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

---

### 코드 증적 품질 기준 (필수 준수)

> ⚠️ **evidence.file은 반드시 실제 파일 경로여야 한다 (디렉토리 금지).
> evidence.code_snippet은 반드시 Read 툴로 읽은 실제 파일 내용을 사용한다.**

- `evidence.file`: 실제 파일 경로 (`Config.java`, `application.yml` 등) — 디렉토리 경로 금지
- `evidence.code_snippet`: Read 툴로 직접 읽은 실제 코드만 허용 — 생성/추측 주석 금지
- 파일을 직접 읽지 못한 경우: `needs_review: true` + `manual_review_note: "코드 미확인"` 표시
- 자동스캔 `code_snippet`이 `"**** (마스킹)"` 상태인 경우, LLM 보완 finding 작성 시 반드시 Read 툴로 실제 파일을 읽어 evidence 첨부
