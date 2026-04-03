## Task: 2-5 데이터 보호 검토 (LLM 수동분석 보완)

**역할**: 당신은 보안 진단 전문가입니다.
**입력 파일**: `state/<prefix>/task25.json` (scan_data_protection.py 자동스캔 결과)
**출력 파일**: `state/<prefix>/task25_llm.json` (LLM 수동분석 보완 — supplemental)
**게시 방식**: 별도 Confluence 페이지 X → `<prefix>_task25.json` finding 페이지의 `supplemental_sources`로 통합

> ⚠️ **이 JSON은 자동스캔 페이지에 통합 렌더링된다.** 독립 보고서가 아님.
> `confluence_page_map.json`의 data_protection finding 항목에 `supplemental_sources` 배열로 추가할 것.

> 📋 **Finding 작성 기준**: `references/finding_writing_guide.md` 필수 준수
> - `evidence.code_snippet`: 취약 코드 직접 인용 필수 (없으면 finding 미완성)
> - `description`: 현황 → 보안 위협 → 현재 평가 3단 구어체 서술
> - `recommendation`: 번호 목록(`1. 2. 3.`) 2개 이상, 구체적 코드 수정 방법 포함

---

### ⚠️ 모듈 스코프 제한 시 필수 절차

> `scan_data_protection.py`는 `--modules` 옵션을 지원하지 않아 **항상 전체 repo를 스캔**한다.
> 진단 범위가 특정 서브모듈로 제한된 경우 아래 절차를 반드시 따른다.

#### Step 0: in-scope 필터링

`DIAGNOSIS_SCOPE` (예: `wv/pointcon`, `wv/shoppingtab`)가 정의된 경우:

1. `state/<prefix>/task25.json`의 모든 findings를 **파일 경로 기준**으로 분류
   - **in-scope**: `file` 경로에 `DIAGNOSIS_SCOPE` 모듈명 포함 → 이후 단계에서 분석
   - **out-of-scope**: 해당 없음 → `data_protection_assessment.out_of_scope` 섹션에 요약, 분석 생략

2. **오탐(FP) 처리**: in-scope finding이더라도 실제 코드 확인 결과 로깅 내용이 PII/시크릿이 아닌 경우 `false_positives` 섹션에 기록

3. **카테고리별 in-scope finding 0건인 경우** (예: 하드코딩 시크릿 0건, CORS 0건 등)
   - 별도 finding 생성 불필요 — `data_protection_assessment` 내 해당 항목에 `result: "해당없음"` 기록으로 충분

> PII 로깅(SENSITIVE_LOGGING)이 in-scope에서 완전히 0건인 경우에도 `data_protection_assessment.pii_logging` 블록에 명시적으로 `result: "해당없음"`, 확인 근거를 기록한다.

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

`state/<prefix>/task25.json`을 로드하여 다음을 확인합니다:
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

#### 6-0. 허용 목록 / 보호 필수 목록 (FP 판정 기준)

로그 진단 시 아래 목록을 기준으로 TP/FP를 분리한다.

**[허용 목록] — 단독 출력 시 FP, 탐지 결과에서 제외**

| 분류 | 변수/패턴 | 판정 근거 |
|---|---|---|
| 내부 추적 식별자 | `userId`, `feedId`, `feedSeq`, `asumUid` | 애플리케이션 내부 동작 추적용. 고객 식별에 직결되지 않음 |
| 비즈니스 상수/URL | `pushType`, `redirectUri` | 단순 상수값·URL 경로. 개인정보 미포함 |
| 일반 예외 메시지 | `e.message`, `exception.message` | 오류 타입·메시지 텍스트. 단, **토큰 원문·Secret Key가 결합 출력되는 경우는 TP** |

> 허용 목록 변수가 `mbrId`·`authToken` 등 보호 필수 변수와 **동일 로그 라인에 결합** 출력되는 경우 → 보호 필수 변수 기준으로 **TP 처리** (허용 목록 적용 불가).

**[보호 필수 목록] — 로그 레벨 무관, 반드시 TP + 마스킹 필수**

| 분류 | 변수/패턴 | 조치 방안 |
|---|---|---|
| 핵심 고객 식별자 | `mbrId`, `mbrno`, `mbr_id` | **절대 예외 불가** — MaskingUtils.mask() 필수 |
| 인증·세션 토큰 | `authToken`, `accessToken`, `refreshToken`, `httpSession.getId()` | 토큰 원문 마스킹 처리 필수 |
| 개인정보 포함 객체 전체 | `webTokenInfo`, `kmcResult`, `response` (회원 API 응답 전체) | 로그 제외 또는 필드별 마스킹 |
| 암호화 처리 전/후 데이터 | `encryptData`, `plainText` | 평문 결합 로깅 금지 |

**병합 규칙:**

| 버킷 | 조건 | finding 1건으로 통합 | 결과 | 심각도 |
|---|---|---|---|---|
| `high` | `info/warn/error/fatal` 레벨 보호 필수 변수 로깅 | 전체 파일 × 라인 집계 | **취약** | **Critical** |
| `low` | `debug/trace` 레벨 보호 필수 변수 로깅 | 전체 파일 × 라인 집계 | 정보 | **Medium** |

**evidence 기재 방법:**
```
"file": "대표 파일 외 N개 파일 (총 M건)",
"lines": "대표 라인 번호 (대표 샘플)",
"code_snippet": "대표 2~3건 샘플 코드 + (※ 컨설턴트 Note: FP 가능성 있는 항목 명시)"
```

**FP 컨설턴트 노트 기재 기준:**
- 허용 목록 변수(`userId`, `feedSeq` 등)가 단독으로 로깅되는 경우 → FP 처리
- 로그 메시지 문자열 리터럴(예: `"Invalid JWT :"`)에 PII 키워드 포함 + 실제 파라미터는 `e.message` 단독 → FP
- Kotlin 문자열 보간(`$hmacSignature`) — 변수명이 PII 패턴에 일치하나 실제로는 서명값인 경우 → FP
- FP 가능성이 있으면 `code_snippet` 하단에 아래 형식으로 반드시 기재:
  ```
  (※ 컨설턴트 Note: [파일명:라인]의 [코드 패턴]은 FP(오탐) — 보호 필수 변수 미포함.
  [다른 파일:라인]의 mbrId 직접 바인딩은 명백한 취약점(TP)입니다.)
  ```

**대응 방안 필수 포함 항목:**
1. [필수] `mbrId`, `authToken` 등 보호 필수 변수: `MaskingUtils.mask()` 적용 리팩토링 — **"해당 파라미터는 마스킹 처리 필수"** 명시
2. 근본 조치: Logback `MessageConverter` 커스텀 구현으로 전역 자동 마스킹 아키텍처 도입

---

### Step 7: DTO_EXPOSURE 분석 — 엔드포인트 역추적 + FP 방지

#### 7-0. 스크립트 역추적 결과 활용 (포지티브 분석)

`scan_data_protection.py`는 `--api-inventory` 옵션 사용 시 DTO 클래스를 실제로 반환하는 컨트롤러 엔드포인트를 자동 역추적하여 `affected_endpoints` 배열로 제공한다.

**LLM 분석 절차:**

1. `task25.json`의 `DTO_EXPOSURE` findings에서 `affected_endpoints` 배열 확인
2. `affected_endpoints`가 비어 있는 경우 (`endpoint_type: "INTERNAL"` 등): 내부 객체로 API 응답에 미포함 → **FP 처리**
3. `affected_endpoints`에 실제 API 경로가 있는 경우:
   - 해당 DTO 클래스를 직접 읽어 PII 필드 목록 확인
   - 해당 API의 **비즈니스 목적** 파악: 본인 정보 조회(Safe by Design) vs 관리자/목록 조회(취약 가능)
   - `@JsonIgnore`, `@JsonView`, `@JsonSerialize(using=MaskSerializer.class)` 적용 여부 확인
4. 분석 결과를 finding의 `affected_endpoints` 배열로 출력 (method, path, controller, description 구조화)

```
분석 흐름:
task25.json DTO finding
  └─ affected_endpoints 존재 여부
       ├─ 없음(INTERNAL/Consumer DTO) → FP → 7-1~7-4 FP 규칙 적용
       └─ 있음 → 해당 Controller 코드 확인
                   ├─ 본인 정보 반환 API → Safe by Design → 양호
                   ├─ PII 필드에 @JsonIgnore 적용 → 양호
                   └─ PII 필드 노출 + 타인 조회 가능 → 취약 (finding 확정)
```

> `affected_endpoints`가 없고(`[]`) `--api-inventory` 옵션을 사용하지 않은 경우:
> DTO 클래스명으로 Controller 코드를 직접 검색하여 응답 경로에 포함되는지 수동 확인

---

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

### Step 8: TLS 클라이언트 설정 / gRPC 채널 보안 / Redis 직렬화 (Semgrep 스캔 결과 기반)

> **파이프라인**: Phase 2에서 Semgrep SSC 피드백 룰이 사전 실행되어
> `state/<prefix>/ssc_feedback_semgrep.json`에 결과가 저장된다.
> LLM은 해당 JSON을 읽어 판정만 수행한다. grep 직접 실행 금지.

#### Step 8 입력 데이터 확인

```
1. state/<prefix>/ssc_feedback_semgrep.json 파일 존재 여부 확인
   - 존재: 아래 8-1~8-3 절차로 findings 판정
   - 미존재: workflow.md Phase 2 Semgrep 스캔 단계를 먼저 수행 요청
             (scan_data_protection.py 이후 Semgrep 추가 실행 필요)

2. JSON 구조 확인:
   results[].check_id     → 룰 ID (ssl-client-bypass, grpc-plaintext-channel, redis-template-*)
   results[].path         → 탐지 파일 경로
   results[].start.line   → 탐지 라인
   results[].extra.message → 룰 메시지
```

#### 8-1. SSL 인증서 검증 우회 (check_id: ssl-client-bypass)

**판정 기준**:

| 조건 | 판정 |
|------|------|
| `src/test/` 경로 내 탐지 | 양호(FP) — 테스트 전용 |
| `src/main/` + `NoopHostnameVerifier` | **취약** (severity 4) |
| `src/main/` + `loadTrustMaterial(null, ...)` | **취약** (severity 4) |
| `src/main/` + `verify=False` | **취약** (severity 3) |
| 외부 결제사/금융사 통신에 적용 시 | severity 5로 상향 |

**Finding 템플릿 (DATA-TLS-001)**:

```json
{
  "finding_id": "DATA-TLS-001",
  "category": "INSECURE_TLS_CLIENT",
  "title": "HTTP 클라이언트 SSL 인증서 검증 비활성화",
  "severity": 4,
  "result": "취약",
  "evidence": {
    "file": "<semgrep results[].path>",
    "line": "<semgrep results[].start.line>",
    "code_snippet": "<Read 툴로 해당 파일 ±5줄 확인 후 기재>"
  },
  "recommendation": "loadTrustMaterial 제거. 필요 시 해당 CA 인증서만 TrustStore에 등록. NoopHostnameVerifier → DefaultHostnameVerifier 교체.",
  "diagnosis_method": "Semgrep(ssl-client-bypass) + LLM검증"
}
```

#### 8-2. gRPC 채널 평문 전송 (check_id: grpc-plaintext-channel)

> ⚠️ **MSA/서비스 메시 환경 오탐 주의**: Kubernetes + Istio/Linkerd 환경에서
> `usePlaintext()`는 sidecar proxy가 mTLS를 담당하는 정상 구성일 수 있다.
> 인프라 아키텍처를 확인하기 전까지 "정보/검토필요"로만 분류한다.

**판정 기준**:

| 조건 | 판정 |
|------|------|
| `localhost` / `127.0.0.1` 전용 | 양호(FP) |
| 서비스 메시(Istio/Linkerd) 확인됨 | 양호(FP) — sidecar mTLS |
| 서비스 메시 불명확 / k8s manifest 미확인 | **정보** (severity 2, 검토필요) |
| 서비스 메시 없음 확인 + 외부 서비스 통신 | **취약** (severity 3) |

**Finding 템플릿 (DATA-TLS-002)**:

```json
{
  "finding_id": "DATA-TLS-002",
  "category": "INSECURE_TLS_CLIENT",
  "title": "gRPC 채널 평문 전송 — 서비스 메시 아키텍처 확인 필요",
  "severity": 2,
  "result": "정보",
  "evidence": {
    "file": "<semgrep results[].path>",
    "line": "<semgrep results[].start.line>",
    "code_snippet": "<Read 툴로 해당 파일 ±5줄 확인 후 기재>"
  },
  "recommendation": "인프라팀과 서비스 메시(Istio/Linkerd) 적용 여부 확인. 서비스 메시 없는 환경이면 useTransportSecurity() 적용 필요.",
  "manual_review_note": "MSA 인프라 아키텍처(k8s manifest, istio.io/inject 어노테이션) 확인 후 취약/양호 재판정 필요.",
  "diagnosis_method": "Semgrep(grpc-plaintext-channel) + LLM검증"
}
```

#### 8-3. Redis 직렬화 설정 누락 (check_id: redis-template-default-serializer)

**판정 기준**:

| 조건 | 판정 |
|------|------|
| `StringRedisTemplate` 탐지 | 양호(FP) — StringRedisSerializer 고정 |
| `RedisTemplate` + `setDefaultSerializer()` 없음 | **취약** (severity 4) |
| `RedisTemplate` + `setValueSerializer(new GenericJackson2JsonRedisSerializer())` 있음 | 양호 |
| `ReactiveRedisTemplate` + `RedisSerializationContext` 없음 | **취약** (severity 3) |

**Finding 템플릿 (DATA-DESER-001)**:

```json
{
  "finding_id": "DATA-DESER-001",
  "category": "UNSAFE_DESERIALIZATION",
  "title": "RedisTemplate 기본 JDK 직렬화 — 역직렬화 RCE 위험",
  "severity": 4,
  "result": "취약",
  "evidence": {
    "file": "<semgrep results[].path>",
    "line": "<semgrep results[].start.line>",
    "code_snippet": "<Read 툴로 @Bean 메서드 전체 확인 후 기재>"
  },
  "recommendation": "redisTemplate.setDefaultSerializer(new GenericJackson2JsonRedisSerializer()) 명시적 추가.",
  "diagnosis_method": "Semgrep(redis-template-default-serializer) + LLM검증"
}
```

> **참고**: Semgrep 룰 원본 — `references/rules/semgrep/ssl-client-bypass.yaml`,
> `grpc-plaintext-channel.yaml`, `redis-template-default-serializer.yaml`
> Phase 2 실행 명령은 `workflow.md` Phase 2 "Semgrep SSC 피드백 룰 실행" 참조.

---

### ⚠️ 완료 조건 자가 검증 (필수 — 미충족 시 Task 미완료)

출력 JSON 작성 전 반드시 아래 기준을 자가 검증하라:

```
□ SENSITIVE_LOGGING 병합 적용 여부 — 분할 기준은 모듈/파일이 아닌 로그 레벨
  - info/warn/error/fatal 레벨 PII 로깅 전체 → 1개 finding(DATA-LOG-001, Critical)으로 통합
  - debug/trace 레벨 PII 로깅 전체 → 1개 finding(DATA-LOG-002, Medium)으로 통합
  - 동일 PII 타입이 여러 모듈에 걸쳐 있어도 같은 레벨 버킷에 통합 (모듈별 분리 금지)
  ⚠️ 잘못된 패턴: DATA-LOG-001(shoppingtab mbrId), DATA-LOG-002(pointcon mbrId) → 모듈별 분리
  ✅ 올바른 패턴: DATA-LOG-001(info/error 레벨 mbrId, 전 모듈), DATA-LOG-002(debug 레벨 mbrId, 전 모듈)
  - DATA-LOG-001(info/error)과 DATA-LOG-002(debug)가 동시에 존재하는 것은 정상

□ HARDCODED_SECRET 병합 적용 여부
  - 동일 파일 내 여러 라인 → 1개 finding
  - 동일 환경의 동일 유형 파일(ccdev/*.properties 3파일) → 1개 finding

□ data_protection_assessment 블록 존재 여부
  - admin_page_separation, cors_wildcard, jwt_unsigned_allowed 필드 기재 필수

□ findings 배열이 비어 있지 않은 경우 각 finding에 evidence.file(실제 경로) 기재 필수

□ [Step 8] Semgrep SSC 피드백 스캔 결과 참조 여부
  □ state/<prefix>/ssc_feedback_semgrep.json 파일 확인 (Phase 2 사전 실행 필요)
  □ check_id 별 결과 확인: ssl-client-bypass / grpc-plaintext-channel / redis-template-*
  □ 탐지 건 → Read 툴로 해당 파일 직접 확인 후 판정 (Semgrep 탐지만으로 취약 단정 금지)
  □ gRPC usePlaintext: 반드시 "정보/검토필요"로 분류 (취약 단정 금지 — MSA 아키텍처 확인 필요)
  → 0건이면 "해당없음" 기록. Semgrep JSON 미존재 시 Phase 2 재실행 요청.
```

**병합 미적용 시 거부 조건:**
- 동일 PII 타입 + 동일 로그 레벨을 모듈별로 분리하여 별도 finding 생성 → **모듈별 분리 금지, 병합 미완료**
- `data_protection_assessment` 키가 없음 → **미완료**

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
  "consolidation_note": "자동스캔 N건을 파일/심각도 단위로 병합. 원본 개별 findings는 state/<prefix>/task25.json에 증적 보존.",
  "executed_at": "",
  "claude_session": ""
}
```

**ID 명명 규칙:**
- `DATA-SEC-NNN` — HARDCODED_SECRET 병합 그룹 (환경/파일 단위, 001부터 순차 부여)
- `DATA-LOG-001` — SENSITIVE_LOGGING Critical 병합 (info/warn/error/fatal 레벨, 전 모듈 통합)
- `DATA-LOG-002` — SENSITIVE_LOGGING Medium 병합 (debug/trace 레벨, 전 모듈 통합)
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
