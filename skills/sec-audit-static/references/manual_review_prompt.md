# Manual Review Prompt — LLM 수동 심층진단

SAST 스크립트가 구조적 한계(DTO 래핑, 다단계 인터페이스 위임 등)로 인해 명확히 판정하지
못하고 **`정보(Info)`** 또는 **`수동검토 필요(needs_review: true)`**로 분류한 항목에 대해
LLM이 시니어 애플리케이션 보안 컨설턴트 역할로 심층 분석할 때 사용하는 프롬프트입니다.

## 적용 시점

- `result: "정보"` 이면서 `needs_review: true`인 항목
- `result: "취약"` 중 `diagnosis_method: "추정"` 이거나 `taint_confirmed: null`인 항목
- 자동 스캔이 `[잠재] 취약한 쿼리 구조`로 판정하여 수동 확인이 필요한 항목

## LLM 페르소나 선언 (프롬프트 시작부에 포함)

```
당신은 엔터프라이즈 환경의 취약점을 분석하는 '시니어 애플리케이션 보안 컨설턴트'입니다.
현재 우리 팀은 정적 분석 스크립트(SAST)를 통해 프로젝트의 SQL 인젝션 및 XSS 취약점을
1차 진단했습니다. 스크립트가 구조적 한계(DTO 래핑, 다단계 인터페이스 위임 등)로 인해
명확히 판정하지 못하고 '정보(Info)' 또는 '수동 검토 필요(Medium)'로 분류한 코드 스니펫과
API 흐름을 제공합니다.

아래의 [진단 기준]과 [답변 원칙]을 엄격하게 준수하여 제공된 코드를 심층 분석해 주십시오.
```

---

## 진단 기준

### 1. SQL Injection
*(KISA: DBMS 조회 및 결과 검증 취약점 / OWASP A03:2021-Injection)*

- **동적 쿼리 확인:** MyBatis의 `${}` 바인딩, JPA/QueryDSL 내부에서의 `+` 문자열 결합 등
  Prepared Statement를 우회하는 로직이 있는지 확인합니다.
- **입력값 제어 여부:** 해당 파라미터가 사용자가 직접 조작할 수 있는 자유 텍스트(`String`)인지,
  `Enum`, `Integer` 등 타입 캐스팅으로 인해 인젝션이 원천 차단되는 값인지 추적합니다.
- **방어 로직:** Controller 계층의 `@Valid`, 정규식 필터링, 화이트리스트 검증 등이
  안전하게 적용되었는지 판단합니다.

### 2. Cross-Site Scripting (XSS)
*(KISA: 크로스사이트 스크립팅 / OWASP A03:2021-Injection)*

- **Reflected XSS:** 컨트롤러 응답이 `application/json`이 아닌 `text/html` 등이며,
  사용자 입력값이 필터링 없이 화면에 그대로 반사(Reflect)되는지 확인합니다.
- **Persistent (Stored) XSS:** 사용자 입력(자유 텍스트)이 적절한 정제(Sanitization)나
  HTML 인코딩 없이 DB의 `SET` 또는 `INSERT` 컨텍스트에 저장되는지 확인합니다.
  > API가 JSON을 반환하더라도 DB에 필터 없이 저장된다면, 타 관리자 화면 등에서 실행될 수
  > 있으므로 **[취약-잠재적 위협]**으로 판정합니다.

---

## 답변 원칙 (절대 준수)

| # | 원칙 | 구체적 행동 |
|---|------|------------|
| 1 | **팩트 기반 검증** | OWASP, KISA 공식 문서를 근거로 진단 |
| 2 | **엄격한 불확실성 표기** | Taint 추적 불가 시 "알 수 없습니다" / "확실하지 않음" 명시 |
| 3 | **추측의 명시** | 논리적 추론이 불가피한 경우 "추측입니다"라고 밝힘 |
| 4 | **추가 정보 요구** | 코드가 모호하면 판정 강행 금지 — 필요한 클래스/메서드 명시 요청 |
| 5 | **출처 명시** | OWASP Top 10 항목 또는 KISA 기준 구체 항목을 판정 근거로 제시 |

---

## 입력 제공 형식

LLM에게 분석을 요청할 때 아래 항목을 포함해 제공합니다.

```
## 분석 대상 항목

- API 경로 + HTTP Method: [예: POST /api/v1/users/search]
- 스크립트 판정: [예: 정보 - 호출 경로 추적 불가 / 잠재 - 취약한 쿼리 구조]
- needs_review: true

### Controller 코드
(파라미터 선언, 어노테이션 포함)

### Service / UseCase 코드
(비즈니스 로직, 분기 처리)

### Repository / SQL
(MyBatis XML, QueryDSL, JPA 쿼리)

### DTO 구조 (있는 경우)
(필드 타입, @Valid 어노테이션 여부)
```

---

## 기대 출력 형식

LLM의 분석 결과를 아래 형식으로 수집하고 JSON에 반영합니다.

```
### 판정 결과: [취약 / 양호 / 정보 / 추가 정보 필요]

**판정 근거:**
- (팩트 기반 설명)

**불확실 사항:**
- (있는 경우 명시, 없으면 "없음")

**참고 기준:**
- OWASP A03:2021 / KISA DBMS 조회 및 결과 검증 취약점 / 기타
```

### JSON 결과 반영

```json
{
  "result": "취약",
  "diagnosis_type": "[실제] SQL Injection",
  "diagnosis_detail": "Controller에서 String 타입 파라미터가 DTO 래핑 없이 Repository의 MyBatis ${} 구문에 직접 전달됨. OWASP A03:2021 기준 취약.",
  "diagnosis_method": "수동진단(LLM)",
  "needs_review": false,
  "manual_review_note": "추가 정보 없이 판정 가능 / 또는 추측 포함 (이유)"
}
```

---

## 참고 공식 문서

- OWASP A03:2021 — Injection: https://owasp.org/Top10/A03_2021-Injection/
- OWASP SQL Injection Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- OWASP XSS Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
- KISA 시큐어코딩 가이드 (Java): https://www.kisa.or.kr/2060204/form?postSeq=13&lang_type=KO

---

## 외부 라이브러리(JAR) 진단 프롬프트

### 적용 대상

스캔 결과 JSON에서 아래 조건을 **모두** 만족하는 항목:

```json
{
  "result": "정보",
  "diagnosis_type": "외부 의존성 호출",
  "needs_review": true
}
```

해당 클래스가 프로젝트 소스가 아닌 외부 JAR/모듈에 위치하여 자동 추적 불가.
LLM이 클래스명·메서드명·파라미터 타입 기반으로 위험도를 추론합니다.

---

### LLM 판단 기준

| 판단 요소 | 추론 방법 | 예시 |
|----------|----------|------|
| **DB 접근 여부** | 클래스명/패키지명 접미사 | `XxxRepository`, `XxxMapper`, `XxxDao` → DB 접근 / `XxxClient`, `XxxUtil` → 비DB 추정 |
| **접근 유형** | 메서드명 접두사 규칙 | `find*/get*/select*` → 읽기 / `save*/insert*/update*/delete*` → 쓰기 |
| **인젝션 위험도** | 파라미터 타입 | `String` → 위험 / `Integer`, `Long`, `Enum`, `Boolean` → 안전 (타입 캐스팅으로 차단) |
| **라이브러리 특성** | 의존성 패턴 | Spring Data JPA 계열 → PreparedStatement 자동 바인딩 → 안전 추정 / MyBatis → XML 확인 필요 |

---

### 입력 제공 형식

LLM에게 분석을 요청할 때 아래 항목을 포함해 제공합니다.

```
## 외부 라이브러리 진단 대상

- API 경로 + HTTP Method: [예: GET /api/v1/users]
- 스크립트 판정: 정보 - 외부 의존성 호출 / needs_review: true
- 외부 클래스명: [예: com.external.lib.UserRepository]
- 호출 메서드명: [예: findByNameContaining]
- 파라미터 타입: [예: String name]
- 호출 컨텍스트:
  Controller → Service(UserService.searchUser) → 외부 클래스(UserRepository.findByNameContaining)
- (선택) pom.xml/build.gradle 의존성 항목:
  [예: implementation 'org.springframework.data:spring-data-jpa:3.x']
```

---

### 판정 분류

| 판정 | 조건 |
|------|------|
| **[DB 미접근]** | 클래스/메서드명이 DB와 무관 (HttpClient, EventPublisher 등) |
| **[안전 추정]** | Spring Data JPA/QueryDSL 계열이며 파라미터가 비자유텍스트 타입 |
| **[취약 가능성 있음]** | `String` 타입 파라미터가 Repository/Mapper/DAO로 전달 + 내부 구현 미확인 |
| **[추가 정보 필요]** | 클래스 출처 불명확 또는 메서드명만으로 판단 불가 |

> **원칙**: 내부 구현 코드 없이 추론하는 경우 반드시 "추측" 표기.
> 불확실성이 높으면 "[추가 정보 필요]"로 판정하고 확인 필요 항목을 명시.

---

### 기대 출력 형식

```
### 판정 결과: [DB 미접근 / 안전 추정 / 취약 가능성 있음 / 추가 정보 필요]

**판정 근거:**
- (클래스명/메서드명/파라미터 타입 기반 추론)
- (라이브러리 특성 기반 추론)

**불확실 사항:**
- (내부 구현 미확인 사항 명시, 없으면 "없음")

**추가 확인 필요 항목 (있는 경우):**
- (JAR 디컴파일 또는 소스 확인이 필요한 클래스/메서드)
```

### JSON 결과 반영

```json
{
  "result": "정보",
  "diagnosis_type": "외부 의존성 호출",
  "diagnosis_detail": "Spring Data JPA findByNameContaining — String 타입 파라미터이나 JPA 자동 PreparedStatement 바인딩으로 안전 추정. 단, 커스텀 @Query 존재 시 재검토 필요.",
  "diagnosis_method": "수동진단(LLM)",
  "needs_review": false,
  "manual_review_note": "추측 포함 — JAR 내부 구현 미확인. Spring Data JPA 패턴 기반 추론."
}
```

---

## Task 2-5: 데이터 보호 AI 수동 진단 프롬프트

### 적용 대상

`scan_data_protection.py` 가 `result: "정보"` 또는 `needs_review: true`로 분류한 항목.
자동 스캐너가 패턴은 탐지했으나 **컨텍스트 판단**이 필요한 3가지 핵심 케이스에 대해
AI가 시니어 보안 컨설턴트로서 최종 판정합니다.

---

### LLM 페르소나 선언

```
당신은 엔터프라이즈 환경의 데이터 보호 취약점을 분석하는 '시니어 보안 컨설턴트'입니다.
OWASP Top 10(A02/A04/A09), KISA 개인정보 기술적·관리적 보호조치, PIPA(개인정보보호법)
기준에 따라 아래 코드 스니펫을 분석하고 최종 판정을 내려주십시오.

[절대 원칙]
1. 코드 근거 없이 추측으로 판정 금지 — 근거 미확인 시 "추가 정보 필요" 표기
2. 실제 키/비밀번호 값은 응답에 포함 금지 — "****" 마스킹 처리
3. 불확실한 경우 판정 강행 대신 확인 필요 항목을 명시하여 요청
```

---

### [케이스 A] 하드코딩 시크릿 — Prod 키 vs. 테스트 더미 판별

**스캐너 판정**: `HARDCODED_SECRET / needs_review: true`
**판별 목적**: 탐지된 시크릿 값이 **실제 운영 환경 자격증명**인지, **테스트/더미 데이터**인지 구분.

#### 판단 기준

| 증거 | 판정 방향 |
|------|----------|
| 파일 경로에 `test/`, `spec/`, `mock/`, `fixture/` 포함 | 테스트 더미 → **정보** |
| 변수명에 `test`, `dummy`, `fake`, `sample`, `example`, `stub` 포함 | 테스트 더미 → **정보** |
| 값이 `password`, `secret`, `changeme`, `test123`, `example` 등 명백한 플레이스홀더 | 더미 → **정보** |
| `@SpringBootTest`, `@Test`, `@Mock` 어노테이션이 같은 클래스에 존재 | 테스트 코드 → **정보** |
| AWS AKIA 키가 `AKIAIOSFODNN7EXAMPLE` 형태 | AWS 공식 예시 키 → **양호** |
| 값이 `${...}`, `#{...}`, `ENC(...)`, `@Value(...)` 등 참조 패턴 | 환경변수 참조 → **양호** |
| Git history에서 해당 값이 변경 없이 오래 유지된 경우 | Prod 키 의심 → **취약** |
| 값이 32자 이상 랜덤 문자열이고 production 경로의 Config 클래스에 존재 | Prod 키 의심 → **취약** |

#### 입력 제공 형식

```
## 하드코딩 시크릿 판별 대상

- 스캐너 판정: HARDCODED_SECRET / needs_review: true
- 파일 경로: [예: src/main/java/config/JwtConfig.java]
- 라인: [예: 15]
- 탐지 패턴: [예: jwt.secret = "abcd1234..."]
- 값 길이: [예: 48자]

### 코드 컨텍스트 (전후 10줄)
```java
// 스캔 결과 코드 붙여넣기 (실제 시크릿 값은 마스킹 후 제공)
@Value("${jwt.secret:hardcoded-fallback-key-here}")
private String jwtSecret;
```

### 추가 컨텍스트 (있는 경우)
- 클래스 어노테이션: [@Configuration / @SpringBootTest 등]
- 해당 파일의 사용 위치: [JwtTokenProvider, AuthService 등]
- application.yml의 jwt.secret 설정 여부: [있음/없음/확인 불가]
```

#### AI 판단 지침

```
아래 순서로 판단하십시오:

1. 파일 경로와 클래스 어노테이션으로 테스트 코드 여부를 먼저 확인.
2. 값 자체가 명백한 플레이스홀더인지 확인 (changeme, test123, example 등).
3. @Value fallback 패턴(@Value("${key:fallback}"))인 경우:
   - application.yml에 해당 키가 정의되어 있으면 → 양호 (fallback은 미사용)
   - application.yml에 해당 키가 없으면 → fallback 값이 실제 사용됨 → 취약
4. 값이 충분히 길고(32자 이상) 랜덤해 보이며 운영 Config 파일에 있으면 → 취약 의심.
5. 판단 불가 시 "추가 정보 필요" — application.yml 내용 또는 배포 환경 확인 요청.
```

#### 기대 출력 형식

```
### 판정: [취약 / 정보 / 양호 / 추가 정보 필요]

**판정 근거:**
- (파일 경로 / 어노테이션 / 값 특성 기반 분석)

**Prod 키 여부:**
- [확정 / 더미로 판단 / 불명확]

**불확실 사항:**
- [있으면 명시, 없으면 "없음"]

**조치 권고 (취약 판정 시):**
- [즉시 키 로테이션 / Vault 이관 / 환경변수 처리 등]
```

---

### [케이스 B] 민감정보 로깅 — 마스킹 유틸 적용 여부 검증

**스캐너 판정**: `SENSITIVE_LOGGING / needs_review: true`
**판별 목적**: 로그 구문에 PII 변수가 포함되나, 마스킹 유틸리티가 실제로 적용되었는지 확인.

#### 판단 기준

| 패턴 | 판정 |
|------|------|
| `log.info("val={}", MaskingUtils.mask(ssn))` — 마스킹 함수가 PII 변수를 직접 래핑 | **양호** |
| `log.info("val={}", ssn.substring(0,3) + "****")` — 인라인 마스킹 | **양호** |
| `log.info("val={}", member.getSsn())` — getter 직접 전달, 반환값 미확인 | **정보** (getter 내부 마스킹 여부 확인 필요) |
| `log.info("ci=" + ci)` — 마스킹 없이 직접 연결 | **취약** |
| `log.debug("member: {}", member.toString())` — toString() 내 PII 포함 가능 | **정보** (toString 내용 확인 필요) |
| `@ToString(exclude = {"ssn", "password"})` — Lombok exclude 설정 | **양호** |

#### 입력 제공 형식

```
## 민감정보 로깅 판별 대상

- 스캐너 판정: SENSITIVE_LOGGING / needs_review: true
- 파일/라인: [예: UserService.java:145]
- 탐지 코드: [예: log.info("member login: {}", member.getCi())]

### 관련 코드 (로그 구문 전후 + 마스킹 유틸 정의)
```java
// 로그 구문
log.info("login success: ci={}", MaskingUtil.maskCi(member.getCi()));

// MaskingUtil 클래스 (있는 경우 제공)
public static String maskCi(String ci) {
    // 마스킹 로직
}
```

### 추가 컨텍스트
- MaskingUtil / MaskingUtils 클래스 존재 여부: [있음/없음]
- toString() 오버라이드 또는 Lombok @ToString 설정: [있음/없음/미확인]
```

#### AI 판단 지침

```
아래 순서로 판단하십시오:

1. 마스킹 함수가 PII 변수를 직접 래핑하는지 확인.
   - MaskingUtils.mask(pii) ← PII가 인수 → 양호
   - log.info("{}", pii) 이후 다른 줄에서 mask 호출 → 순서 문제, 이미 로깅됨 → 취약

2. getter 메서드가 마스킹된 값을 반환하는지 확인.
   - getSsn()이 마스킹 처리 후 반환 → 양호
   - getSsn()이 원본 반환 → 취약

3. toString() 또는 Lombok의 @ToString 설정 확인.
   - @ToString(exclude = {"ssn", "ci"}) → 해당 필드 제외 → 양호
   - @Data 또는 @ToString 기본값 → 모든 필드 포함 → 취약

4. 마스킹 함수 내부 로직 확인:
   - 안전: 앞 뒤 일부만 노출 (010-****-1234), 고정 길이 마스킹
   - 위험: 단순 replace("-", "")처럼 구분자만 제거 → 원본 노출
```

---

### [케이스 C] 커스텀 암호화 유틸 — 내부 알고리즘 안전성 검증

**스캐너 판정**: `WEAK_CRYPTO / needs_review: true` 또는 커스텀 유틸 래핑 의심
**판별 목적**: 자체 구현 암호화 유틸이 내부적으로 안전한 알고리즘을 사용하는지 확인.

#### 판단 기준

| 내부 구현 | 판정 |
|----------|------|
| `AES/GCM/NoPadding` + 96비트 IV + 128비트 태그 | **양호** (AEAD 모드) |
| `AES/CBC/PKCS5Padding` + 랜덤 IV + HMAC 무결성 검증 | **양호** |
| `AES/CBC/PKCS5Padding` + 고정 IV (0x00...) | **취약** (IV 재사용 → 패턴 노출) |
| `AES/ECB/PKCS5Padding` | **취약** (ECB 모드 → 패턴 노출) |
| 내부적으로 MD5/SHA-1 사용 | **취약** |
| `SecureRandom`으로 IV/Salt 생성 | **양호** |
| `new Random()`으로 IV 생성 | **취약** (예측 가능) |
| PBKDF2/bcrypt/Argon2로 키 파생 | **양호** (패스워드 기반 암호화) |
| `key = password.getBytes()` 직접 사용 | **취약** (키 파생 미적용) |

#### 입력 제공 형식

```
## 커스텀 암호화 유틸 판별 대상

- 스캐너 판정: [WEAK_CRYPTO 또는 커스텀 유틸 래핑 의심]
- 유틸 클래스: [예: CryptoUtils.java, AesEncryptor.java]

### 암호화 유틸 구현 코드 전체
```java
public class CryptoUtils {
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH = 128;

    public static String encrypt(String data, String key) {
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH, iv);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        // ...
    }
}
```

### 호출 컨텍스트
- 어디서 어떤 데이터에 적용: [예: 주민번호 암호화, 카드번호 저장 등]
- 키 관리 방식: [하드코딩 / @Value 참조 / KMS 연동 등]
```

#### AI 판단 지침

```
아래 체크리스트를 순서대로 확인하십시오:

[알고리즘 확인]
1. Cipher.getInstance() 또는 ALGORITHM 상수에서 알고리즘/모드/패딩 확인.
   - AES/GCM → 안전 (AEAD, 무결성 자동 보장)
   - AES/CBC → IV 관리 방식 추가 확인 필요
   - AES/ECB → 즉시 취약
   - DES/3DES/RC4 → 즉시 취약

[IV/Nonce 관리 확인]
2. IV 생성에 SecureRandom 사용 여부.
   - new SecureRandom().nextBytes(iv) → 안전
   - new byte[16] (고정 IV) → 취약
   - new Random() → 취약 (예측 가능)
3. AES/GCM의 경우 IV 재사용 방지 로직 확인.
   - 동일 키 + IV 조합 재사용 → 키스트림 노출 위험

[키 파생 확인]
4. 패스워드 기반 암호화인 경우 키 파생 함수(KDF) 사용 여부.
   - PBKDF2WithHmacSHA256, bcrypt, Argon2 → 안전
   - password.getBytes() 직접 사용 → 취약

[무결성 확인]
5. AES/CBC 사용 시 HMAC 등 메시지 무결성 검증 여부.
   - GCM은 인증 태그로 자동 보장
   - CBC는 별도 HMAC-SHA256 필요

판단 불가 시: 구현체 코드 전체 또는 알고리즘 상수 값 요청.
```

---

### JSON 결과 반영 형식

```json
{
  "finding_id": "DATA-SEC-001",
  "result": "정보",
  "severity": "Medium",
  "diagnosis_detail": "JWT secret key가 @Value fallback으로 하드코딩되었으나 application.yml에 jwt.secret이 정의되어 있어 운영환경에서는 fallback 미사용. 테스트 환경에서만 노출 위험.",
  "diagnosis_method": "수동진단(LLM)",
  "needs_review": false,
  "manual_review_note": "application.yml jwt.secret 정의 확인 — 운영 배포 환경 변수 주입 여부 재확인 권장."
}
```

---

## View XSS (JSP/Thymeleaf) AI 수동 진단 프롬프트

### 적용 대상

정적 분석 스크립트가 `HTML_VIEW` 컨트롤러로 분류하여 `view_xss: "정보"` 또는
`needs_review: true`로 남긴 항목.
스크립트는 View 파일의 **출력 컨텍스트**별 이스케이프 여부를 정밀 추적할 수 없으므로
AI가 Controller-View 전체 흐름을 직접 점검합니다.

---

### LLM 페르소나 선언 (프롬프트 시작부에 포함)

```
당신은 엔터프라이즈 환경의 취약점을 분석하는 '시니어 애플리케이션 보안 컨설턴트'입니다.
OWASP XSS Prevention Cheat Sheet와 KISA 주요정보통신기반시설 취약점 분석·평가 기준에 따라
아래 제공된 Controller 코드와 View 파일(JSP 또는 Thymeleaf)을 분석하여
크로스사이트 스크립팅(XSS) 취약 여부를 판정하십시오.

아래의 [진단 기준]과 [답변 원칙]을 반드시 준수하십시오.
```

---

### 진단 기준 — View XSS 출력 컨텍스트별 안전/위험 패턴

#### JSP

| 출력 컨텍스트 | 위험 패턴 (취약) | 안전 패턴 (양호) |
|-------------|----------------|----------------|
| **HTML Body** | `${modelAttr}` (naked EL), `<%= request.getParameter("x") %>` | `<c:out value="${modelAttr}"/>`, `${fn:escapeXml(modelAttr)}` |
| **HTML Attribute** | `<input value="${modelAttr}">`, `<a href="${url}">` | `<c:out value="${modelAttr}" escapeXml="true"/>` attribute 내 사용 |
| **JavaScript 블록** | `var x = '${modelAttr}';`, `var x = "<%= param %>";` | `var x = '${fn:escapeXml(modelAttr)}';` 또는 별도 JSON API 활용 |
| **URL/href** | `<a href="${modelAttr}">`, `<form action="${url}">` | `<c:url>` 태그 또는 ESAPI `encodeForURL()` 적용 |
| **`<c:out>` 오용** | `<c:out value="${v}" escapeXml="false"/>` | `<c:out value="${v}"/>` (escapeXml 기본값 true) |

#### Thymeleaf

| 출력 컨텍스트 | 위험 패턴 (취약) | 안전 패턴 (양호) |
|-------------|----------------|----------------|
| **HTML Body** | `th:utext="${modelAttr}"` (HTML escape 없음) | `th:text="${modelAttr}"` (자동 HTML escape) |
| **HTML Attribute** | `th:attr="value=${modelAttr}"` + utext 혼용 | `th:value="${modelAttr}"` (자동 escape) |
| **JavaScript 인라인** | `<script> var x = [[${modelAttr}]]; </script>` (unescaped) | `<script> var x = /*[[${modelAttr}]]*/ null; </script>` (inlined escaped) 또는 `th:inline="javascript"` |
| **URL/href** | `th:href="${url}"` (외부 입력 URL 직접 바인딩) | `th:href="@{${url}}"` (Thymeleaf URL 표현식, 검증 포함) |
| **Fragment 삽입** | `th:utext="${htmlContent}"` (관리자 입력 HTML 직접 렌더링) | DOMPurify 클라이언트 sanitize 병행 또는 th:text 전환 |

---

### 입력 제공 형식

AI에게 분석을 요청할 때 아래 항목을 **모두** 포함해 제공합니다.

```
## View XSS 진단 대상

- API 경로 + HTTP Method: [예: GET /main/wallet/clause]
- 스크립트 판정: [예: 정보 - HTML_VIEW 컨트롤러 / needs_review: true]
- View 엔진: [JSP / Thymeleaf / 혼합]

---

### 1. Controller 코드
(model.addAttribute() 호출 포함, 전체 메서드 본문 제공)

```java
@GetMapping("/main/wallet/clause")
public String clauseView(Model model, @RequestParam String clauseType) {
    ClauseDto clause = clauseService.getClause(clauseType);
    model.addAttribute("clauseContent", clause.getContent());
    model.addAttribute("clauseTitle",   clause.getTitle());
    return "main/wallet/clause";
}
```

---

### 2. View 파일 (JSP 또는 Thymeleaf)
(해당 View 파일 전체 또는 modelAttr 출력 부분)

(파일명: src/main/webapp/WEB-INF/views/main/wallet/clause.jsp)
```jsp
<h2>${clauseTitle}</h2>
<div class="content">
    ${clauseContent}
</div>
```

---

### 3. 전역 XSS 필터 정보 (스크립트 Phase 3 결과)
[예: has_lucy: false / has_antisamy: false / filter_level: none]

---

### 4. Model 데이터 출처
[예: clauseContent = DB에서 로드한 관리자 입력 HTML, clauseType = 사용자 파라미터]
```

---

### AI 점검 지시 (프롬프트 본문에 포함)

```
위 Controller 코드와 View 파일을 기반으로 다음 항목을 순서대로 점검하십시오.

[점검 항목 1] Model Attribute 출처 추적
- Controller에서 model.addAttribute()로 View에 전달된 각 변수명과 값의 출처를 파악하십시오.
- 해당 값이 (a) 사용자 직접 입력(Request Param/Body), (b) DB 저장값(관리자 포함),
  (c) 시스템 내부 상수 중 어디에 해당하는지 분류하십시오.
- (a) 또는 (b)에 해당하는 값만 XSS 분석 대상으로 간주합니다.

[점검 항목 2] View 출력 컨텍스트별 이스케이프 적용 여부
아래 4가지 컨텍스트 각각에 대해 위험 패턴 존재 여부를 확인하십시오.

  (2-1) HTML Body 컨텍스트
    - JSP: ${var} 또는 <%= ... %> 로 직접 출력하는지 확인
      → <c:out value="${var}"/> 또는 ${fn:escapeXml(var)} 로 대체되었으면 양호
    - Thymeleaf: th:utext 사용 여부 확인
      → th:text 사용 시 양호, th:utext 사용 시 취약

  (2-2) HTML Attribute 컨텍스트
    - <input value="${var}">, <a href="${var}"> 등 속성값에 naked EL 직접 삽입 여부
    - Thymeleaf th:value, th:href 등 표준 속성 바인딩은 자동 escape 적용 → 양호

  (2-3) JavaScript 인라인 컨텍스트
    - <script> 블록 내 var x = '${var}'; 또는 var x = '<%= param %>'; 패턴
    - 특히 작은따옴표/큰따옴표 탈출이 없으면 즉시 취약으로 판정
    - fn:escapeXml()은 JS 컨텍스트 이스케이프에 불충분함을 주의할 것
      (OWASP 권고: JavaScript 컨텍스트에는 \uXXXX 유니코드 이스케이프 필요)

  (2-4) URL/href 컨텍스트
    - <a href="${url}"> 또는 th:href="${url}" 에서 외부 입력값 직접 사용 여부
    - javascript: 프로토콜 삽입 가능 여부 확인

[점검 항목 3] 전역 XSS 필터 보완 여부
- 전역 필터(Lucy/AntiSamy 등)가 없는 경우(filter_level: none), View 출력 이스케이프가
  유일한 방어선임을 명시하고, naked EL 출력 패턴이 하나라도 있으면 취약으로 판정하십시오.
- 커스텀 필터(custom_wrapper)가 있는 경우, 필터가 HTML Body/Attribute/JS 컨텍스트
  각각에 대해 올바른 인코딩을 적용하는지 별도로 판단하십시오.

[점검 항목 4] Stored XSS 렌더링 경로 확인
- DB에서 로드한 값이 View에 출력될 경우, 해당 값을 저장하는 API(POST/PUT)에
  전역 필터가 적용되었는지 연계 확인하십시오.
- 저장 시 필터 없음 + 출력 시 이스케이프 없음 = Stored XSS 실제위협으로 판정.
- 저장 시 필터 없음 + 출력 시 이스케이프 있음 = 출력 방어만으로 불완전 — 정보로 분류.

출력 이스케이프 적용 여부가 불분명하면 판정을 강행하지 말고,
확인이 필요한 코드 위치나 추가 제공 파일을 명시하여 요청하십시오.
```

---

### 기대 출력 형식

```
### 판정 결과: [취약 / 양호 / 정보 / 추가 정보 필요]

**[점검 항목 1] Model Attribute 출처**
| 변수명 | 출처 | XSS 분석 대상 여부 |
|--------|------|------------------|
| clauseContent | DB (관리자 입력 HTML) | 예 |
| clauseTitle   | DB (관리자 입력 텍스트) | 예 |

**[점검 항목 2] 컨텍스트별 이스케이프 분석**
| 컨텍스트 | 패턴 | 판정 |
|---------|------|------|
| HTML Body | `${clauseContent}` naked EL | **취약** — c:out 또는 fn:escapeXml 미적용 |
| HTML Body | `${clauseTitle}` naked EL | **취약** — 동일 |
| HTML Attribute | 해당 없음 | 양호 |
| JavaScript 인라인 | 해당 없음 | 양호 |
| URL/href | 해당 없음 | 양호 |

**[점검 항목 3] 전역 필터 보완**
전역 XSS 필터 미설정(filter_level: none). View 출력 이스케이프가 유일한 방어선이나
naked EL 패턴 2건 확인 — View 단 방어 부재로 즉시 취약.

**[점검 항목 4] Stored XSS 렌더링 경로**
clauseContent는 DB 저장값(관리자 입력 HTML). 저장 시 전역 필터 없음 +
출력 시 이스케이프 없음 = **Stored XSS 실제위협**.

**최종 판정:** 취약 — Stored XSS 실제위협 (High)

**조치 권고:**
1. `${clauseContent}` → `<c:out value="${clauseContent}"/>` 또는
   HTML 렌더링이 필요한 경우 DOMPurify 클라이언트 새니타이즈 적용
2. 전역 Lucy XSS Filter 또는 AntiSamy 도입 (근본 방어)

**불확실 사항:** 없음

**참고 기준:**
- OWASP XSS Prevention Cheat Sheet — Rule #1: HTML Context Output Encoding
- KISA 주요정보통신기반시설 취약점 분석·평가 기준 — 크로스사이트 스크립팅
```

### JSON 결과 반영

```json
{
  "result": "취약",
  "view_xss": "취약",
  "xss_category": "실제위협",
  "severity": "High",
  "diagnosis_type": "[View XSS] Stored XSS 실제위협",
  "diagnosis_detail": "JSP ${clauseContent}, ${clauseTitle} naked EL 직접 출력. 전역 XSS 필터 없음 + View 이스케이프 없음 + DB 저장값(관리자 HTML) = Stored XSS 실제위협. OWASP XSS Prevention Rule #1 위반.",
  "diagnosis_method": "수동진단(LLM)",
  "needs_review": false,
  "manual_review_note": "View 파일 코드 직접 확인 — 추측 없음"
}
```

---

### 판정 분류 기준

| 판정 | 조건 |
|------|------|
| **취약 — 실제위협** | naked EL(`${}`) 또는 `th:utext` + 전역 필터 없음 + 사용자/DB 입력값 출력 |
| **취약 — JS 컨텍스트** | `<script>` 내 `${var}` 또는 `'<%= param %>'` 직접 삽입 |
| **정보 — 수동확인필요** | `<c:out>` 일부 적용이나 JS 컨텍스트 미확인, 또는 커스텀 필터 안전성 불명확 |
| **양호** | 모든 출력 컨텍스트에서 `<c:out>`, `fn:escapeXml()`, `th:text` 등 명시적 이스케이프 확인 |
| **추가 정보 필요** | View 파일 미제공 또는 출력 경로 추적 불가 |

> **원칙**: JS 컨텍스트 이스케이프에는 `fn:escapeXml()`이 불충분함을 항상 명시.
> HTML Entity 인코딩과 JavaScript Unicode 이스케이프는 다른 컨텍스트임.
> 불확실한 경우 "추가 정보 필요"로 판정하고 확인 대상 파일/코드를 명시.
