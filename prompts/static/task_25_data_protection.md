## Task: 2-5 데이터 보호 검토

**역할**: 당신은 보안 진단 전문가입니다.
**입력 파일**: state/task_21_result.json (API 인벤토리)
**출력 파일**: state/task_25_result.json
**출력 스키마**: schemas/finding_schema.json

---

### 컨텍스트
Task 2-1에서 추출한 API 인벤토리를 기반으로 **CORS 설정**, **중요정보 노출**, **하드코딩된 민감정보**, **관리자 페이지 분리** 등 데이터 보호 관련 취약점을 정적 분석합니다.

---

### 파일 탐색 전략 (토큰 최적화)

> **전체 소스코드를 탐색하지 마세요.** 아래 순서로 필요한 파일만 추적합니다.

1. `state/task_21_result.json`에서 API 엔드포인트 목록을 로드
2. **전역 설정 파일** 우선 확인:
   - `WebConfig.java`, `SecurityConfig.java`, `CorsConfig.java` (CORS 설정)
   - `application.yml`, `application.properties` (서버 설정, TLS, 포트)
   - `web.xml` (서블릿 설정)
3. 각 API의 **Controller** → 어노테이션 확인 (`@CrossOrigin` 등)
4. **응답 객체/DTO** 확인 → 민감정보 포함 여부
5. 소스코드 내 **하드코딩된 시크릿** 검색 (전역)

```
전역 설정 (CORS, TLS, 관리자 분리)
  └→ Controller (@CrossOrigin, 응답 데이터)
       └→ Service → DTO/Response 객체 (민감정보 포함 여부)
```

---

### 1. CORS (Cross-Origin Resource Sharing) 설정 검토

#### 1.1 검색 키워드 (Spring 기준)

| 키워드 | 설명 |
|---|---|
| `CorsRegistry` | CORS 매핑 설정 클래스 |
| `addCorsMappings` | CORS 매핑 메서드 |
| `allowedOrigins` | Origin 허용 설정 |
| `@CrossOrigin` | 컨트롤러/메서드 레벨 CORS 설정 |
| `Access-Control-Allow-Origin` | 헤더 직접 설정 |
| `setHeader.*Access-Control` | 응답 헤더에 CORS 직접 설정 |

#### 1.2 판정 기준

| Origin 설정 | Credentials 설정 | 판정 |
|---|---|---|
| `*` (와일드카드) | `true` | **취약** |
| `*` (와일드카드) | 없음/false | **취약** |
| 특정 URL | `true` | **양호** (단, Origin 우회 확인 필요) |
| 특정 URL | 없음/false | **양호** (단, Origin 우회 확인 필요) |
| 미선언 | - | 단순 WEB → 양호, API 서버 → **취약** |

**Origin 우회 확인:**
- `request.getHeader("Origin")` 값을 그대로 응답에 반영하는 코드 → **취약**
- 정적 개체(HTML, JS, CSS)에 대한 CORS는 N/A 처리

**취약 코드 사례:**
```java
// 취약: 와일드카드 + credentials
registry.addMapping("/**")
    .allowedOrigins("*")
    .allowCredentials(true);

// 취약: 요청 Origin을 그대로 반영
String origin = request.getHeader("Origin");
response.setHeader("Access-Control-Allow-Origin", origin);
```

---

### 2. 중요정보 노출

#### 2.1 소스코드 내 하드코딩된 민감정보 검색

**검색 키워드:**

| 대상 | 키워드 |
|---|---|
| 비밀번호 | `password =`, `passwd =`, `pwd =`, `secret =` (문자열 리터럴 할당) |
| API 키 | `apiKey =`, `api_key =`, `API_KEY =`, `accessKey =` (문자열 리터럴 할당) |
| 토큰 | `token =`, `jwt =`, `bearer` (문자열 리터럴 할당) |
| DB 접속 | `jdbc:`, `mongodb://`, `redis://` (URL 내 credentials 포함 여부) |
| 주민등록번호 | `\d{6}-[1-4]\d{6}` 패턴 |
| 전화번호 | `010-\d{4}-\d{4}` 패턴 |

**판정:**
- 소스코드에 비밀번호, API 키 등이 문자열 리터럴로 하드코딩 → **취약**
- 환경변수(`System.getenv`), 설정 파일 참조(`@Value`) → **양호**

#### 2.2 응답 데이터 내 과다정보 노출

**확인 항목:**
- API 응답 DTO에 불필요한 민감 필드 포함 여부 (CI값, 주민번호, 전화번호 등)
- Response 객체에 apiKey, deviceKey, 기기 정보 등 불필요 정보 포함 여부
- 에러 응답에 스택 트레이스, DB 정보, 절대 경로 노출 여부

**판정:**
- 응답에 민감정보 평문 포함 → **취약**
- 에러 페이지에 서버 버전, 절대경로, SQL 에러 메시지 노출 → **취약**

---

### 3. 관리자 페이지 분리

**판정 기준:**
- 관리자 페이지가 별도 서버에서 서비스 (물리적 분리) → **양호**
- 동일 서버이나 별개 WAS/포트에서 서비스 (논리적 분리) → **양호**
- 동일 서버+WAS이나 IP 접근제어 적용 → **양호**
- 일반 사용자 페이지와 동일 서버/포트에서 접근 가능 → **취약**

**검색 키워드:** `admin`, `/admin`, `management`, `/manage`, `@PreAuthorize`, `hasRole('ADMIN')`

---

### 4. JWT 토큰 보안

**확인 항목:**
- JWT 서명 알고리즘: `none` 사용 여부 → **취약**
- JWT Secret Key 복잡도: 짧거나 추측 가능한 키 → **취약**
- JWT 만료 시간 설정 여부

**검색 키워드:** `Jwts.builder`, `JWT.create`, `jsonwebtoken`, `io.jsonwebtoken`, `jjwt`

---

### 판정 기준

| 심각도 | 조건 |
|---|---|
| **Critical** | 소스코드 내 DB 비밀번호/API 시크릿 하드코딩 + 외부 접근 가능 |
| **High** | CORS `allowedOrigins("*")` + `credentials(true)`, JWT `none` 알고리즘 |
| **Medium** | 응답에 불필요 민감정보 포함, 관리자 페이지 미분리, Origin 우회 가능 |
| **Low** | 에러 페이지 서버 버전 노출, 주석 내 테스트 계정 정보 |
| **Info** | 보안 개선 권고 (JWT 만료 시간 미설정, CORS 정책 강화 권고 등) |

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
      "category": "Data Protection / CORS Misconfiguration",
      "description": "상세 설명",
      "affected_endpoint": "/api/xxx 또는 전역",
      "evidence": {
        "file": "src/config/WebConfig.java",
        "lines": "20-30",
        "code_snippet": "취약 코드"
      },
      "cwe_id": "CWE-942",
      "owasp_category": "A05:2021 Security Misconfiguration",
      "recommendation": "조치 방안"
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
- 민감정보(실제 비밀번호, API 키 값) 포함 금지 → 마스킹 처리
- API 인벤토리에 없는 파일을 임의로 탐색 금지 (전역 설정 파일 제외)
