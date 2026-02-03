## Task: 2-2 인젝션 취약점 검토

**역할**: 당신은 보안 진단 전문가입니다.
**입력 파일**: state/task_21_result.json (API 인벤토리)
**출력 파일**: state/task_22_result.json
**출력 스키마**: schemas/finding_schema.json

---

### 컨텍스트
Task 2-1에서 추출한 API 인벤토리를 기반으로 **SQL Injection**, **OS Command Injection** 등 인젝션 계열 취약점을 정적 분석합니다.

---

### 파일 탐색 전략 (토큰 최적화)

> **전체 소스코드를 탐색하지 마세요.** 아래 순서로 필요한 파일만 추적합니다.

1. `state/task_21_result.json`에서 API 엔드포인트 목록을 로드
2. 각 API의 **Controller 파일** 위치를 확인
3. Controller에서 호출하는 **Service 클래스**를 추적
4. Service에서 호출하는 **Repository / Mapper / DAO** 파일을 추적
5. 전역 설정 파일 확인: `application.yml`, `application.properties`, `web.xml`

```
API 목록 → Controller → Service → Repository/Mapper/DAO
                                    └→ MyBatis XML, JPA @Query, R2DBC 등
```

---

### 1. SQL 인젝션 진단

#### 1.1 진단 대상 DB API 식별

아래 키워드로 프로젝트의 DB 접근 방식을 식별합니다:

| DB 접근 방식 | 검색 키워드 |
|---|---|
| JDBC 단독 | `NamedParameterJdbcTemplate`, `JdbcTemplate`, `PreparedStatement` |
| JDBC + JPA | `JpaRepository`, `@Query`, `EntityManager`, `createQuery`, `createNativeQuery` |
| MyBatis / iBatis | `@Mapper`, `SqlSession`, `mybatis`, `ibatis`, mapper XML 파일 (`${` 사용 여부) |
| R2DBC | `DatabaseClient`, `R2dbcEntityTemplate`, `Criteria`, `.execute(`, `.sql(` |
| Node.js | `Sequelize(`, `db.query`, `client.query`, `connect.query`, `queryQueue` |

#### 1.2 DB API별 진단 방법

**MyBatis XML Mapper:**
- `${...}` (문자열 직접 삽입) → **취약**
- `#{...}` (PreparedStatement 바인딩) → **양호**

**JPA @Query:**
- `@Query("SELECT ... WHERE x = " + param)` → **취약** (문자열 연결)
- `@Query("SELECT ... WHERE x = :param")` → **양호** (파라미터 바인딩)
- `createNativeQuery(sql)` + 문자열 연결 → **취약**

**R2DBC / Criteria:**
- `Criteria.where(...).toString()` 후 SQL에 직접 삽입 → **취약**
- `.bind("param", value)` 사용 → **양호**
- `R2dbcEntityTemplate` + Query DSL → **양호**

**JDBC:**
- `Statement.executeQuery(sql)` + 문자열 연결 → **취약**
- `PreparedStatement` + `setString()` → **양호**

**Node.js:**
- `db.query("SELECT ... " + input)` → **취약**
- `db.query("SELECT ... $1", [input])` → **양호** (Parameterized)

---

### 2. OS 명령 실행 인젝션 진단

#### 2.1 검색 대상 키워드

| 언어 | 검색 키워드 |
|---|---|
| Java | `Runtime.exec`, `ProcessBuilder`, `Runtime.getRuntime`, `getRuntime().exec`, `DefaultExecutor`, `Execute.Command` |
| Node.js | `eval(`, `setTimeout(` (문자열 인자), `setInterval(` (문자열 인자), `child_process`, `exec(`, `execSync(`, `spawn(` |
| PHP | `exec(`, `system(`, `passthru(`, `shell_exec(`, `proc_open(`, `popen(` |

#### 2.2 진단 기준

1. **명령 실행 함수의 파라미터가 클라이언트 입력값에서 오는지 확인**
   - 서버 config에서 로드 → 양호
   - 사용자 입력값(`@RequestParam`, `request.getParameter()` 등)에서 수신 → 취약 가능성

2. **필터 적용 여부 및 충분성 확인**
   - **양호 기준**: 아래 6개 문자 모두 필터링 중
     ```
     &  |  ;  >  `(backQuote)  $
     ```
   - **취약 기준**: 6개 문자 중 하나라도 필터에 포함되지 않을 시

3. **ProcessBuilder 특수 케이스**
   - `ProcessBuilder(listOf("명령어"))` 처럼 하드코딩된 단일 명령만 실행 → RCE 양호 (단, 불필요 코드 삭제 권고)
   - 사용자 입력값을 전체로 받아 실행 → **취약**

4. **Node.js CSP 확인**
   - `setTimeout`, `setInterval`에 function 객체 전달 → **양호**
   - 문자열 인자 전달 → **취약** (단, CSP 헤더로 실행 방지 설정 시 양호)

---

### 판정 기준

| 심각도 | 조건 |
|---|---|
| **Critical** | 인증 없이 접근 가능 + SQL/명령어 직접 삽입 (RCE 가능) |
| **High** | 인증 필요 + SQL/명령어 직접 삽입, 또는 `${}`를 통한 MyBatis 인젝션 |
| **Medium** | 간접적 삽입 가능성 (필터 부분 적용, 일부 문자 누락 등) |
| **Low** | 이론적 가능성만 존재 (하드코딩 명령어, 내부 파라미터만 사용) |
| **Info** | 보안 개선 권고 (불필요한 명령 실행 코드 존재 등) |

---

### 출력 형식

```json
{
  "task_id": "2-2",
  "status": "completed",
  "findings": [
    {
      "id": "INJ-001",
      "title": "취약점 제목",
      "severity": "High",
      "category": "Injection / SQL Injection",
      "description": "상세 설명",
      "affected_endpoint": "/api/xxx",
      "evidence": {
        "file": "src/repository/XxxMapper.xml",
        "lines": "45-52",
        "code_snippet": "취약 코드"
      },
      "cwe_id": "CWE-89",
      "owasp_category": "A03:2021 Injection",
      "recommendation": "조치 방안"
    }
  ],
  "executed_at": "",
  "claude_session": ""
}
```

---

### 금지사항
- 추측 금지 (코드 근거 없으면 finding 생성 금지)
- 실제 Exploit 페이로드 작성 금지
- 고객 DB 비밀번호, API 시크릿 등 민감정보 포함 금지
- API 인벤토리에 없는 파일을 임의로 탐색 금지
