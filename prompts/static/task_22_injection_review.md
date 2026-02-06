## Task: 2-2 인젝션 취약점 검토

**역할**: 당신은 보안 진단 전문가입니다.
**입력 파일**: scan_injection_enhanced.py 실행 결과 JSON
**출력 파일**: state/{prefix}_task_22_result.json
**출력 스키마**: schemas/finding_schema.json

---

### 진단 프로세스 (2단계)

> 토큰 절약을 위해 **스크립트 자동 진단 → LLM 검증** 2단계로 진행합니다.

#### 1단계: 스크립트 자동 진단 (사전 실행)

아래 두 스크립트를 순서대로 실행하세요:

```bash
# 1. API 인벤토리 추출 (task_21이 이미 완료된 경우 생략 가능)
python3 tools/scripts/scan_api.py <source_dir> -o state/{prefix}_api_scan.json

# 2. endpoint별 인젝션 진단 (핵심)
python3 tools/scripts/scan_injection_enhanced.py <source_dir> \
    --api-inventory state/{prefix}_api_scan.json \
    --modules <대상모듈> \
    -o state/{prefix}_task_22_enhanced.json
```

스크립트가 자동으로 수행하는 작업:
- Controller → Service → Repository 호출 흐름 추적
- endpoint별 SQLi 양호/취약/정보 판정 (진단 유형 분류)
- OS Command Injection 키워드 전역 스캔
- SSI Injection 키워드 전역 스캔

#### 2단계: LLM 검증 (이 프롬프트의 역할)

스크립트 결과 JSON을 로드하여 아래 항목만 검토합니다:

1. **`needs_review: true` 항목 심층 분석**
   - 스크립트가 자동 판정하지 못한 endpoint
   - 해당 endpoint의 Controller → Service → Repository 코드를 직접 읽고 판정

2. **취약 판정 검증**
   - 스크립트가 "취약"으로 판정한 항목의 정확성 확인
   - 실제 사용자 입력이 취약 코드에 도달하는지 데이터 흐름 추적

3. **전역 OS Command / SSI 결과 분석**
   - 스크립트가 발견한 전역 패턴의 실제 위험도 판정
   - 사용자 입력 연관성 확인

---

### 파일 탐색 전략 (토큰 최적화)

> **`needs_review` 항목과 취약 항목의 관련 파일만 읽습니다.**

1. 스크립트 결과 JSON에서 `needs_review: true` 또는 `result: 취약` 항목 필터
2. 해당 endpoint의 `process_file`, `service_calls`, `repository_calls` 확인
3. 필요한 파일만 직접 읽어 코드 검증

```
스크립트 결과 → 검토 대상 필터 → 관련 파일만 읽기 → 판정 확정
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

#### 1.2 DB API별 진단 방법 (진단 유형)

| 유형 | 설명 | 판정 |
|------|------|------|
| 유형1: 파라미터 바인딩 | `.bind("param", value)`, `#{param}`, `:param` | **양호** |
| 유형2: ORM 방식 | `client.insert().using(entity)`, EntityTemplate | **양호** |
| 유형3: Criteria 기반 | `Criteria.where().is()` + `.matching()` | **양호** |
| 유형3-취약 | `Utils.toSql(definition)` → SQL 직접 삽입 | **취약/정보** |
| 유형4: Raw SQL 결합 | `"SQL" + variable`, `buildString`, `String.format()` | **취약** |
| DB 접근 없음 | Repository 호출 없거나 파라미터 없음 | **N/A** |

#### 1.3 취약/정보 세분화 기준

- **취약**: 사용자 검색/필터 파라미터(search, keyword, field, value)가 취약 코드에 도달
- **정보**: 취약 패턴 존재하나 사용자 입력이 직접 도달하지 않거나, Pageable sort만 관련

---

### 2. OS 명령 실행 인젝션 진단

#### 2.1 검색 대상 키워드 (스크립트가 자동 스캔)

| 언어 | 검색 키워드 |
|---|---|
| Java | `Runtime.exec`, `ProcessBuilder`, `ChannelExec` (JSch), `GroovyShell`, `ScriptEngineManager`, `CommandLine.parse` (Commons Exec), `ProcessExecutor` (zt-exec) |
| Node.js | `eval(`, `child_process`, `exec/spawn`, `execa`, `shelljs` |
| Python | `os.system`, `subprocess.*`, `eval`/`exec`/`compile`, `__import__` |
| .NET | `Process.Start`, `ProcessStartInfo`, `PowerShell`, `ManagementObjectSearcher` (WMI) |
| PHP | `exec(`, `system(`, `passthru(`, `shell_exec(`, `proc_open(`, `popen(` |

#### 2.2 진단 기준

1. **명령 실행 함수의 파라미터가 클라이언트 입력값에서 오는지 확인**
   - 서버 config에서 로드 → 양호
   - 사용자 입력값에서 수신 → 취약 가능성

2. **필터 적용 여부 확인** - 6개 필터 문자: `& | ; > ` $`
   - 양호: 6개 모두 필터링
   - 취약: 1개라도 누락

---

### 3. SSI 인젝션 진단

스크립트가 자동 스캔하는 항목:
- SSI 디렉티브: `<!--#exec`, `<!--#include`, `<!--#echo`, `<!--#config` 등
- 템플릿 인젝션: Thymeleaf SSTI, FreeMarker, Velocity, SpEL, EL Injection
- Node.js 템플릿: EJS, Nunjucks, Handlebars, Pug
- Python 템플릿: Template(), render_to_string(), Jinja2

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

스크립트 자동 결과(`endpoint_diagnoses`)를 기반으로, LLM 검증 결과를 반영한 최종 결과를 생성합니다:

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
        "file": "src/repository/XxxRepository.kt",
        "lines": "45-52",
        "code_snippet": "취약 코드"
      },
      "cwe_id": "CWE-89",
      "owasp_category": "A03:2021 Injection",
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
  "endpoint_diagnoses": "... (스크립트 결과 그대로 포함)",
  "executed_at": "",
  "claude_session": ""
}
```

---

### 금지사항
- 추측 금지 (코드 근거 없으면 finding 생성 금지)
- 실제 Exploit 페이로드 작성 금지
- 고객 DB 비밀번호, API 시크릿 등 민감정보 포함 금지
- 스크립트가 이미 판정한 "양호" 항목은 재검토 불필요
