## Task: 2-2 인젝션 취약점 검토 (LLM 수동분석 보완)

**역할**: 당신은 보안 진단 전문가입니다.
**입력 파일**: `state/<prefix>_injection.json` (scan_injection_enhanced.py 자동스캔 결과)
**출력 파일**: `state/<prefix>_task22_llm.json` (LLM 수동분석 보완 — supplemental)
**게시 방식**: 별도 Confluence 페이지 X → `<prefix>_injection.json` finding 페이지의 `supplemental_sources`로 통합

> ⚠️ **이 JSON은 자동스캔 페이지에 통합 렌더링된다.** 독립 보고서가 아님.
> `confluence_page_map.json`의 injection finding 항목에 `supplemental_sources` 배열로 추가할 것.

> 📋 **Finding 작성 기준**: `references/finding_writing_guide.md` 필수 준수
> - `evidence.code_snippet`: 취약 코드 직접 인용 필수 (없으면 finding 미완성)
> - `description`: 현황 → 보안 위협 → 현재 평가 3단 구어체 서술
> - `recommendation`: 번호 목록(`1. 2. 3.`) 2개 이상, 구체적 코드 수정 방법 포함

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

스크립트 결과 JSON을 로드하여 아래 항목을 검토합니다:

---

##### 1-A. [필수] Taint 추적 실패 endpoint 전수 재확인 — "호출 관계 못 따라간 API 없도록"

> **이 단계는 `result: 정보` 중에서 스캐너가 DB 호출 관계를 따라가지 못해 판정한 항목만 대상으로 한다.**
> 스캐너가 안전하다고 확인한 것이 아니라, **확인 자체를 포기한 항목**이므로 반드시 LLM이 직접 재확인해야 한다.

**Taint 추적 실패 판단 기준** — 아래 `diagnosis_type` 값 중 하나에 해당하면 Taint 추적 실패:

| diagnosis_type 값 | 의미 |
|---|---|
| `"자동 판정 불가"` | 스캐너가 DB 접근 패턴 자체를 분석하지 못한 경우 |
| `"DB 접근 미확인"` | Controller→Service 추적은 됐으나 Repository/SQL까지 연결 못한 경우 |
| `"추적 불가"` | 외부 모듈·인터페이스 등으로 call chain이 끊긴 경우 |
| `access_type: "mybatis_dynamic_review"` | 4단계 매트릭스 Step 2/3 수동 확인 대기 상태 |

---

##### 1-A-1. 스캐너 추적 실패 유형별 근본 원인 분석

> **추적 실패 원인을 먼저 파악해야 LLM이 올바른 탐색 전략을 선택할 수 있다.**
> 아래 표를 참조하여 각 그룹의 `root_cause`를 `group_judgments`에 기록한다.

| diagnosis_type | 주요 발생 원인 | LLM 탐색 전략 |
|---|---|---|
| `자동 판정 불가` | ① Kotlin 파일 내 SQL Builder 함수를 스캐너가 심볼 추적 실패 (Kotlin lambda/inline 함수 경계), ② Generic DAO 패턴 (`BaseRepository<T>`), ③ 런타임 위임(함수 참조·람다), ④ 동적 프록시 | Kotlin DAO 파일 직접 grep: `buildQuery`, `createQuery`, SQL 상수 변수 |
| `DB 접근 미확인` | ① Repository 인터페이스만 탐지, 구현체 파일 탐색 실패 (멀티모듈/별도 JAR), ② `@Mapper` 없이 XML만 있는 iBatis/MyBatis DAO, ③ `SqlMapClientTemplate` 패턴 미인식 | `rg "implements <InterfaceName>"`, `rg "class.*DaoImpl"` 구현체 탐색 |
| `추적 불가` | ① **FeignClient/RestTemplate → 실제 DB는 외부 서비스 담당** (가장 흔한 원인), ② EventPublisher/Listener 비동기 구조, ③ 위임 체인 3홉 초과, ④ 인터페이스 구현체 없음(미구현 스텁) | Service 클래스 직접 읽기 → `FeignClient`, `restTemplate.exchange`, `webClient` 호출이면 DB 접근 없음 확정 |
| `mybatis_dynamic_review` | ① `orderBy`/`sortColumn` 등 ORDER BY 구문에 동적 변수 사용, ② 스캐너가 Enum/Integer 방어 로직 자동 확인 실패 | 해당 mapper.xml SQL ID 직접 확인 + Controller 파라미터 타입 및 검증 로직 |

---

##### 1-A-2. "DB 로직 없음" 확정 절차 (⚠️ 별도 판정 단계)

> **"DB 접근 미확인"/"추적 불가" 항목 중 실제로 DB 접근 자체가 없는 API가 다수 포함된다.**
> 이런 API를 "양호"나 "정보"로 묶지 말고 **별도 `해당없음(DB접근없음)` 판정으로 분리**하면
> 실제 취약 후보 수가 줄어 후속 단계의 검토 부담이 크게 감소한다.

**"DB 로직 없음" 판정 기준** — 아래 중 하나라도 확인되면 확정:

| 확인 내용 | 판정 근거 |
|---|---|
| Service가 FeignClient / RestTemplate / WebClient 만 호출 | 외부 API 위임 — 이 서비스에 DB 없음 |
| Service가 `redisTemplate`, `cacheManager` 만 사용 | Cache/Redis only |
| Service 메서드가 단순 계산·변환·포맷팅만 수행 | 비즈니스 로직, DB 없음 |
| Controller가 Service를 호출하지 않고 직접 응답 | Controller-only 처리 |
| Service가 File I/O 만 수행 | 파일 처리, DB 없음 |

**확인 방법:**
```bash
# 1. Service 클래스 내 DB 관련 키워드 부재 확인
rg "(Repository|Mapper|JdbcTemplate|SqlSession|createQuery|executeQuery)" <ServiceFile> -c
# → 0건이면 DB 접근 없음 확정

# 2. FeignClient/RestTemplate 사용 여부 확인
rg "(FeignClient|restTemplate\.|webClient\.|feign\.)" <ServiceFile> -l

# 3. Redis 전용 Service 확인
rg "(redisTemplate|StringRedisTemplate|RedisRepository)" <ServiceFile> -c
```

**판정 기록**: 확인된 `해당없음(DB접근없음)` endpoint들은 `group_judgments`의 별도 group으로 분리:
```json
{
  "group": "DB 접근 없음 (N건)",
  "root_cause": "FeignClient/RestTemplate 외부 API 호출 전용 서비스",
  "judgment": "해당없음(DB접근없음)",
  "llm_resolution_method": "Service 클래스 직접 확인 — DB 관련 키워드 0건, FeignClient 호출만 확인",
  "endpoints_reviewed": ["GET /api/v1/...", "POST /api/v2/..."]
}
```

---

##### 1-A-3. DB 접근 확인 후 취약 여부 판정 (코드 직접 확인 절차)

> "DB 로직 없음"으로 분리한 후, **실제로 DB 접근이 있는 추적 실패 endpoint**들에 대해 코드를 읽고 취약 여부를 판정한다.

**그룹별 대표 endpoint 샘플링 및 코드 확인 절차:**

```bash
# Step 1: 추적 실패 endpoint를 diagnosis_type별로 그룹화하여 목록 확인
python3 -c "
import json
from collections import defaultdict
d = json.load(open('state/<prefix>_injection.json'))
eps = d.get('endpoint_diagnoses', [])
groups = defaultdict(list)
for e in eps:
    if e.get('diagnosis_type') in ['자동 판정 불가', 'DB 접근 미확인', '추적 불가'] \
       or e.get('access_type') == 'mybatis_dynamic_review':
        key = e.get('diagnosis_type','') or e.get('access_type','')
        groups[key].append(e.get('endpoint',''))
for k, v in groups.items():
    print(f'{k}: {len(v)}건')
    for ep in v[:5]: print(f'  {ep}')
"

# Step 2: 그룹별 대표 Service/DAO 파일 탐색
rg "<ServiceClassName>" testbed/ -l   # Service 구현체 파일 찾기
rg "<DaoClassName>" testbed/ -l       # DAO/Mapper 파일 찾기

# Step 3: MyBatis XML 전수 ${}  스캔 (전체 repo)
find testbed/ -name "*.xml" | xargs grep -n '\${' 2>/dev/null | grep -v "<!--" | grep -v ".svn"

# Step 4: iBatis XML 전수 $param$ 스캔
find testbed/ -name "*.xml" | xargs grep -n '\$[a-zA-Z]' 2>/dev/null | grep -v "<!--"
```

**그룹 대표 샘플 검토 → 그룹 전체 판정 적용:**

각 그룹에서 3~5개 endpoint의 Controller → Service → DAO → SQL 코드를 직접 확인한다.
대표 샘플의 패턴이 그룹 전체에서 동일한 구조(같은 Service/DAO 클래스, 같은 XML)를 공유하면 **그룹 전체에 동일 판정 적용**한다.

| 확인 결과 | judgment 값 | 기록 방법 |
|---|---|---|
| 전원 DB 없음 | `해당없음(DB접근없음)` | group으로 분리 (1-A-2) |
| DB 있고, `#{}` 바인딩만 사용 | `양호` | group_judgments + services_reviewed |
| DB 있고, `${}` + 외부입력 미도달 | `정보` | group_judgments + 근거 |
| DB 있고, `${}` + 외부입력 도달 | `취약` | findings에 INJ-001 등록 |
| 일부 endpoint는 다른 판정 | 그룹 판정 + `endpoint_verdicts`로 예외 기록 | — |

**완료 조건**: Taint 추적 실패로 분류된 모든 endpoint가 `group_judgments` 내 어느 group의 `endpoints_reviewed`에 포함되어야 한다. 누락 시 Task 미완료.

```bash
# 완료 조건 검증: 전수 확인 완료 여부
python3 -c "
import json
d = json.load(open('state/<prefix>_injection.json'))
eps = d.get('endpoint_diagnoses', [])
taint_failed = [e for e in eps if e.get('diagnosis_type') in [
    '자동 판정 불가', 'DB 접근 미확인', '추적 불가'
] or e.get('access_type') == 'mybatis_dynamic_review']
print(f'Taint 추적 실패: {len(taint_failed)}건')
for e in taint_failed[:10]:
    print(f'  {e.get(\"endpoint\",\"\")} — {e.get(\"diagnosis_type\",\"\")} / {e.get(\"access_type\",\"\")}')
"
```

---

1. **`needs_review: true` / `result: 정보` 항목 심층 분석 [필수]**
   - 스크립트가 자동 판정하지 못한 endpoint (외부 의존성 / XML 미발견 등)
   - **diagnosis_type 그룹별 대표 서비스/DAO 소스코드를 직접 읽고 판정 확정**
   - ⚠️ **`diagnosis_type: "자동 판정 불가"` 항목은 반드시 LLM이 직접 서비스/DAO 코드를 확인해야 한다.**
     - "자동 판정 불가" = 스캐너가 DB 접근 패턴을 분석하지 못한 것 (안전 확인이 아님)
     - 자동으로 양호 처리 절대 금지 — 코드 직접 확인 후 판정
     - 주요 원인: Kotlin SQL 상수 참조, 동적 SQL 빌더, 외부 모듈 의존성
   - 절차:
     1. `endpoint_diagnoses`에서 `result: 정보` 항목을 `diagnosis_type`별로 그룹화
     2. 각 그룹의 외부 서비스/DAO → MyBatis XML/JPA/iBatis 직접 확인
     3. `${}` 발견 시 → **injection_diagnosis_criteria.md Section 1의 4단계 매트릭스** 적용
        - Step 1: `${}` 탐지 → 즉시 취약 판정 금지, taint 역추적 시작
        - Step 2: 변수가 HTTP 파라미터에서 유래하지 않으면 → **정보**
        - Step 3: Enum 캐스팅 / Integer형 / 화이트리스트 if-switch → **양호(FP)**
        - Step 4: 검증 없이 String 직삽 → **취약(TP)**
        - 스캐너 `access_type="mybatis_dynamic_review"` 결과는 Step 2/3 수동 확인 필요
     4. 판정 결과를 `sqli_endpoint_review` 블록으로 저장
   - **전체 매퍼 XML `${}` 패턴 전수 스캔** (`find` + `grep -n '\${' *.xml`) 으로 빠른 일괄 확인 가능

2. **취약 판정 검증**
   - 스크립트가 "취약"으로 판정한 항목의 정확성 확인
   - 실제 사용자 입력이 취약 코드에 도달하는지 데이터 흐름 추적

3. **전역 OS Command / SSI 결과 분석**
   - 스크립트가 발견한 전역 패턴의 실제 위험도 판정
   - 사용자 입력 연관성 확인

---

### 파일 탐색 전략 (토큰 최적화)

> **`needs_review` / `정보` 항목과 취약 항목의 관련 파일만 읽습니다.**

1. 스크립트 결과 JSON에서 `result: 정보` 또는 `result: 취약` 항목 필터
2. `diagnosis_type`별 그룹화 → 그룹 대표 서비스/DAO 식별
3. 외부 모듈 소스 경로 탐색 (`find testbed/ -name "ServiceName*"`)
4. **MyBatis/iBatis XML 전수 스캔** (빠른 일괄 확인):
   ```bash
   python3 -c "
   import glob
   files = glob.glob('testbed/**/*.xml', recursive=True)
   mapper_files = [f for f in files if 'mapper' in f.lower() or '/mapper/' in f]
   for f in mapper_files:
       lines = [(i+1,l.strip()) for i,l in enumerate(open(f).read().splitlines()) if '\${' in l and not l.strip().startswith('<!--')]
       if lines:
           print(f.split('/')[-1] + ':')
           for no,l in lines[:3]: print(f'  L{no}: {l}')
   "
   ```
5. JPA Repository 패턴: `findBy*` 파생 쿼리 + `@Query(:param)` 바인딩 → 안전
6. iBatis `SqlMapClientTemplate.queryForObject("id", param)`: XML의 `#{}` 확인

```
정보 endpoint → diagnosis_type 그룹화 → 대표 서비스 소스 확인
  └→ mapper XML 전수 스캔: ${}=위험, #{}=안전
  └→ JPA findBy*/JPQL :param → 안전
  └→ 판정 결과 → sqli_endpoint_review 블록으로 저장
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

#### 2.3 [필수] global_findings.os_command_injection 항목 LLM 판정 → global_findings_analysis.os_command 기록

`injection.json`의 `global_findings.os_command_injection.findings[]`가 비어 있지 않으면 **각 항목에 대해** 아래 절차로 판정하여 `global_findings_analysis.os_command[]`에 기록한다:

```
[1] 파일·라인 코드 확인 → 실제 명령 실행 함수(exec/ProcessBuilder 등) 사용 여부
[2] 파라미터 소스 추적 → 사용자 HTTP 입력인지, 서버 내부값/설정값인지
[3] 판정:
    - 사용자 입력 + 미필터링 → "취약" (findings[]에 INJ-00N으로 추가)
    - 내부값/설정값만 → "정보(잠재적 위험)"
    - 실제 exec() 미동반 (패턴만 매칭) → "양호(패턴오탐)"
```

기록 형식:
```json
{
  "global_findings_analysis": {
    "os_command": [
      {
        "pattern_id": "RUNTIME_EXEC",
        "file": "com/example/Foo.java",
        "line": 42,
        "judgment": "정보(잠재적 위험)",
        "reason": "Runtime.exec() 호출이지만 hardcoded 서버 명령만 실행, 사용자 입력 미도달"
      }
    ]
  }
}
```

`os_command_injection.total == 0`이면 빈 배열 `[]` 기재 (생략 금지).

---

### 3. SSI 인젝션 진단

스크립트가 자동 스캔하는 항목:
- SSI 디렉티브: `<!--#exec`, `<!--#include`, `<!--#echo`, `<!--#config` 등
- 템플릿 인젝션: Thymeleaf SSTI, FreeMarker, Velocity, SpEL, EL Injection
- Node.js 템플릿: EJS, Nunjucks, Handlebars, Pug
- Python 템플릿: Template(), render_to_string(), Jinja2

#### 3.1 [필수] global_findings.ssi_injection 항목 LLM 판정 → global_findings_analysis.ssi 기록

`injection.json`의 `global_findings.ssi_injection.findings[]`가 비어 있지 않으면 **각 항목에 대해** 아래 절차로 판정하여 `global_findings_analysis.ssi[]`에 기록한다:

```
[1] 파일·라인 코드 확인 → 실제 템플릿 엔진 평가(SpEL parseExpression 등) 사용 여부
[2] 파라미터 소스 추적 → 평가되는 표현식이 사용자 입력인지, 내부 상수/설정값인지
    - SpEL: @Cacheable key 표현식, @Value 등은 내부 설정 → 취약 아님
    - FreeMarker/Thymeleaf: 사용자 입력 문자열이 template 변수로 직접 전달 → 취약 가능
[3] 판정:
    - 사용자 입력 + 비검증 템플릿 평가 → "취약"
    - 내부 설정값/상수만 → "정보(out-of-scope)"
    - 검색 결과 상 패턴만 매칭, 실제 평가 미발생 → "양호(패턴오탐)"
```

기록 형식:
```json
{
  "global_findings_analysis": {
    "ssi": [
      {
        "pattern_id": "SSI_SPEL_EXPRESSION",
        "file": "com/example/RedisCacheAspect.java",
        "line": 88,
        "judgment": "정보(out-of-scope)",
        "reason": "SpEL parseExpression()은 @Cacheable key 표현식 파싱용 — 사용자 HTTP 입력 미도달, out-of-scope"
      }
    ]
  }
}
```

`ssi_injection.total == 0`이면 빈 배열 `[]` 기재 (생략 금지).

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

### ⚠️ 완료 조건 자가 검증 (필수 — 미충족 시 Task 미완료)

**출력 JSON 작성 전 반드시 아래 명령을 실행하고 수치를 확인하라:**

```bash
# 1. injection.json의 실제 정보 endpoint 수 확인
python3 -c "
import json
d = json.load(open('state/<prefix>_injection.json'))
eps = d.get('endpoint_diagnoses', [])
info = [e for e in eps if e.get('overall_result')=='정보' or e.get('needs_review')]
from collections import Counter
dtype_cnt = Counter(e.get('diagnosis_type','') for e in info)
print(f'총 정보 endpoint: {len(info)}건')
for k,v in dtype_cnt.most_common(): print(f'  {v}건: {k}')
"
```

**검증 기준:**
- `sqli_endpoint_review.total_info_endpoints` 값 == 위 명령의 출력 수치 **일치 필수**
- `group_judgments` 배열에 **모든 diagnosis_type 유형**이 각 1개 이상 포함 필수
  - 예: 79건 자동판정불가 + 45건 DB접근미확인 + 2건 추적불가 → group_judgments 3개 이상
  - `해당없음(DB접근없음)` 그룹이 확인된 경우 반드시 별도 group으로 분리 기록
- 각 group의 `endpoints_reviewed` 배열에 **실제 분석한 endpoint 목록** 기재 필수 (빈 배열 [] 금지)
- 각 group에 `root_cause` (스캐너 추적 실패 원인) + `llm_resolution_method` (LLM 해결 방법) 필수 기재
- **그룹 판정과 다른 개별 endpoint**가 있으면 `endpoint_verdicts` 배열에 별도 기록
- **[Taint 추적 실패 전수 확인 체크]** 아래 명령으로 Taint 추적 실패 건수를 별도 확인하고,
  해당 수치가 `group_judgments` 내 모든 `endpoints_reviewed` 합계와 일치해야 함:
  ```bash
  python3 -c "
  import json
  d = json.load(open('state/<prefix>_injection.json'))
  eps = d.get('endpoint_diagnoses', [])
  taint_failed = [e for e in eps if e.get('diagnosis_type') in [
      '자동 판정 불가', 'DB 접근 미확인', '추적 불가'
  ] or e.get('access_type') == 'mybatis_dynamic_review']
  print(f'Taint 추적 실패 endpoint: {len(taint_failed)}건')
  "
  ```
  - 위 수치가 0보다 크고 `group_judgments`에서 누락되면 → **Task 3-2 미완료**

**[global_findings 체크]** `injection.json`의 `global_findings.*.total` 합계를 확인:
```bash
python3 -c "
import json
d = json.load(open('state/<prefix>_injection.json'))
gf = d.get('global_findings', {})
for k, v in gf.items():
    t = v.get('total', 0) if isinstance(v, dict) else len(v)
    print(f'{k}: {t}건')
"
```
- OS Command 또는 SSI 항목이 1건 이상이면 → `global_findings_analysis.os_command[]` / `global_findings_analysis.ssi[]` **반드시 기재**
- 두 배열 모두 기재 없이(`[]` 포함 누락) Task 완료 불가 → **Task 미완료**

---

### 출력 형식

자동스캔 결과(`<prefix>_injection.json`)에서 수동 확정이 필요한 항목만 findings로 출력합니다.
`endpoint_diagnoses`는 포함하지 않으며(자동스캔 JSON에 이미 있음), **보완 findings만** 작성합니다.

> **`affected_endpoints` 작성 규칙** — 각 finding에 영향 받는 API 목록을 구조화 배열로 명시.
> 보고서 렌더링 시 Confluence Expand 매크로 또는 `<details>` 펼치기 섹션으로 자동 출력됩니다.
> - `method`: HTTP 메서드 (GET/POST/PUT/DELETE 등)
> - `path`: Request Mapping 경로 (예: `/api/v1/user/login`)
> - `controller`: 클래스명.메서드명() (예: `UserController.login()`)
> - `description`: 해당 엔드포인트에서 취약점 발현 방식 한 줄 설명

```json
{
  "task_id": "2-2",
  "status": "completed",
  "sqli_endpoint_review": {
    "reviewed_at": "ISO8601 datetime",
    "total_info_endpoints": 0,
    "no_db_logic_count": 0,
    "no_db_logic_note": "FeignClient/RestTemplate 호출 전용 서비스 N건, Redis 전용 M건 등",
    "group_judgments": [
      {
        "group": "DB 접근 없음 (N건)",
        "root_cause": "FeignClient/RestTemplate 외부 API 호출 전용 서비스 — DB 접근 자체 없음",
        "judgment": "해당없음(DB접근없음)",
        "llm_resolution_method": "Service 클래스 직접 확인: DB 키워드 0건, FeignClient 호출만 확인",
        "endpoints_reviewed": ["GET /api/v1/...", "POST /api/v1/..."]
      },
      {
        "group": "외부 의존성 호출 (N건)",
        "root_cause": "스캐너가 추적 실패한 원인: Repository 인터페이스만 탐지, 구현체 파일 다른 모듈",
        "judgment": "양호|정보|취약",
        "llm_resolution_method": "구현체 탐색 후 mapper.xml #{} 바인딩 확인",
        "services_reviewed": [
          {
            "service": "ServiceName (N건)",
            "dao": "DaoClass → mapper.xml (MyBatis/iBatis/JPA)",
            "finding": "#{} 바인딩 확인 / ${}위험패턴 N건 / JPA 파생쿼리",
            "result": "양호|정보|취약"
          }
        ],
        "endpoints_reviewed": ["POST /api/v1/..."]
      },
      {
        "group": "XML 미발견 패턴 추정 (N건)",
        "root_cause": "스캐너가 추적 실패한 원인: Kotlin SQL Builder 심볼 추적 한계",
        "judgment": "양호|정보|취약",
        "llm_resolution_method": "Kotlin DAO 파일 직접 읽기 + SQL 상수 grep",
        "daos_reviewed": [
          {
            "dao": "DaoName (N건 참조)",
            "xml": "mapper-file.xml",
            "finding": "${}패턴 N건 / #{} 바인딩만",
            "result": "양호|정보|취약"
          }
        ],
        "endpoints_reviewed": ["GET /api/v2/..."]
      }
    ],
    "endpoint_verdicts": [
      {
        "endpoint": "POST /api/v1/example",
        "group": "외부 의존성 호출",
        "individual_judgment": "취약",
        "reason": "그룹 전체는 양호이나 이 endpoint만 ${}+String 파라미터 직삽 확인"
      }
    ],
    "overall_sqli_judgment": "양호|정보|취약",
    "rationale": "판정 근거 요약"
  },
  "findings": [
    {
      "id": "INJ-001",
      "title": "취약점 제목",
      "severity": "Medium",
      "category": "Injection / OS Command (Stored RCE Pattern)",
      "description": "상세 설명 — 자동스캔이 탐지하지 못한 취약 패턴",
      "affected_endpoints": [
        {
          "method": "POST",
          "path": "/api/v1/example",
          "controller": "ExampleController.doAction()",
          "description": "파라미터 userInput이 비검증 SQL 쿼리에 직접 삽입됨"
        }
      ],
      "evidence": {
        "file": "com/.../ServiceClass.java",
        "lines": "61-67",
        "code_snippet": "취약 코드 스니펫"
      },
      "cwe_id": "CWE-94",
      "owasp_category": "A03:2021 Injection",
      "diagnosis_method": "수동진단(LLM)",
      "result": "정보",
      "needs_review": false,
      "manual_review_note": "코드 직접 확인 근거",
      "recommendation": "조치 방안"
    }
  ],
  "global_findings_analysis": {
    "os_command": [
      {
        "pattern_id": "RUNTIME_EXEC",
        "file": "com/example/Foo.java",
        "line": 42,
        "judgment": "정보(잠재적 위험)|양호(패턴오탐)|취약",
        "reason": "판정 근거 — 사용자 입력 도달 여부, exec() 실제 호출 여부"
      }
    ],
    "ssi": [
      {
        "pattern_id": "SSI_SPEL_EXPRESSION",
        "file": "com/example/RedisCacheAspect.java",
        "line": 88,
        "judgment": "정보(out-of-scope)|양호(패턴오탐)|취약",
        "reason": "판정 근거 — SpEL 표현식 소스, 사용자 입력 도달 여부"
      }
    ]
  },
  "endpoint_summary": {
    "total": 0,
    "양호": 0,
    "정보": 0,
    "취약": 0
  },
  "executed_at": "",
  "claude_session": ""
}
```

**주의**: `endpoint_diagnoses` 키는 출력하지 않는다 (자동스캔 JSON과 중복).
findings 배열이 비어 있으면(`[]`) 파일을 저장하되 `supplemental_sources`에서 자동으로 무시된다.

---

### 금지사항
- 추측 금지 (코드 근거 없으면 finding 생성 금지)
- 실제 Exploit 페이로드 작성 금지
- 고객 DB 비밀번호, API 시크릿 등 민감정보 포함 금지
- 스크립트가 이미 판정한 "양호" 항목은 재검토 불필요
