# Injection Diagnosis Criteria (Enhanced)

Framework/ORM별 SQL Injection 진단 기준. scan_injection_enhanced.py (v3.2+)에서 자동 적용.

## 1. MyBatis — ${}  4단계 판정 매트릭스 (v3.2+)

> `${}` 탐지 시 즉시 취약 판정하지 않고, 아래 4단계 Taint Flow 분석을 수행한다.

| 단계 | 상태 | 조건 | 판정 | 스캐너 access_type |
|------|------|------|------|--------------------|
| **Step 1** | 탐지 (Base State) | XML 파일 내 `${param}` 존재 | `[잠재적 위협]` — taint 역추적 시작 | — |
| **Step 2** | Source 확인 | `${}` 변수가 HTTP 파라미터에서 유래하지 않음 (시스템 내부값, 상수, UUID 등) | `정보(Info)` — 외부 조작 불가 | `mybatis_dynamic_review` |
| **Step 3** | Context 확인 | 외부 입력이 도달하나 **방어 로직** 존재 | `양호(FP)` — SQL Injection 페이로드 삽입 불가 | `mybatis_dynamic_safe` |
| **Step 4** | 최종 판정 | String 입력이 검증 없이 `${}` 에 직삽 | `취약(TP)` — SQL Injection 확정 | `mybatis_unsafe` |

### Step 3 방어 로직 인정 기준

| 방어 패턴 | 예시 | 판정 |
|-----------|------|------|
| Enum 클래스 타입 캐스팅 | `SortDirection.valueOf(param)`, `OrderType.ASC` | 양호 |
| `Integer` / `Long` 등 숫자형 타입 강제 | `Integer pageSize`, `Long.parseLong(param)` | 양호 |
| `if-else` / `switch` 화이트리스트 치환 | `if (sort.equals("ASC")) "ASC" else "DESC"` | 양호 |

### 변수명 분류 기준 (스캐너 자동 적용)

| 분류 | 변수명 패턴 | 기본 판정 (방어 없을 때) |
|------|------------|--------------------------|
| **동적 바인딩** | `orderBy`, `sortColumn`, `direction`, `tableName`, `limit`, `offset` 등 | Step 2/3 경계 → `정보` (Review Needed) |
| **일반 입력** | 그 외 (`keyword`, `name`, `status` 등) | Step 4 → `취약` |

> `#{param}` 은 PreparedStatement 바인딩 → 항상 **양호**.

---

## 2. JPA / Spring Data JPA

| 패턴 | 판정 | 설명 |
|------|------|------|
| Repository 내장 메서드 (`findById`, `save`, `deleteById` 등) | 양호 | 자동 파라미터 바인딩 |
| `@Query("... :param ...")` | 양호 | Named parameter 바인딩 |
| `@Query("... " + param + " ...")` | 취약 | 문자열 연결 |
| `Specification` / `Criteria API` | 양호 | 타입 안전 쿼리 빌더 |
| `EntityManager.createNativeQuery(str)` | **검토 → 반드시 추적** | 동적 SQL 여부 확인 필요 — 아래 상세 기준 참조 |
| `EntityManager.createNativeQuery("..." + var + "...")` | **취약** | 문자열 결합 직접 확인 → 즉시 취약 판정 |
| `EntityManager.createNativeQuery(String.format(...))` | **취약** | 포맷 인자가 외부 입력인 경우 |
| `EntityManager.createQuery("... :param ...")` + `setParameter` | 양호 | Named parameter 바인딩 |

#### EntityManager.createNativeQuery() 심층 탐지 절차 (SSC TP-01 피드백)

`@Query(nativeQuery=true)` 어노테이션 스캐너가 잡지 못하는 **메서드 바디 동적 SQL 패턴**을 별도 확인한다.

```bash
# Step 1: createNativeQuery 직접 호출 전체 탐지
grep -rn "createNativeQuery" <src> | grep -v "@Query"

# Step 2: 해당 라인 ±30줄 Read → SQL 문자열 구성 방식 확인
#   - 변수로 구성 후 전달? → 해당 변수의 구성 코드 추적
#   - "..." + var + "..." 패턴? → 즉시 취약 판정

# Step 3: 해당 메서드의 호출 경로 추적 (멀티홉 테인트)
grep -rn "<메서드명>" <src>
#   → Controller에서 requestBody/requestParam 값을 파라미터로 전달하면 취약
#   → 내부 하드코딩 상수만 전달하면 tableName 취약 아님 (단, mbrId 등 동반 파라미터 추가 확인)
```

**판정 기준**:
- SQL 문자열에 `+` 결합 / `String.format` / `StringBuilder.append`가 있고, 그 값이 Controller 파라미터에서 유래 → **취약**
- tableName만 하드코딩이고 모든 조건 파라미터가 `:param`으로 바인딩 → **양호**
- tableName 하드코딩 + 조건 파라미터도 문자열 결합 → **취약** (mbrId 등 결합 파라미터 확인)

## 3. JDBC / NamedParameterJdbcTemplate

| 패턴 | 판정 | 설명 |
|------|------|------|
| `:param` + `paramMap.put()` | 양호 | Named parameter 바인딩 |
| `?` + `PreparedStatement.setXxx()` | 양호 | Positional 바인딩 |
| `"..." + param + "..."` | 취약 | 문자열 연결 |
| `String.format("...%s...", param)` | 취약 | 포맷 문자열 삽입 |

## 4. Kotlin String Template (NEW - v2.3)

Kotlin 파일에서 SQL 문자열 생성 시 사용되는 패턴. **가장 높은 오탐 위험**.

| 패턴 | 판정 | 설명 |
|------|------|------|
| `'$variable'` in SQL | 취약 | 단순 변수 보간 → SQL 직접 삽입 |
| `'${expression}'` in SQL | 취약 | 표현식 보간 → SQL 직접 삽입 |
| `sql += "... $variable ..."` | 취약 | 동적 SQL 조립 + 보간 |
| `:param` in SQL + `paramMap` | 양호 | Named parameter 바인딩 |

### Kotlin SQL Builder 패턴 탐지

Kotlin top-level function이 SQL 문자열을 반환하는 패턴:

```kotlin
// 취약 패턴: 파라미터가 SQL에 직접 삽입
fun buildQuery(ordering: String): String {
    return """
        SELECT * FROM table
        ORDER BY column ${ordering}    ← 취약
    """
}

// 양호 패턴: Named parameter 사용
fun buildQuery(): String {
    return """
        SELECT * FROM table
        ORDER BY column :ordering      ← 양호
    """
}
```

### 탐지 방법 (5-method detection)

1. **Method 1**: `${expression}` 중 함수 파라미터명 포함 여부
2. **Method 2**: `$variable` 단순 변수 보간 확인
3. **Method 3**: 파생 변수 추적 (param → local var → SQL)
4. **Method 4**: `+ param +` 문자열 연결
5. **Method 5**: 델리게이트 함수 재귀 추적 (depth 3)

## 5. R2DBC

| 패턴 | 판정 | 설명 |
|------|------|------|
| `.bind(index, value)` / `.bind("name", value)` | 양호 | 파라미터 바인딩 |
| `Criteria.where(...).is(value)` | 양호 | Criteria API |
| `"..." + param.toString()` | 취약 | 문자열 연결 |

## 6. NamedParameterJdbcTemplate

| 패턴 | 판정 | 설명 |
|------|------|------|
| `namedParameterJdbcTemplate.query(sql, paramMap)` + `:param` | 양호 | Named parameter 바인딩 |
| `jdbcTemplate.query(sql, args)` + `?` | 양호 | Positional 바인딩 |
| `jdbcTemplate.execute("..." + param + "...")` | 취약 | 문자열 결합 |

## 7. MyBatis / iBatis (v3.0+)

> **`${}` 판정은 Section 1의 4단계 매트릭스를 따른다.** 아래는 패턴 분류 참조용.

| 패턴 | 초기 분류 | 최종 판정 | 설명 |
|------|----------|-----------|------|
| `#{param}` (XML/Annotation) | 양호 | 양호 | PreparedStatement 바인딩 |
| `${param}` (XML/Annotation) | 잠재적 위협 | Step 1→4 매트릭스 적용 | 문자열 직접 치환 — taint 추적 필수 |
| `#param#` (iBATIS 2.0 XML) | 양호 | 양호 | Legacy PreparedStatement 바인딩 |
| `$param$` (iBATIS 2.0 XML) | 잠재적 위협 | Step 1→4 매트릭스 적용 | Legacy 직접 치환 |
| `@Select("... #{param} ...")` | 양호 | 양호 | Mapper interface 어노테이션 바인딩 |
| `@Select("... ${param} ...")` | 잠재적 위협 | Step 1→4 매트릭스 적용 | Mapper interface 어노테이션 직접 삽입 |
| `SqlMapClientTemplate` + `#{}` XML | 양호 | 양호 | DAO → XML 간접 바인딩 |
| `SqlMapClientTemplate` + `${}` XML | 잠재적 위협 | Step 1→4 매트릭스 적용 | DAO → XML 간접 직접 삽입 |

### MyBatis XML Mapper 추적 방식

1. **XML 인덱스 구축**: `<mapper namespace="...">` / `<sqlMap namespace="...">` 파싱
2. **SQL ID 매핑**: `namespace.sqlId` → `#{}`/`${}` 사용 여부 분석
3. **DAO 역추적**: `sqlMapClientTemplate.queryForObject("namespace.sqlId", param)` 호출에서 SQL ID 추출
4. **Mapper Interface 매핑**: interface 메서드명 → XML SQL ID 자동 연결

### 자동 판정 기준 (v3.2+)

| access_type | 판정 | 스캐너 동작 |
|---|---|---|
| `mybatis_safe` / `ibatis_safe` | **양호** | `#{}` 바인딩 확인 |
| `mybatis_dynamic_safe` | **양호 (FP)** | Step 3: Enum/Integer/화이트리스트 방어 로직 확인 |
| `mybatis_dynamic_review` | **정보** | Step 2/3: 동적 바인딩 변수 (order/sort 등), 수동 검증 필요 |
| `mybatis_unsafe` / `ibatis_unsafe` | **취약** | Step 4: 일반 변수 검증 없이 직삽 |

- XML mapper 전체가 `#{}` 만 사용 시 → 해당 namespace의 모든 endpoint **양호**
- `_assess_mybatis_dollar_verdict()` 함수가 caller(서비스/DAO) 코드에서 방어 패턴을 탐색하여 Step 3 자동 적용

### XML 파싱 정책 (v3.1+)

- **파싱 방식**: `xml.etree.ElementTree` 사용 (정규식 대신)
- **XML 주석** (`<!-- -->`): ElementTree가 자동 무시
- **SQL 주석** (`/* ... */`, `-- ...`): 텍스트 수집 후 제거하여 오탐 방지
- **`<include refid="...">`**: 해당 `<sql id>` 조각을 인라인 병합하여 분석

## 8. OS Command Injection - 동적 스크립트 실행 엔진

### 8.1 GroovyShell / ScriptEngine 판정 기준

| 판정 | 스크립트 소스 | 설명 | 조건 |
|------|-------------|------|------|
| **취약** (Direct RCE) | HTTP request parameter | 사용자 입력이 parse()/evaluate()의 코드 영역에 직접 전달 | `shell.evaluate(request.getParameter("script"))` |
| **취약** (Stored RCE / 잠재적 취약) | DB entity / Config | DB 또는 설정 파일의 스크립트 필드 → 관리자/DB 침해 시 RCE. 악용 경로가 실재하므로 취약으로 분류. | `shell.evaluate(entity.getScript())` |
| **양호** | classpath 고정 파일 | 정적 리소스만 parse + 사용자 입력은 Binding 변수(값)로만 전달 | `shell.parse(classpathSource)` + `setBinding()` |

### 8.2 판정 세부 기준

**취약 판정 조건** (1개라도 해당 시):
- HTTP `@RequestParam`/`@RequestBody` 값 → `GroovyShell.parse()` 또는 `.evaluate()` 인자로 전달
- URL 경로 변수 → 스크립트 코드 문자열에 결합

**취약 판정 조건 (Stored RCE / 잠재적 취약)**:
- DB Entity의 `script` 필드 → `shell.evaluate(condition)` 경로 존재
- `replaceAll()` 등 syntax 치환은 **보안 필터가 아님** → RCE 차단 불가
- 이중 파싱 구조: 1차 parse(classpath) → run() → 결과 문자열에 `it.script` 포함 → 2차 parse
- DB 침해(관리자 권한 탈취 또는 SQL Injection) 시 임의 코드 실행 경로가 확실히 존재 → **취약**으로 분류
- 심각도: Medium (DB 침해 선행 필요) / 필수 조치: `SecureASTCustomizer` 샌드박스 적용

**양호 판정 조건** (모두 충족 시):
- 스크립트 소스가 classpath 리소스 파일(`classpath:xxx.groovy`)만 사용
- 사용자 입력은 `Binding` 변수(값)로만 전달, 코드 영역 미도달
- 추가 안전장치 존재: `SecureASTCustomizer`, `CompilerConfiguration` 등

### 8.3 브라우저 JavaScript eval() 판정 기준

| 판정 | 실행 환경 | 설명 |
|------|----------|------|
| **OS Command 아님** | 브라우저 (webapp/) | 클라이언트 JS의 eval()은 OS Command Injection 범주 아님 (DOM-based XSS 영역) |
| **정보** | Node.js 서버 | 서버사이드 eval()은 Code Injection / RCE 가능성 존재 |

**브라우저 JS 판별**: `require(`/`module.exports`/`from '` 패턴 없는 JS 파일 → 클라이언트사이드로 추정

### 8.4 실제 사례 분석 (GameGroovyService 패턴)

```
Controller → GameHandler → GameGroovyService.cacheAndRun()
  → groovyShell.parse(groovySource)     // classpath:game_targeting.groovy (고정)
  → script.setBinding(binding)           // conditions를 Binding 변수로 전달
  → script.run()                         // 1차 실행 → 동적 스크립트 문자열 생성
  → groovyShell.parse(runScriptText)     // 2차 파싱 (생성된 스크립트)
  → runScript.run()                      // 2차 실행
```

- HTTP 파라미터(`deviceId`, `uuid`)는 조건 비교 '값'으로만 사용, '코드' 영역 미도달
- `GameTargetingScriptEntity.script`는 DB에서 조회 → **Stored RCE** (DB 침해 필요)
- 판정: **취약 / 잠재적 취약** (Direct RCE 불가, Stored RCE 경로 실재 → Medium)

## 9. 스캐너 추적 실패 유형별 근본 원인 및 LLM 해결 전략

> **이 섹션은 scan_injection_enhanced.py가 endpoint의 DB 접근 흐름을 추적하지 못한 경우의
> 원인 분석과 LLM 수동 해결 방법을 정의한다.** (`task_22_injection_review.md` 1-A-1과 쌍.）

### 9.1 diagnosis_type별 근본 원인 분류

| diagnosis_type | 스캐너 실패 원인 | 실제 상황 | LLM 해결 전략 |
|---|---|---|---|
| `자동 판정 불가` | Kotlin SQL Builder 함수 심볼 추적 한계 / Generic DAO 패턴 / 런타임 위임 | DB 접근이 있으나 스캐너가 코드 구조를 파싱하지 못함 | Kotlin 파일 직접 grep: `buildQuery`, `createQuery`, SQL 리터럴 상수 |
| `DB 접근 미확인` | Repository 인터페이스만 발견, 구현체 탐색 실패 / iBatis `SqlMapClientTemplate` 미인식 | DB 접근은 있으나 어떤 SQL인지 미확인 | `rg "class.*DaoImpl\|implements.*Repository"` 구현체 탐색 후 mapper.xml 확인 |
| `추적 불가` | FeignClient/RestTemplate 외부 API 호출 (가장 흔함) / 3홉 이상 위임 체인 / 인터페이스만 존재 | **많은 경우 실제로 DB 접근이 없음** (외부 서비스 위임) | Service 직접 읽기 → FeignClient/HTTP 호출이면 DB 없음 확정 |
| `mybatis_dynamic_review` | Enum/Integer 방어 로직 자동 확인 실패 / ORDER BY 동적 변수 | `${}` 있으나 방어 여부 미확인 | mapper.xml SQL + Controller 파라미터 타입 동시 확인 |

### 9.2 "DB 로직 없음" 조기 확정 기준

아래 확인을 통해 DB 접근이 **없음이 확정되면** `해당없음(DB접근없음)`으로 즉시 판정하여 후속 분석 범위를 줄인다:

```bash
# DB 관련 키워드 전무 확인
rg "(Repository|Mapper|JdbcTemplate|SqlSession|createQuery|executeQuery|entityManager)" \
   <ServiceFile> -c
# → 0이면 DB 없음 확정

# 외부 HTTP 클라이언트 사용 확인
rg "(FeignClient|restTemplate\.|webClient\.|feign\.target\|@FeignClient)" \
   <ServiceFile>
# → 있으면 외부 API 위임 → DB 없음

# Redis 전용 확인
rg "(redisTemplate|StringRedisTemplate|RedisRepository|@Cacheable)" \
   <ServiceFile>
# → DB 관련 없고 Redis만 있으면 DB 없음
```

### 9.3 추적 실패 API 취약 여부 갱신 절차 (LLM Phase 3-2 수행)

1. **1-A-2 DB 로직 없음 분리**: 먼저 `해당없음(DB접근없음)` 케이스를 확정하여 분리
2. **나머지 그룹별 대표 샘플 코드 확인**: Controller → Service → DAO → SQL (3~5개/그룹)
3. **그룹 단위 판정 확정**: 대표 샘플이 동일 패턴이면 그룹 전체에 동일 판정 적용
4. **예외 endpoint 개별 기록**: 그룹 판정과 다른 endpoint는 `endpoint_verdicts`에 별도 기록
5. **취약 확정 시 finding 등록**: `findings` 배열에 INJ-00N으로 finding 생성

→ 상세 출력 스키마: `task_22_injection_review.md` 출력 형식 참조

---

## 10. 교차 검증 필수 조건

자동 스캐너가 "취약"으로 판정한 경우, 반드시 아래 교차검증을 수행:

1. **사용자 입력 도달 여부**: `@RequestParam`, `@PathVariable`, `@RequestBody`에서 취약 파라미터까지 데이터 흐름 추적
2. **하드코딩 여부**: Service/Controller에서 고정값만 전달되는지 확인
3. **타입 안전성**: `long`, `int` 등 숫자 타입은 SQL Injection 불가
4. **코드 활성화 여부**: 주석 처리(`/* */`)된 코드는 "정보(비활성 코드)"로 분류
5. **경로 도달 여부**: switch/if 분기에서 실제 취약 메서드 호출 경로에 도달하는지 확인

→ 상세 절차는 `references/cross_verification.md` 참조
