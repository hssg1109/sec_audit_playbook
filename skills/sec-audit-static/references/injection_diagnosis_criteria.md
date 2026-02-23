# Injection Diagnosis Criteria (Enhanced)

Framework/ORM별 SQL Injection 진단 기준. scan_injection_enhanced.py (v3.1+)에서 자동 적용.

## 1. MyBatis

| 패턴 | 판정 | 설명 |
|------|------|------|
| `#{param}` | 양호 | PreparedStatement 바인딩 |
| `${param}` | 취약 | 문자열 직접 치환 (SQL Injection) |
| `${param}` in `ORDER BY` / `LIMIT` | 취약 | 동적 정렬/페이징도 위험 |

## 2. JPA / Spring Data JPA

| 패턴 | 판정 | 설명 |
|------|------|------|
| Repository 내장 메서드 (`findById`, `save`, `deleteById` 등) | 양호 | 자동 파라미터 바인딩 |
| `@Query("... :param ...")` | 양호 | Named parameter 바인딩 |
| `@Query("... " + param + " ...")` | 취약 | 문자열 연결 |
| `Specification` / `Criteria API` | 양호 | 타입 안전 쿼리 빌더 |
| `EntityManager.createNativeQuery(str)` | 검토 | 동적 SQL 여부 확인 필요 |

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

| 패턴 | 판정 | 설명 |
|------|------|------|
| `#{param}` (XML/Annotation) | 양호 | PreparedStatement 바인딩 |
| `${param}` (XML/Annotation) | 취약 | 문자열 직접 치환 (SQL Injection) |
| `#param#` (iBATIS 2.0 XML) | 양호 | Legacy PreparedStatement 바인딩 |
| `$param$` (iBATIS 2.0 XML) | 취약 | Legacy 문자열 직접 치환 |
| `@Select("... #{param} ...")` | 양호 | Mapper interface 어노테이션 바인딩 |
| `@Select("... ${param} ...")` | 취약 | Mapper interface 어노테이션 직접 삽입 |
| `SqlMapClientTemplate` + `#{}` XML | 양호 | DAO → XML 간접 바인딩 |
| `SqlMapClientTemplate` + `${}` XML | 취약 | DAO → XML 간접 직접 삽입 |

### MyBatis XML Mapper 추적 방식

1. **XML 인덱스 구축**: `<mapper namespace="...">` / `<sqlMap namespace="...">` 파싱
2. **SQL ID 매핑**: `namespace.sqlId` → `#{}`/`${}` 사용 여부 분석
3. **DAO 역추적**: `sqlMapClientTemplate.queryForObject("namespace.sqlId", param)` 호출에서 SQL ID 추출
4. **Mapper Interface 매핑**: interface 메서드명 → XML SQL ID 자동 연결

### 자동 판정 기준

- `mybatis_safe` / `ibatis_safe` → **양호** (filter_detail: "mybatis #{}")
- `mybatis_unsafe` / `ibatis_unsafe` → has_search_params 기준 **취약/정보** 분류
- XML mapper 전체가 `#{}` 만 사용 시 → 해당 namespace의 모든 endpoint **양호**

### 동적 바인딩 예외 처리 (v3.1+)

| `${}` 변수명 | 판정 | 설명 |
|---|---|---|
| `${orderBy}`, `${sort}`, `${column}` 등 | **정보 (Review Needed)** | 기능상 불가피한 동적 바인딩 - 수동 검증 필요 |
| `${table}`, `${schema}` | **정보 (Review Needed)** | 동적 테이블 참조 - 화이트리스트 검증 확인 필요 |
| 기타 변수명 (`${name}`, `${keyword}` 등) | **취약** | 사용자 입력이 SQL에 직접 삽입 |

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
| **정보** (Stored RCE) | DB entity / Config | DB 또는 설정 파일의 스크립트 필드 → 관리자/DB 침해 시 RCE | `shell.evaluate(entity.getScript())` |
| **양호** | classpath 고정 파일 | 정적 리소스만 parse + 사용자 입력은 Binding 변수(값)로만 전달 | `shell.parse(classpathSource)` + `setBinding()` |

### 8.2 판정 세부 기준

**취약 판정 조건** (1개라도 해당 시):
- HTTP `@RequestParam`/`@RequestBody` 값 → `GroovyShell.parse()` 또는 `.evaluate()` 인자로 전달
- URL 경로 변수 → 스크립트 코드 문자열에 결합

**정보 판정 조건** (Stored RCE):
- DB Entity의 `script` 필드 → `shell.evaluate(condition)` 경로 존재
- `replaceAll()` 등 syntax 치환은 **보안 필터가 아님** → RCE 차단 불가
- 이중 파싱 구조: 1차 parse(classpath) → run() → 결과 문자열에 `it.script` 포함 → 2차 parse
- 개선 권고: `SecureASTCustomizer`로 허용 클래스/메서드 화이트리스트 적용

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
- 판정: **정보** (Direct RCE 불가, Stored RCE 가능)

## 9. 교차 검증 필수 조건

자동 스캐너가 "취약"으로 판정한 경우, 반드시 아래 교차검증을 수행:

1. **사용자 입력 도달 여부**: `@RequestParam`, `@PathVariable`, `@RequestBody`에서 취약 파라미터까지 데이터 흐름 추적
2. **하드코딩 여부**: Service/Controller에서 고정값만 전달되는지 확인
3. **타입 안전성**: `long`, `int` 등 숫자 타입은 SQL Injection 불가
4. **코드 활성화 여부**: 주석 처리(`/* */`)된 코드는 "정보(비활성 코드)"로 분류
5. **경로 도달 여부**: switch/if 분기에서 실제 취약 메서드 호출 경로에 도달하는지 확인

→ 상세 절차는 `references/cross_verification.md` 참조
