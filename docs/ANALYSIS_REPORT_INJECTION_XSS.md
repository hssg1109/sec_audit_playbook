# SQL Injection & XSS 진단 스크립트 설계 분석 보고서

> 대상 스크립트: `tools/scripts/scan_injection_enhanced.py` (v4.6.3) / `tools/scripts/scan_xss.py` (v2.3.2)
> 작성일: 2026-03-04

---

## 1. 개요

이 문서는 Hexagonal Architecture(Port & Adapter 패턴) 기반 Spring Boot 프로젝트를 대상으로
SQL Injection 및 XSS 취약점을 자동 탐지하는 두 스크립트의 핵심 설계 원칙과 구현 패턴을 기록한다.

### 진단 대상 프로젝트 특성

| 특성 | 내용 |
|------|------|
| 언어 | Java 17 + Kotlin |
| 아키텍처 | Hexagonal (Port & Adapter) / MVC 혼재 |
| ORM | JPA + QueryDSL + MyBatis |
| 프레임워크 | Spring Boot 3.x |
| 진단 규모 | 598 ep (msgsugar), 226 ep (ocb-community), 110 ep (pcona-console), 19+10 ep (okick) |

### 최종 진단 정확도

| 프로젝트 | 양호 | 취약 | 정보 | 비고 |
|----------|------|------|------|------|
| msgsugar | 485 | 0 | 113 | SQL Injection v4.5.2 |
| ocb-community | 218 | 6 | 2 | 실제2 + 잠재4 |
| pcona-console | 92 | 18 | 0 | 실제16 + 잠재2 |
| okick-event | 19 | 0 | 0 | v4.6.3 전량 양호 |
| okick-reward | 10 | 0 | 0 | v4.6.3 전량 양호 |

---

## 2. Hexagonal Architecture 호출 그래프 추적

### 2.1 문제 정의

일반 MVC 패턴에서는 `Controller → Service → Repository` 3-tier 호출 체인이 명확하다.
Hexagonal Architecture에서는 인터페이스와 구현체가 분리된다:

```
Controller
  └─ XxxUseCase (interface, in-package)
       └─ XxxService (class, application layer)  ← 실제 구현체
            └─ XxxPort (interface, out-package)
                 └─ XxxAdapter (class, infrastructure)  ← 실제 구현체
                      └─ XxxJpaRepository (Spring Data JPA)
```

Regex 기반 파서는 인터페이스 파일을 읽으면 메서드 body가 없어(`""` 반환) taint 추적이
중단되는 문제가 발생한다.

### 2.2 해결 전략: 인터페이스 → 구현체 이름 변환

**scan_injection_enhanced.py** — `_resolve_impl_class()` 함수:

```python
_IFACE_IMPL_MAP = {
    "Repository":  ["JpaRepository", "PersistenceAdapter"],
    "Port":        ["Adapter"],
    "UseCase":     ["Service"],
}

def _resolve_impl_class(name: str, class_index: dict,
                        impl_index: dict = None) -> Optional[Path]:
    # 1. impl_index O(1) 직접 조회 (build_class_index 단계에서 구현체 인덱스 별도 구축)
    if impl_index and name in impl_index:
        return impl_index[name]
    # 2. suffix 치환 후 class_index 조회
    for iface_suf, impl_suffixes in _IFACE_IMPL_MAP.items():
        if name.endswith(iface_suf):
            base = name[:-len(iface_suf)]
            for impl_suf in impl_suffixes:
                if base + impl_suf in class_index:
                    return class_index[base + impl_suf]
    return None
```

**scan_xss.py** — `_resolve_svc_impl_body()` 함수:

```python
_P5_IFACE_TO_IMPL_SUFFIX = (
    ("UseCase", "Service"),
    ("Port",    "Adapter"),
)

def _resolve_svc_impl_body(svc_type, svc_method, class_index, source_dir):
    for iface_suf, impl_suf in _P5_IFACE_TO_IMPL_SUFFIX:
        if not svc_type.endswith(iface_suf):
            continue
        impl_name = svc_type[:-len(iface_suf)] + impl_suf
        impl_file = class_index.get(impl_name) or _glob_fallback(impl_name, source_dir)
        if not impl_file:
            continue
        body = extract_method_body(read_file_safe(impl_file), svc_method)
        if body:
            return body, read_file_safe(impl_file)
    return "", ""
```

### 2.3 impl_index 구축 (build_class_index 확장)

단순 클래스명 → 파일 경로 매핑 외에, 구현체 탐지를 위한 인덱스를 추가 구축한다:

```python
def build_class_index(source_dir: Path) -> tuple[dict, dict]:
    class_index = {}
    impl_index = {}
    for f in source_dir.rglob("*.java"):
        stem = f.stem
        class_index[stem] = f
        # implements/extends 패턴으로 구현체 탐지
        content = f.read_text(errors="ignore")
        m = re.search(r'\bimplements\s+([\w,\s]+)', content)
        if m:
            for iface in m.group(1).split(","):
                impl_index[iface.strip()] = f
    return class_index, impl_index
```

### 2.4 다단계 위임 추적

Adapter가 직접 JPA가 아닌 도메인 Repository 인터페이스를 보유하는 경우:

```
XxxPersistenceAdapter
  └─ XxxRepository (domain interface)      ← Phase 17b: 추가 1단계 위임
       └─ XxxJpaRepository (extends JPA)   ← Phase 17 최종 목적지
```

Phase 17b에서 Adapter의 의존성 중 Repository 접미사 필드를 발견하면
1단계 추가 역참조를 수행한다.

---

## 3. AST/Regex 기반 컨텍스트 인식

### 3.1 WHERE vs SET 절 구분

SQL Injection에서 "파라미터가 WHERE 조건에만 사용"되는 경우는 **읽기 경로**로 안전하다.
파라미터가 SET 절에 사용되는 경우만 **쓰기 경로**로 취약하다.

`scan_xss.py` Phase 5의 `_check_repo_param_context()`:

```python
def _check_repo_param_context(repo_content, repo_method, param_names) -> str:
    repo_body = extract_method_body(repo_content, repo_method) or ""
    if not repo_body:
        return "unknown"

    # SET 절 지시자 — 우선 확인 (Worst-case 원칙: SET 발견 시 즉시 취약)
    if _P5_QDSL_SET_RE.search(repo_body):        # QueryDSL: .set(Q.field, val)
        return "set"
    if _P5_ENTITY_SETTER_RE.search(repo_body):   # JPA: entity.setXxx(val)
        return "set"
    if _P5_BUILDER_SET_RE.search(repo_body):     # Builder: .builder()...field(val)
        return "set"

    # WHERE 절 지시자
    has_where = re.search(r'\.where\s*\(', repo_body) or re.search(r'\bWHERE\b', repo_body)
    has_write = re.search(r'\bUPDATE\b|\bINSERT\b|\bpersist\b|\bmerge\b', repo_body)
    if has_where and not has_write:
        return "where"

    return "unknown"  # 판정 불가 → 보수적 폴백
```

판정 결과 흐름:

| ctx 반환값 | 의미 | taint 처리 |
|-----------|------|-----------|
| `"set"` | SET 절 사용 → DB 저장 경로 확인 | taint_confirmed=True (취약) |
| `"where"` | WHERE 조건만 → 읽기 경로 | sanitized=True (양호) |
| `"unknown"` | 판정 불가 | write 메서드면 보수적 취약 처리 |

### 3.2 직접 전달 vs 체인 호출 구분

`_has_param_in_direct_call()` — HTTP param이 repo 메서드 인수에 **standalone 변수**로
직접 전달되는지 확인한다. DTO 필드 접근(`log.dto().id()`)이나 메서드 체인은 제외한다:

```python
# standalone identifier: 앞에 '.' 없고, 뒤에 '(' 없음
standalone_re = re.compile(r'(?<![.\w])(\w+)(?!\s*\()')
```

| 패턴 | 판정 | 이유 |
|------|------|------|
| `repo.findAll(id, cnt)` | direct=True | `id` standalone |
| `repo.update(log.dto().id(), type)` | direct=False | `id`는 `.id()` 체인 |
| `repo.save(entity)` | direct=False | entity는 DTO 래핑 → FN 방지 경로로 별도 처리 |

### 3.3 QueryDSL 안전 패턴 탐지

`scan_injection_enhanced.py`의 `_QUERYDSL_HINT_RE`:

```python
_QUERYDSL_HINT_RE = re.compile(
    r'(?:'
    r'jpaQueryFactory\.'
    r'|JPAQueryFactory\.'
    r'|queryFactory\.'
    r'|new\s+JPAQuery\b'
    r'|new\s+JPAQueryFactory\b'
    r'|QEntity\s*\.'      # Q클래스 직접 사용
    r'|PathBuilder\s*<'   # PathBuilder 패턴
    r'|BooleanBuilder\s*\(' # BooleanBuilder 패턴
    r'|\bQ[A-Z]\w+\.\w+'  # Q접두사 클래스 필드 참조
    r')',
    re.DOTALL,
)
```

QueryDSL은 PreparedStatement 방식으로 파라미터를 바인딩하므로
조건 빌더 패턴 자체가 SQL Injection에 안전하다.

### 3.4 메서드 body 추출 정확도 개선

**문제**: `extract_method_body`가 Kotlin interface 메서드(body 없음) 이후의
다른 메서드 body를 잘못 흡수하는 버그:

```kotlin
interface Foo {
    fun bar(): String   // body 없음 — 하지만 다음 메서드 body까지 흡수
}
class Impl {
    fun bar(): String { return "ok" }
}
```

**수정**: interface 메서드 guard:
- `{` 이전에 `;` 발견 (Java abstract) → `""` 반환
- `fun` / `public/private` 선언만 있고 `{` 없음 → `""` 반환

**문제 2**: `extract_method_body`가 동명 메서드 중 private overload를 우선 반환:

```java
class ExchangePointsService {
    private void exchangePoints(Integer cnt) { ... }  // ← 잘못된 반환
    @Override
    public void exchangePoints(ExchangePointsCommand cmd) { ... }  // ← 원하는 것
}
```

**수정**: `_extract_service_method_body()` 신규 함수:
1. `@Override public/protected` 어노테이션 우선 탐색
2. 없으면 일반 `extract_method_body` 폴백

---

## 4. FN(False Negative) 방어 로직

### 4.1 DTO/Entity 래핑 패턴

Controller에서 HTTP 파라미터를 Command/DTO로 래핑한 후 Service를 호출하면
Positional Index Taint Tracking이 빈 집합을 반환할 수 있다:

```java
// Controller
ExchangePointsCommand cmd = new ExchangePointsCommand(goldenEggsCnt, ...);
exchangePointsUseCase.exchangePoints(cmd);  // svc_tainted = {}
```

**방어 로직**: `svc_tainted or svc_tainted is None` 조건에서 empty set → name-based 폴백:

```python
# tainted 집합이 empty인 경우(DTO 래핑 등) → name-based 폴백 활성화
if not repo_tainted and not svc_tainted:
    repo_tainted = None  # name-based 폴백 신호
```

### 4.2 Enum/Type 캐스팅 무해화

`scan_xss.py`의 `_check_enum_validation()`:

```python
# Controller body에서 파라미터가 Enum.from() 등으로 변환되는지 확인
_P5_SANITIZE_PATTERNS = re.compile(
    r'(?:'
    r'Integer\.parseInt\(\s*\w+\s*\)'
    r'|Long\.parseLong\(\s*\w+\s*\)'
    r'|UUID\.fromString\(\s*\w+\s*\)'
    r'|[A-Z]\w+\.from(?:Code|Value|Name)?\(\s*\w+\s*\)'  # Enum factory
    r'|[A-Z]\w+\.valueOf\(\s*\w+\s*\)'
    r')',
    re.IGNORECASE,
)
```

타입 변환은 입력값을 구조화된 타입으로 강제 변환하여 자유 텍스트 삽입을 방지한다.

### 4.3 `@AuthenticationPrincipal` 제외

Spring Security의 `@AuthenticationPrincipal`은 JWT/세션에서 추출한 인증된 객체로,
HTTP 요청 파라미터와 다르다. taint 추적 시 제외한다:

```python
if "@AuthenticationPrincipal" in ann:
    continue  # 인증 객체 — taint 추적 대상 아님
```

### 4.4 자유 텍스트 없으면 즉시 양호

`_has_freetext_params()`: 파라미터가 모두 `Integer`, `Boolean`, `UUID`, `LocalDate` 등
비-자유텍스트 타입이면 XSS 불가 → 즉시 양호 반환:

```python
_P5_NON_FREETEXT_TYPES = frozenset({
    "Integer", "int", "Long", "long", "Double", "double",
    "Boolean", "boolean", "UUID", "LocalDate", "LocalDateTime",
    "ZonedDateTime", "OffsetDateTime", "Date", "BigDecimal",
})

def _has_freetext_params(endpoint, class_index=None, source_dir=None) -> bool:
    for p in endpoint.get("params", []):
        base = _extract_base_type(p.get("data_type", ""))
        if base in _P5_NON_FREETEXT_TYPES:
            continue
        is_request_body = "@RequestBody" in ann or p.get("type") == "body"
        if is_request_body and class_index:
            all_nonfree = _inspect_dto_fields(base, class_index, source_dir)
            if all_nonfree is True:
                continue  # DTO 필드 전부 비자유텍스트 → 안전
        return True  # 자유 텍스트 파라미터 존재
    return False
```

### 4.5 DTO 필드 1레벨 검사 (v2.3.2 신규)

`_inspect_dto_fields()`: Java record 파일을 파싱하여 필드 타입 검사.

핵심 파싱 과제: `@Min(1) Integer goldenEggsCnt` 에서 `@Min(1)` 안의 `)` 때문에
단순 `[^)]+` regex가 실패한다. 해결: 괄호 깊이(depth) 추적 방식:

```python
def _inspect_dto_fields(dto_type, class_index, source_dir) -> Optional[bool]:
    # ...파일 로드...
    record_start = re.search(r'\brecord\s+\w+\s*\(', content)
    if record_start:
        pos = record_start.end() - 1
        # 괄호 깊이 추적으로 record 파라미터 목록 끝 위치 탐색
        depth = 0
        for i in range(pos, len(content)):
            if content[i] == '(':   depth += 1
            elif content[i] == ')':
                depth -= 1
                if depth == 0: end = i; break
        inner = content[pos + 1:end]
        # 쉼표로 분리 (괄호 안 쉼표 제외)
        components = _split_by_top_level_comma(inner)
        types = [_strip_annotations_get_base(comp) for comp in components]
        return all(t in _P5_NON_FREETEXT_TYPES for t in types if t)
```

---

## 5. 폴백 및 교차 검증

### 5.1 SQLi 결과 교차 검증 (scan_xss.py)

Persistent XSS는 "HTTP 파라미터가 DB에 저장 → 다른 사용자가 조회 시 실행"되는 패턴이다.
전제 조건: HTTP 파라미터가 DB에 **저장**되어야 한다.

`check_persistent_xss()`는 별도로 생성된 `sqli_result`(SQL Injection 진단 결과)를
교차 참조하여 해당 엔드포인트가 DB 쓰기 경로를 보유하는지 확인한다:

```python
sqli_ep = sqli_by_api.get(api_path)
if sqli_ep:
    sqli_verdict = sqli_ep.get("verdict", "")
    has_write = _sqli_has_db_write(sqli_ep)
    if not has_write:
        return {"result": "양호", "reason": "SQLi 진단: DB 쓰기 경로 없음"}
```

`_sqli_has_db_write()` 정확도 개선 (v2.1.0):
- `jpa_builtin`/`querydsl_safe`: `detail`에 save/insert/update/persist/merge 키워드 확인
- 단순 `access_type` 만으로 판정하면 SELECT QueryDSL도 write로 오인 → FP 발생

### 5.2 보수적 잠재적 취약 판정 (scan_injection_enhanced.py)

taint 추적이 불완전한 경우 무조건 양호 판정하지 않고 `[잠재] 취약한 쿼리 구조`로 판정:

```python
# taint_confirmed = None (추적 불가) → name-based 폴백
if taint_confirmed is None:
    # HTTP 파라미터명과 SQL 변수명이 일치하면 [실제]
    if param_name in kt_sql_varnames:
        return "actual_vuln"   # [실제] SQL Injection
    else:
        return "potential_vuln"  # [잠재] 취약한 쿼리 구조
```

| 상황 | 판정 |
|------|------|
| taint 경로 확인됨 + 파라미터명 일치 | [실제] SQL Injection |
| 구조적으로 취약하나 taint 경로 불확실 | [잠재] 취약한 쿼리 구조 |
| WHERE 절만 사용 확인 | 양호 |
| DB 미접근 경로 확인 | 양호 |

### 5.3 Worst-Case Override 원칙

여러 DB 접근 경로가 존재할 때 가장 심각한 케이스를 최종 결과로 선택:

```python
def _assess_op(db_ops, tainted_params):
    worst = None
    for op in db_ops:
        result = _assess_single_op(op, tainted_params)
        if worst is None or result.priority > worst.priority:
            worst = result
    return worst
```

Priority: `[실제] SQL Injection` (4) > `[잠재] 취약한 쿼리 구조` (3) > `정보` (2) > `양호` (1)

### 5.4 Controller private 헬퍼 메서드 추적

Controller의 핵심 메서드가 UseCase를 직접 호출하지 않고 private 헬퍼를 통해 호출하는 경우:

```java
// Controller
public void receiveReward(...) {
    receiveGoldenEggReward(user, dto);  // private 헬퍼 호출
}
private void receiveGoldenEggReward(...) {
    goldenEggRewardReceiveUseCase.receiveReward(...);  // 실제 UseCase 호출
}
```

Phase 3b: `_SAME_CLASS_CALL_RE`로 헬퍼 메서드명 추출 → `extract_method_calls`로
추가 UseCase 호출 수집:

```python
_SAME_CLASS_CALL_RE = re.compile(r'(?<![.\w])([a-z]\w+)\s*\(')
```

---

## 6. 진단 파이프라인 전체 흐름

```
[입력]
  API 인벤토리 (scan_api.py 생성)
  소스 코드 (testbed/)

[Phase 0] 클래스 인덱스 구축
  build_class_index() → (class_index, impl_index)

[Phase 1~3] 엔드포인트 분류
  1. Controller 탐색 및 파라미터 추출
  2. Service 호출 체인 탐색
  3b. Controller private 헬퍼 내 추가 UseCase 수집

[Phase 4~16] DB 접근 분석
  4. Repository 의존성 탐지 (Hexagonal 포함)
  5. JPA Convention 메서드 판정 (findAllBy, save 등)
  10~16. MyBatis/비DB 필터/외부모듈 추정 등

[Phase 17] Hexagonal Architecture 해석
  domain interface → impl_index/suffix 치환 → JPA구현체
  Adapter → 내부 Repository 1단계 추가 추적

[Phase 23~24] Taint 추적
  HTTP params → Service → Repository (Positional Index)
  Kotlin $var 변수명 교차 검증

[Phase 20] 비DB 메서드 필터
  DB 의존성 없는 인프라 서비스 non-DB 판정

[출력]
  verdict: 양호/[잠재]취약/[실제]취약/정보
  call_chain: 호출 경로
  evidence: 취약 코드 스니펫
```

---

## 7. 알려진 한계 및 개선 방향

### 7.1 현재 한계

| 한계 | 설명 | 영향 |
|------|------|------|
| 4단계 이상 위임 체인 | Port→Adapter→DomainRepo→JpaRepo 같은 다단계 | 일부 FP 잔존 |
| Cross-repo 호출 | MSA 환경에서 타 마이크로서비스 호출 추적 불가 | 탐지 누락 |
| 동적 SQL (런타임) | 리플렉션, 동적 클래스 로딩 | 탐지 불가 |
| Regex vs AST | 복잡한 중첩 표현식에서 파싱 오류 | 오탐/누락 |

### 7.2 개선 방향 (로드맵)

1. **Language-Server-MCP-Bridge** (T-08): LSP `textDocument/references`로
   IDE 수준 시맨틱 분석 — Regex 파싱 한계 극복
2. **Sourcegraph/Zoekt 전사 인덱싱** (A-05): Cross-repo taint tracking
3. **SARIF 출력** (A-01): IDE 플러그인 직접 연동
4. **Delta 진단** (A-02): PR 변경분 중심 증분 스캔

---

## 8. 관련 파일 경로

| 파일 | 설명 |
|------|------|
| `tools/scripts/scan_injection_enhanced.py` | SQL/Command/SSI Injection 진단 엔진 (v4.6.3) |
| `tools/scripts/scan_xss.py` | XSS 진단 엔진 (v2.3.2) |
| `tools/scripts/scan_api.py` | API 엔드포인트 인벤토리 추출 |
| `tools/scripts/publish_confluence.py` | Confluence 자동 게시 |
| `skills/sec-audit-static/` | 진단 기준, 스키마, 태스크 프롬프트 |
| `docs/22_injection_review.md` | SQL Injection 진단 절차 |
| `docs/23_xss_review.md` | XSS 진단 절차 |
| `RELEASENOTE.md` | 버전 이력 |
