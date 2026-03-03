# Release Notes — AI-SEC-OPS Playbook

> 이 저장소는 보안진단 자동화 프레임워크(skills/ + tools/)의 릴리즈 이력을 관리합니다.
> 버전 형식: `vMAJOR.MINOR.PATCH` (SemVer)
> - MAJOR: 아키텍처/진단 엔진 전면 개편
> - MINOR: 신규 Phase 추가 / 주요 기능
> - PATCH: 버그 수정 / 설정 변경

---

## [v4.6.3] - 2026-02-28

### Fixed — scan_injection_enhanced.py: Call Graph 완성 (5종 버그 수정)
- **Fix A**: `_collect_helper_port_calls` — "첫 발견 즉시 반환" → "모든 헬퍼에서 전체 수집" (all_calls 누적)
- **Fix B**: `_extract_service_method_body(content, method_name)` 신규 함수
  - `@Override public/protected` 우선 탐색 → private overload 우선 반환 문제 해결
  - 예: `ExchangePointsService.private exchangePoints(Integer)` vs `@Override public exchangePoints(Command)` → 후자 정확 반환
- **Fix C**: Phase 3b — Controller private 헬퍼에서 추가 UseCase 호출 수집
  - `_SAME_CLASS_CALL_RE` 기반 헬퍼명 추출 → svc_calls 보강
  - 예: `RewardReceiveController.receiveReward()` → `receiveGoldenEggReward()` → `goldenEggRewardReceiveUseCase`
- **Fix D**: Phase 20c — DB 의존성 없는 인프라 서비스 non-DB 판정
  - `not repo_fields AND not db_client_fields AND not db_operations` → `[non-DB]` 마킹
- **Fix E**: `_SAME_CLASS_CALL_RE` 음수 후방탐색 `(?<![.\w])` → DTO getter 오탐 방지

### Verified
- okick-event (19 ep): 양호 19 / 취약 0 / 정보 0 — SHA-256 PASS
- okick-reward (10 ep): 양호 10 / 취약 0 / 정보 0 — SHA-256 PASS

---

## [v4.6.2] - 2026-02-27

### Fixed — scan_injection_enhanced.py: Call Graph Disconnection
- `build_class_index` → `(class_index, impl_index)` 튜플 반환 (구현체 O(1) 조회)
- `_resolve_impl_class(name, class_index, impl_index)` — impl_index 우선 조회
- Phase 17: domain Repository 인터페이스 → JPA 구현체 해석 블록 추가
- Phase 11: `_port_like_fields` 있으면 `[non-DB]` continue 스킵
- Phase 4b: trace_endpoint — Controller private 헬퍼 내 Port 호출 추적
- Phase 17d: `entityManager.persist/merge/remove` → `jpa_builtin` 판정
- Phase 17e: Reflection API + DB indicator 없음 → `none` 판정

---

## [v4.6.1] - 2026-02-26

### Fixed — scan_injection_enhanced.py: `findAllBy` → "DB 미접근" 오분류
- **근본 원인 3가지**:
  1. `findAllBy`가 `JPA_CONVENTION_PREFIXES` 미등록
  2. Phase 17 트리거 조건 `if not db_ops` → domain interface가 `none` op 반환 시 Phase 17 스킵
  3. `extract_method_body`가 Kotlin interface 메서드(body 없음) 이후 메서드를 잘못 흡수
- `JPA_CONVENTION_PREFIXES`에 `findAllBy` 추가
- `extract_method_body`: interface 메서드 guard 추가 (`;` 또는 body 없는 선언 감지)
- Phase 17 트리거: `not db_ops OR all-none` 으로 확장
- Phase 17b: Adapter → 내부 Repository 1단계 추가 추적
- Phase 17c: `analyze_repository_method`에 JPA 위임 호출 패턴 탐지 추가
- `_QUERYDSL_HINT_RE` 확장: `PathBuilder<`, `BooleanBuilder(`, `Q[A-Z]\w+.\w+` 추가

### Added — publish_confluence.py: main_report 타입 신규
- `_json_to_xhtml_main_report()`: 섹션 1(개요)/8(한계)만 추출, JSON 기반 종합 요약 계산
- `_build_main_summary_table()`: injection/xss JSON에서 수치 계산 (단일 소스)
- `_build_main_api_inventory()`: method/api 또는 http_method/request_mapping 자동 감지
- `confluence_page_map.json`: 테스트13/14 → `"type": "main_report"` + `"task_sources"` 구조

---

## [v4.6.0] - 2026-02-25

### Added — Phase 17: Hexagonal Architecture (Port & Adapter 패턴) 지원
- `_TRACEABLE_COMPONENT_SUFFIXES`에 `Port` 추가 (13종)
- `extract_constructor_deps`: bean_suffixes에 `Port` 추가
- `analyze_repository_method`: QueryDSL JPAQueryFactory 안전 탐지
  - `queryFactory.` / `JPAQueryFactory.` → `.where().eq()` → PreparedStatement 바인딩 → 양호
  - `Expressions.stringTemplate()` → 취약 판정
- `trace_endpoint`: Domain Repository 인터페이스 → JPA 구현체 해석
- Phase 15 stub regex에 Port/UseCase/Adapter 패턴 추가 (오탐 방지)

---

## [scan_xss.py v2.3.2] - 2026-03-04

### Fixed — DTO 필드 1레벨 검사 (`_inspect_dto_fields` 신규)
- `@RequestBody` Java record 타입 balanced-parenthesis 파싱
  - 기존 `[^)]+` regex → `@Min(1)` 중첩 괄호에서 파싱 실패 수정
- API inventory `type: "body"` 필드 감지 추가 (`"@RequestBody" in ann` 보완)
- 결과: `ExchangePointsRequestDto`(`Integer goldenEggsCnt` 단일 필드) → 양호 정확 판정

### Verified
- okick-reward: 양호 7 / 취약 3 / 정보 0 — SHA-256 PASS (양호+1 개선)
- okick-event: 양호 14 / 취약 5 / 정보 0 — SHA-256 PASS (회귀 없음)

---

## [scan_xss.py v2.3.1] - 2026-03-03

### Added — publish_confluence.py XSS 보고서 렌더링 전면 개편
- `_simplify_xss_category(ep)`: 카테고리 분류 (Persistent/Reflected/View XSS, Open Redirect 등)
- `_render_xss_ep_detail(ep)`: 엔드포인트 상세 정보 테이블 + 코드 증거
- `_json_to_xhtml_enhanced_xss()` 전면 재작성:
  - 카테고리별 그룹핑 + 대표 케이스 + Expand 매크로
  - DOM XSS 하단 분리
  - XSS 전역 필터 상태 → info/warning 매크로 박스

---

## [scan_xss.py v2.3.0] - 2026-03-03

### Added — SET/WHERE 절 구분 + 헥사고날 아키텍처 구현체 해석
- `_resolve_svc_impl_body()`: UseCase → Service, Port → Adapter 구현체 해석
- `_has_param_in_direct_call()`: repo 호출 인수의 HTTP param standalone 전달 확인
- `_check_repo_param_context()`: SET/WHERE 절 구조 판정 (변수명 무관, 패턴 기반)
  - QueryDSL `.set(col, val)`, JPA `entity.setXxx(val)`, Builder `.field(val)` → "set"
  - `.where(...)` 단독 → "where"
- `_trace_persistent_xss_taint()` 수정: svc_body 폴백 + repo 루프 전면 교체

### Fixed
- `/api/internal/rewards/failure/retry` → 취약(FP) → 양호 정확 판정

---

## [scan_xss.py v2.2.0] - 2026-03-03

### Fixed — 판정 Regression 수정
- `check_persistent_xss` "잠재" 반환 2곳 → "취약" 변경
- `judge_xss_endpoint` "잠재" 핸들러 → worst-case 강제 (≥ 연산)

---

## [scan_xss.py v2.1.0] - 2026-03-03

### Fixed — FP 제거 3종
- `_sqli_has_db_write`: jpa_builtin/querydsl_safe → detail에 save/insert/update 키워드 확인
  (기존: access_type만으로 판정 → SELECT QueryDSL도 write 오인 → FP)
- `_check_enum_validation` + `_P5_SANITIZE_PATTERNS`: Enum.from()/Integer.parseInt()/UUID.fromString() taint 해제
- `_has_freetext_params`: Integer/Boolean/UUID/날짜 타입만 있으면 즉시 양호

---

## [v4.5.2] - 2026-02-24

### Fixed
- `publish_confluence.py`: code 매크로 `language="kotlin"` → `"java"` 변경
  - Confluence Server/DC가 `kotlin`을 미지원 → `InvalidValueException` 해결
- `scan_injection_enhanced.py`: `_extract_call_args()` 선언부 오탐(false positive) 수정
  - 우선순위: `.methodName(` > `return/= methodName(` > `\bmethodName(`
  - 영향: `/user/my/participated/mission` 의 `tagName=null` 하드코딩 케이스 → `[잠재]` 정확 판정

### Added
- `.gitignore`: 정책 누락 항목 보완
  - `보고서예시/`, `old_진단가이드문서/`, `*.docx`, `*.xlsx`, `state/*.md`
- `confluence_page_map.json`: 테스트10 — PCoNA Console v4.5.2 정합성 검증 항목 추가

### Verified
- pcona-console (110 ep): 양호 92 / 취약 18(실제16+잠재2) / 정보 0 — SHA-256 PASS
- ocb-community (226 ep): 양호 218 / 취약 6 / 정보 2 — SHA-256 PASS
- msgsugar (598 ep): 양호 485 / 취약 0 / 정보 113 — SHA-256 PASS

---

## [v4.5.1] - 2026-02-24

### Fixed
- `scan_injection_enhanced.py`: DTO 랩핑 taint 전파 오류
  - `repo_tainted or svc_tainted or None` — empty set 시 name-based 폴백 활성화
  - 영향: `ordering` param이 `CommentGetRequest` DTO에 랩핑된 경우 `[잠재]` → `[실제]` 정확 판정
- `scan_injection_enhanced.py`: Kotlin `${if(expr)}` 복잡 표현식 키워드 오탐
  - `_KT_KEYWORDS` 모듈 상수화 (frozenset)
  - `var_name`이 키워드(`if`)일 때 표현식 전체 비-키워드 식별자 교차 검증

---

## [v4.5.0] - 2026-02-24

### Added — Phase 24: Positional Index Taint Tracking
- HTTP 파라미터 → Service → Repository 계층간 위치 인덱스 기반 taint 전파
- `_propagate_taint_by_index(caller_body, callee_name, callee_content, tainted)`
- `_extract_param_names(params)`: HTTP endpoint 파라미터 이름 집합 추출
- `DbOperation.taint_confirmed: Optional[bool]` 필드 추가
  - `True` = 확인된 taint, `False` = taint 없음, `None` = 미확인(name-based 폴백)
- `trace_endpoint()`: `initial_tainted` → `svc_tainted` → `repo_tainted` 계층 전파
- `_assess_op()`: `taint_confirmed` 우선 사용, `None`이면 name-based 폴백

### Changed
- `[실제] SQL Injection`: HTTP 파라미터 → SQL 삽입 taint 경로 확인 시
- `[잠재] 취약한 쿼리 구조`: 취약 구조이나 taint 미확인 시

---

## [v4.4.0] - 2026-02-23

### Added
- Taint Tracking 초기 구현 (변수명 교차 검증)
- `_extract_kt_sql_varname(op)`: Kotlin SQL injection op에서 삽입 변수명 추출
- Worst-Case Override: 모든 db_ops 평가 후 최악 케이스 선택
- `publish_confluence.py`: `_simplify_category()` — 개발자 친화적 카테고리 분류
  - 취약: `[실제 위협] SQL Injection` / `[잠재적 위협] 취약한 쿼리 구조`
  - 정보: `외부 의존성 호출` / `XML 미발견 패턴 추정` / `호출 경로 추적 불가`
  - 양호: `JPA & ORM 방식` / `MyBatis #{} 바인딩` / `DB 미접근 엔드포인트` / `제어 흐름상 안전`

---

## [v4.3.0] - 2026-02-23

### Added — Phase 23: Kotlin SQL Builder 위임 탐지
- Java Repository → `XxxKt.func()` → Kotlin top-level 함수의 `$var`/`${expr}` SQL 인젝션
- `_analyze_kotlin_sql_builder(method_body, source_dir)`
- 1단계 위임 추적: `return otherFunc()` 패턴
- 지역변수 필터: `var/val` 선언 변수의 `$var` 제외 (false positive 방지)

---

## [v3.5.0] - 2026-02-23

### Added — Phase 10~16 완성
- **Phase 10**: MyBatis Mapper Interface 추정 판정 (XML 미발견 → `#{}`안전 추정)
- **Phase 11**: 비DB Service 필터 (repo/template 미보유 → `[non-DB]` 양호)
- **Phase 12**: 컴포넌트 접미사 확장 (`_TRACEABLE_COMPONENT_SUFFIXES` 12종)
- **Phase 13**: 외부 모듈 서비스 추정 판정 (`class_index` 미존재 → `[external]` 양호)
- **Phase 14**: 내부 위임 depth 확장 (`_trace_internal_methods` 재귀, max_depth=3)
- **Phase 15**: Controller 부모 클래스 의존성 병합 + 비DB 핸들러 stub 판정
- **Phase 16**: 제거/deprecated 엔드포인트 → 양호 판정
- `skills/sec-audit-static/`: 진단 기준, 스키마, 태스크 프롬프트, 룰 체계 완성

### Metrics (msgsugar 598 endpoints 기준)
- v3.3.0: 판정률 67.4% → v3.4.0: 85.6% → v3.5.0: 90.8%

---

## [v3.0.0] - 2026-02-04

### Added
- Controller → Service → Repository 호출 그래프 추적 기반 SQL Injection 진단 엔진 초기 구현
- Phase 1~9: JPA / MyBatis / Kotlin / 위임 추적 / 비DB 필터 등 핵심 로직
- `scan_api.py`: API 엔드포인트 인벤토리 자동 추출
- `publish_confluence.py`: Confluence Server/DC 자동 게시
- `skills/sec-audit-static/`, `skills/sec-audit-dast/`, `skills/external-software-analysis/` 초기 구성
