# Release Notes — AI-SEC-OPS Playbook

> 이 저장소는 보안진단 자동화 프레임워크(skills/ + tools/)의 릴리즈 이력을 관리합니다.
> 버전 형식: `vMAJOR.MINOR.PATCH` (SemVer)
> - MAJOR: 아키텍처/진단 엔진 전면 개편
> - MINOR: 신규 Phase 추가 / 주요 기능
> - PATCH: 버그 수정 / 설정 변경

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
