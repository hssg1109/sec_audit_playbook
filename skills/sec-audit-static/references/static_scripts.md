# Static Audit Scripts

Canonical automation scripts (repo `tools/scripts/`):

## Core Scripts

- `load_audit_memory.py`: 프로젝트별 FP 예외 메모리 로드 — Phase 3 시작 전 필수 실행
  - `state/<prefix>/.audit-memory.json` 탐색 → `fp_rules` 파싱
  - 출력: `state/<prefix>/audit_memory.md` ([Project Specific Context & Exceptions] 형식)
  - 파일 없으면 빈 파일 생성 후 종료 (Phase 3 정상 진행)
  - 템플릿: `tools/audit_memory_template.json`
  - 사용법: `python3 tools/scripts/load_audit_memory.py --state-dir state/<prefix>/`
- `parse_asset_excel.py`: asset Excel -> JSON
- `merge_results.py`: merge task results -> `final_report.json`
- `redact.py`: redact sensitive data in reports
- `validate_task_output.py`: schema validation for task outputs/reports
- `generate_finding_report.py`: generate Markdown report from findings

## Scan Scripts

- `scan_api.py` (v3.2): API endpoint inventory extraction
  - Java/Kotlin dual-mode parsing (auto-detect by file extension)
  - Java: `@GetMapping`/`@PostMapping` + return type method declarations
  - Kotlin: `fun` keyword declarations
  - Parameter parsing: `Type name` (Java) / `name: Type` (Kotlin)
  - 블록 주석 (`/* ... */`) 자동 제거: 주석 내 컨트롤러는 `commented_controllers`에 별도 기록
  - 인증 4-Level 매트릭스 + 이진 분류 (`auth_required: true/false`):
    - L1 완전 인증: `@Session(required=true, permitted=true)` → true
    - L2 기본 인증: `@Session(required=true)` 또는 bare `@Session` → true
    - L3 비인증: `@Session(required=false)` → false
    - L4 조건부 인증: `@Session(required=false, permitted=true)` → false
    - `@PreAuthorize`, `@Secured` → true
    - `--auth-annotations` 옵션으로 프로젝트별 어노테이션 추가
  - DTO 카탈로그 연동: `--dto-catalog` 옵션으로 파라미터 타입 필드 해석
  - Output: JSON with endpoints, method_stats, module_stats, security_configs, auth_stats, auth_detail_stats, commented_controllers

- `scan_dto.py` (v1.0): DTO/타입 카탈로그 추출
  - Java/Kotlin dual-mode parsing (auto-detect by file extension)
  - Java: `@Data`(Lombok), `@Entity`(JPA), nested static class, 필드 어노테이션
  - Kotlin: `data class` primary constructor, `val`/`var` 프로퍼티
  - 중첩 클래스 지원: `OuterClass.InnerClass` qualified naming
  - 상속 해석: `extends`(Java) / `:`(Kotlin) → 부모 필드 병합(inherited 마킹)
  - Output: JSON type catalog with field-level detail, type_index
  - scan_api.py와 연동: `--dto-catalog` 옵션으로 파라미터 타입 enrichment

- `scan_injection_enhanced.py` (v4.9): Endpoint-level injection diagnosis
  - Controller → Service → Repository → SQL Builder 호출 체인 자동 추적
  - Java dependency injection 지원: `@Autowired`, `@RequiredArgsConstructor`, constructor injection
  - JPA built-in method 자동 양호 판정 (`findById`, `save`, `deleteById` 등)
  - Kotlin SQL Builder 5-method detection:
    1. `${expression}` 파라미터 포함
    2. `$variable` 단순 보간
    3. 파생 변수 추적 (param → local var → SQL)
    4. `+ param +` 문자열 연결
    5. 델리게이트 함수 재귀 추적 (depth 3)
  - Global scan: OS Command Injection, SSI Injection, Kotlin SQL Builder 전역 패턴
  - **[신규] Joern CPG 연동** (`--jar <path>`, `--joern-home <dir>`):
    - `build_target.py`로 빌드된 JAR/WAR를 Joern CPG로 변환하여 bytecode 수준 taint 분석
    - `joern_sqli_taint.sc` 스크립트로 HTTP 파라미터→SQL sink 직접 flow 탐지
    - 결과 병합: "정보+needs_review" 상태에서 Joern flow 확인 시 "취약"으로 자동 상향
    - Joern 미설치 또는 분석 실패 시 source-based 분석 결과 그대로 유지 (no-op)
    - `scan_metadata.joern_analysis` 필드에 분석 결과 기록
  - Output: endpoint_diagnoses (양호/취약/정보/N/A), global_findings, summary

- `scan_file_processing.py` (v1.0): File Upload/Download & LFI/RFI vulnerability scanner
  - 업로드 엔드포인트: MultipartFile + UUID 난수화 / Tika MIME 검증 / 확장자 Whitelist / 크기 제한
  - 다운로드/LFI: HTTP 파라미터 → 파일 API Taint Tracking (Long 타입은 안전 판정)
    - Path Traversal 필터(`replace("../")`, `getCanonicalPath()` 등) 미적용 시 취약 판정
  - RFI/SSRF: HTTP String 파라미터 → 외부 요청 API Taint Tracking, URL Whitelist 검증
  - 설정 파일: `application.properties/yml`에서 `max-file-size`, `max-request-size` 파싱
  - Output: upload_diagnoses / download_diagnoses / rfi_diagnoses / config_findings / summary
  - 수동진단 연동: `needs_review: true` 항목 → `task_prompts/task_24_file_handling.md` 프롬프트 4종

- `scan_injection_patterns.py` (v2.1): OS Command/SSI Injection 패턴 라이브러리 (`scan_injection_enhanced.py` 의존)
  - `OS_CMD_PATTERNS`, `OS_CMD_SAFE_PATTERNS`, `OS_CMD_FILTER_CHARS`: OS Command Injection 탐지 패턴
  - `SSI_PATTERNS`: Server-Side Include Injection 패턴
  - `scan_file()`, `matches_glob()`: 파일 스캔 헬퍼 함수
  - `SQLI_VULNERABLE_PATTERNS`, `SQLI_SAFE_PATTERNS`, `SQLI_CONCAT_PATTERNS`: SQL Injection 패턴 상수
  - ⚠️ `scan_injection_enhanced.py`가 직접 import — 독립 실행 불가, 반드시 함께 유지

- `build_target.py` (v1.0): /sec-audit-static 사전 빌드 실행 + 아티팩트 매니페스트 생성
  - 빌드 도구 자동 감지: Maven / Gradle / npm / pip / PHP (no-build)
  - JDK 버전 자동 탐색: `/usr/lib/jvm/java-{v}-*`, SDKMAN, update-alternatives
  - 빌드 실패 시 소스 분석 fallback 자동 처리 (종료 코드 0 유지)
  - Joern 분석 대상 primary_jar 자동 선택 (WAR 우선 → 가장 큰 JAR)
  - SCA용 dependency tree 생성 (`--dep-report` 플래그)
  - Output: `state/<prefix>/build_manifest.json`
    - `primary_jar`: Joern 분석 대상 경로 → `scan_injection_enhanced.py --jar`에 전달
    - `artifacts`: 전체 빌드 아티팩트 목록 + 크기
    - `fallback_source_only`: true이면 Joern 생략, source-only 분석
  - 사용법: `python3 build_target.py --source-dir <dir> --build-cmd "<cmd>" --jdk 17 -o state/<prefix>/build_manifest.json`
  - **`--resolve-deps`**: 빌드 실패 시 `com.skp.*` 누락 패키지 자동 감지 → Bitbucket에서 클론 → `settings.gradle`에 `includeBuild()` 주입 후 재빌드 (Method B: Composite Build). 재빌드 후 `settings.gradle` 원상복원. `CUSTOMER_BB_TOKEN` (.env) 필요.
    - `_INTERNAL_PKG_REPO_MAP`: 10개 prefix → Bitbucket project/repo 매핑 내장 (com.skp.ocb.webview, com.skp.oz 등)
    - 매니페스트에 `composite_build` 섹션 추가 (attempted, success, cloned_repos, skipped_pkgs)

- `joern_sqli_taint.sc`: Joern SQL Injection taint flow 분석 스크립트 (Scala)
  - Source: `@GetMapping/@PostMapping/@RequestMapping` + `@RequestParam/@PathVariable/@RequestBody`
  - Sink: JDBC/JPA/MyBatis/JdbcTemplate SQL 실행 메서드 (execute, query, createNativeQuery 등)
  - `scan_injection_enhanced.py`가 자동 호출 (`--jar` 지정 시)
  - Output: `state/joern_sqli_taint.json` (taint flow 목록)
  - joern-parse로 CPG 생성 후 joern CLI로 실행 (`joern-parse <jar> -o cpg.bin`)

- `scan_sca_gradle_tree.py` (v2.0): SCA — Gradle/npm 네이티브 파싱 + OSV.dev CVE 조회 (P2-01 권장)
  - Gradle `dependencies` 태스크 결과 파싱: 전이적 의존성(transitive) 포함
  - package-lock.json(npm) 자동 감지 및 파싱 (동일 커맨드로 자동 전환)
  - OSV.dev API 배치 조회: groupId:artifactId:version 기준 CVE 매핑
  - CVSS 점수, 영향 버전 범위, fixed 버전 자동 추출
  - `scan_sca.py`와 동일한 출력 스키마 (findings[] + grouped[])
  - 사용법:
    - (Gradle): `python3 scan_sca_gradle_tree.py <src> --project <name> -o state/<prefix>/sca.json`
    - (npm): 위와 동일 (package-lock.json 자동 감지)
  - Output: `state/<prefix>/sca.json`

- `scan_sca.py` (v2.0): SCA + CVE 관련성 분석 + PoC 생성 + Confluence 게시 (P2-01/P2-02, JAR 레거시)
  - **P2-01 (dependency-check 경로)**: dependency-check 실행 → CVE 파싱 → CVSS 기준 필터링
  - **P2-01 (OSV 경로)**: `--dep-tree` 옵션으로 Gradle dep tree → OSV API 배치 조회 (빌드 실패 시 대체)
  - **P2-02**: CISA KEV 조회 → 소스코드 관련성 자동 grep 판정 → PoC 생성
  - 라이브러리별 그룹화 (`_group_and_sort`): CRITICAL>HIGH, 적용>제한적>조건미충족 정렬
  - OSV `affected.ranges.events[fixed]`에서 same-major 패치 버전 자동 추출
  - CWE 한국어 설명 (`_CWE_KO`) 22종 내장
  - 소스코드 자동 관련성 판정 (`_auto_relevance`): WebFlux/RouterFunction/SocketAppender/MultipartFile 등 grep 기반
  - `--publish`: Confluence SCA 페이지 자동 생성/업데이트 (`.env` 자동 로드)
  - `--page-id`: 기존 페이지 업데이트, `--page-title`: 커스텀 제목
  - Output: `state/<prefix>/sca.json` — findings[] + grouped[] 포함
  - 사용법:
    - (fat JAR): `python3 scan_sca.py <src> --jar <jar> --poc --publish -o state/<prefix>/sca.json`
    - (Gradle dep tree): `python3 scan_sca.py <src> --dep-tree state/<prefix>/dep_tree.log --poc --publish -o state/<prefix>/sca.json`
    - (기존 dc 리포트): `python3 scan_sca.py <src> --dc-report <dc.json> --poc --publish -o state/<prefix>/sca.json`

## Phase 3 Orchestration

- `phase3_coordinator.py` (v1.0): Phase 3 LLM 병렬 워커 코디네이터 (비용 추적 + 세이프가드 + 에코 모드)
  - `ThreadPoolExecutor` + `as_completed` 병렬 실행: 최대 N개 워커 동시 실행 (기본 3)
  - **Rate Limit 방어**: `retry_with_backoff` 데코레이터 — 429/rate_limit 감지 시 지수 백오프(2s→32s) + 0.5~1.5s 지터, 최대 5회. 그 외 오류 즉시 Fail-fast.
  - **토큰 수집**: 각 워커의 `input_tokens`, `output_tokens`, `cache_read_input_tokens`를 `UsageMetrics` 데이터클래스로 추적. 모델별 단가표(Sonnet/Opus/Haiku) 내장.
  - **세이프가드**: `SessionSafeguard` — `hourly_rate = 누적비용 / 경과시간` 계산. `hourly_rate × 5hr > 세션예산` 또는 `주간 누적 + 예상 > 주간한도` 시 대기 중 워커 즉시 취소.
  - **에코 모드**: `hourly_rate > 세션예산 × 0.8 / 5hr` 이면 자동 활성화. 컨텍스트 압축 임계값 80,000 → 40,000 토큰으로 축소.
  - **효율성 리포트**: `state/<prefix>/usage_summary.json` — 총 토큰/캐시 적중률/태스크별 비용/hourly_rate/에코 모드 발동 여부.
  - `state/weekly_usage.json` 누적 갱신 (세션 간 주간 예산 관리).
  - 사용법: `python3 tools/scripts/phase3_coordinator.py --prefix <prefix> --source-dir <src> --tasks injection xss file_handling data_protection sca --session-budget 10.0 --weekly-budget 50.0`
  - 필수 환경변수: `ANTHROPIC_API_KEY` (`.env` 자동 로드)

## Publishing Scripts

- `publish_confluence.py` (v2.0): Confluence Server/DC auto-publishing
  - Markdown → XHTML conversion (with fallback)
  - JSON → XHTML renderers:
    - `_json_to_xhtml_asset()`: task_11 asset identification
    - `_json_to_xhtml_api()`: task_21 standard API inventory
    - `_json_to_xhtml_api_inventory()`: scan_api.py output format
    - `_json_to_xhtml_vuln()`: task_22~25 standard vulnerability findings
    - `_json_to_xhtml_enhanced_injection()`: scan_injection_enhanced.py output format
    - `_json_to_xhtml_final()`: final_report.json
    - `build_sca_xhtml()` (v2, SCA): scan_sca_gradle_tree.py / scan_sca.py 출력 렌더링 (`_json_to_xhtml_sca_v2` 위임)
      - findings 목록, CVE 상세, 관련성 판정, LLM 보완 findings (supplemental_sources) 자동 병합
  - Auto-detection: `endpoint_diagnoses` key → enhanced injection, `endpoints` key → api_inventory
  - `confluence_page_map.json`으로 페이지 구조 관리 (`supplemental_sources` LLM 보완 findings 자동 병합)


## Notes

- Task outputs must include `metadata.source_repo_url`, `metadata.source_repo_path`, `metadata.source_modules`.
- `generate_finding_report.py` 실행 시 `--source-label` 필수.
  - Confluence(md2cf) 업로드 시 `--anchor-style md2cf` 사용.
  - Confluence 앵커 링크는 **헤더 텍스트 기반 자동 앵커**가 가장 안정적임.
    - `finding-<id>` 형태의 헤더를 출력하고, 실제 취약점 제목은 별도 텍스트로 표시.
    - 링크는 `#finding-<id>` 형태로 생성.
