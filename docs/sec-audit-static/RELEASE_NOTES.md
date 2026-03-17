# Release Notes — sec-audit-static

> 이 파일은 `skills/sec-audit-static/` + `tools/scripts/` 전체 변경 이력을 관리합니다.
> 버전 형식: `sec-audit-static vMAJOR.MINOR.PATCH` (통합 SemVer)
> - MAJOR: 아키텍처/진단 엔진 전면 개편
> - MINOR: 신규 Phase 추가 / 주요 기능 / 신규 스캐너 도입
> - PATCH: 버그 수정 / 설정 변경
>
> 각 릴리즈 내 세부 스크립트 버전은 항목 안에 명시됩니다.

---

## [v4.13.0] - 2026-03-17

### Added — OCB WebView API (OCBWEBVIEW) 정적 진단 완료

- **대상**: `http://code.skplanet.com/scm/ocbwebview/ocb-webview-api.git` (commit 197f89f)
- **규모**: 1305 소스파일, 562 API 엔드포인트 (240 인증, 322 공개)
- **Confluence**: 테스트28 — 보고서 page_id: 741055787

#### 주요 취약점 확정 (취약 12건 / 정보 6건)

| 카테고리 | ID | 심각도 | 제목 |
|---|---|---|---|
| XSS | XSS-KCP-001 | High | KCP 결제 JSP JavaScript 컨텍스트 Open Redirect + XSS |
| XSS | XSS-KCP-002 | High | KCP 결제 JSP HTML Attribute/JavaScript XSS |
| XSS | XSS-FILTER-001 | Medium | 서블릿 레벨 전역 XSS 필터 미적용 (form-urlencoded) |
| File | FILE-UPLOAD-001 | Medium | 파일 업로드 MIME 타입 서버사이드 검증 미적용 |
| Data | DATA-SEC-001 | Critical | 운영 DB 자격증명 평문 — application-real.properties |
| Data | DATA-SEC-002 | Critical | 운영 API 키 평문 — real/config.properties (KCP/KakaoPay/NaverPay/KB) |
| Data | DATA-SEC-003 | High | ALP DB 자격증명 평문 — application-alp.properties |
| Data | DATA-SEC-004 | High | ALP API 키 평문 — alp/config.properties |
| Data | DATA-SEC-005/006 | Medium | dev 환경 자격증명/API 키 평문 (13건) |
| Data | DATA-SEC-007/008/009 | Medium | local/공통 자격증명/API 키 평문 (14건) |
| Data | DATA-LOG-001 | Critical | 운영 로그 PII 평문 출력 68건 (60+ 파일) |
| Injection | INJ-001 | Info | SpEL FP (RedisCacheAspect 어노테이션 상수) |

#### 진단 이슈 노트

- `Map<String,String>` 제네릭 타입이 XHTML 파싱 오류 유발 → `Map[String,String]`으로 escaping 처리 후 재게시
- file_upload Critical→Medium 하향: NFS 외부 스토리지 + .webp 화이트리스트 + UUID 파일명 확인

---

## [v4.12.0] - 2026-03-16

### Added — scan_data_protection.py v1.3.0: 3종 탐지 보완

#### [보완 1] Base64 인코딩 시크릿 탐지 추가

- `_S_BASE64_SECRET_NAMES_RE`: `hmacKey`, `authKey`, `signingKey`, `clientKey`, `encryptKey`, `base64Secret` 등 기존 미커버 변수명 컨텍스트 + 24자 이상 Base64 패턴
- `_S_BASE64_CHARS_RE`: `+`/`/`/`=` 포함 여부 2차 필터 (단순 alphanumeric 제외, 기존 `_S_GENERIC_SECRET_RE`와 중복 방지)
- 기존 JWT/AWS 패턴이 탐지한 줄은 `already_flagged_lines` 집합으로 중복 skip

#### [보완 2] 하드코딩 IV(초기화 벡터) 탐지 추가 (CWE-329)

- Pattern A `_C_IV_STRING_RE`: `new IvParameterSpec("literal".getBytes())` → High
- Pattern B `_C_IV_BYTES_INLINE_RE`: `new IvParameterSpec(new byte[]{0x00,...})` → High
  - `_C_IV_NUMERIC_VALS_RE`로 배열 내 숫자 리터럴 유무 확인(메서드 호출 결과 FP 방지)
- Pattern C: `static final byte[] IV = {...}` 상수 선언 + `IvParameterSpec(IV)` 참조 2-pass → Medium (needs_review: true)
- `_C_SECURE_RANDOM_IV_RE`: SecureRandom 기반 IV 생성 파일 전체 skip (안전)

#### [보완 3] Lombok @ToString PII 노출 탐지 추가 (CWE-532)

- `scan_toString_exposure()` 신규 함수 (category: DTO_EXPOSURE, severity: Medium)
- 탐지 대상: `@ToString` / `@Data` / `@Value` (Lombok) 사용 클래스에 PII 필드 존재 + exclude 미처리
- FP 방지:
  - `@ToString(onlyExplicitlyIncluded = true)` → 클래스 전체 양호
  - `@ToString(exclude = {"fieldName"})` → 해당 필드 양호
  - 필드 레벨 `@ToString.Exclude` → 해당 필드 양호
- `--skip tostring` 옵션 추가

---

## [v4.11.1] - 2026-03-16

### Fixed — task_25 LLM 프롬프트 정합성 수정 (v1.3.1)

#### skills/sec-audit-static/references/task_prompts/task_25_data_protection.md

- **Step 5 케이스 A 강화**: `src/main/java/` 경로 findings에 `needs_review: true` 남기는 문제 방지
  - `"Critical 상향 권고"` → `"케이스 A 자동 확정: severity Critical, needs_review: false 강제"` 로 변경
  - `src/main/kotlin/` 경로도 명시적으로 추가
  - 경고 박스 추가: `src/main/java` 경로에 `needs_review: true` 절대 금지
- **Step 6 low 버킷 severity 수정**: `Info` → `Medium` (v4.9.5 스크립트 기준 반영)
  - scan_data_protection.py v4.9.5에서 debug/trace → Medium(Risk 3)으로 변경됐으나 프롬프트에 미반영된 불일치 해소

#### docs/sec-audit-static/task-25_data-protection.md

- HARDCODED_SECRET 예시표: DATA-SEC-001(운영 Java/Kotlin 소스) `High` → `Critical`
- SENSITIVE_LOGGING 예시표: DATA-LOG-002 `Info` → `Medium`
- Step 6 Flowchart 노드: `Critical 1건 + Info 1건` → `Critical 1건 + Medium 1건`
- 예시 JSON: DATA-SEC-001 `severity: High` → `Critical`, `manual_review_note` 자동 확정 문구

#### state/ocb_sugar_stage_task25_llm.json

- DATA-SEC-001: `severity: High` → `Critical`, `needs_review: true` → `false`, manual_review_note 확정 문구
- DATA-LOG-002: `severity: Info` → `Medium`
- `admin_page_separation`: `"미확인"` → `"미분리"` 확정 (0312 실행본 근거 반영)

---

## [v4.11.0] - 2026-03-13

### Added — T-01: 보고서 상단 서비스 설명 + 자산 구조 표 자동 삽입

#### generate_finding_report.py — `--asset-info` 옵션 신규 추가

- `--asset-info state/<prefix>_task11.json` 옵션 전달 시 보고서 상단에 자동 삽입:
  - **1.1 서비스 정보** 표: 서비스 설명, 용도, 프레임워크, 기술 스택, 레포, 담당자(기획/개발)
  - **1.2 자산 구조** 표: 환경(상용/개발/알파)별 도메인, 포트, 노출 범위
  - asset-info 있으면 기존 섹션 번호(1.1/1.2) → 1.3/1.4로 동적 조정 (충돌 방지)
- 옵션 미전달 시 기존 동작 완전 유지 (하위 호환)
- `task_11_result.json` 스키마: `findings[].asset_type`, `domain`, `ip`, `tech_stack`, `framework` 등 활용

#### skills/sec-audit-static/references/workflow.md

- Phase 4 섹션에 `[권장] --asset-info state/<prefix>_task11.json` 사용법 추가

#### skills/sec-audit-static/references/task_prompts/task_11_asset_identification.md

- "Phase 4 보고서 연계" 섹션 신규 추가: `--asset-info` 사용 예시 및 삽입 내용 명세

---

### Added — T-09: Bitbucket 소스코드 자동 다운로드 파이프라인

#### tools/scripts/fetch_bitbucket.py (신규)

- WSL2 환경에서 PowerShell 경유로 사내망 Bitbucket(`code.skplanet.com`) 접근
- 주요 기능:
  - `--list-projects` / `--list-repos`: 접근 가능 프로젝트·repo 목록 출력
  - `--project` / `--repo`: 프로젝트 전체 또는 특정 repo만 clone
  - `--branch`: 브랜치 지정 (미지정 시 기본 브랜치 자동 감지)
  - `--shallow`: `--depth 1` shallow clone (빠른 다운로드)
  - `--dry-run`: 실제 clone 없이 대상 목록만 출력
- 인증: `CUSTOMER_BB_TOKEN` (계정 단위 HTTP Access Token, `.env`에서 로드)
  - 계정 단위 토큰 발급: `http://code.skplanet.com/plugins/servlet/access-tokens/manage`
  - 300+ 프로젝트 접근 가능 확인
- 결과: `state/<prefix>_fetch_manifest.json` (총계 + repo별 상태/커밋 기록)
- WSL 경로 변환: `_wsl_to_unc()` → `//wsl.localhost/Ubuntu/...` UNC 경로로 Windows git 경유 clone

---

### Changed — Confluence page_map.json 구조 개편 (테스트 1-20 → old 하위)

- 테스트 목록 하위 테스트1~20 페이지를 "old" 그룹(`page_id: 739228158`) 하위로 이동
- 향후 게시 시 테스트 1-20은 항상 old 하위에 위치하도록 `groups` 중첩 구조 반영

---

## [v4.10.1] - 2026-03-12

### Added — Task 2-5 데이터보호 진단 병합/고도화 절차 공식화

#### task_25_data_protection.md (LLM 태스크 프롬프트) — Step 5/6 신규 추가

- **Step 5: HARDCODED_SECRET 파일/환경 단위 병합** 지침 추가
  - 5개 환경 계층 병합 기준표 (운영 코드 → Critical, `resources/` → High, ccalp → High, ccdev → Medium, local → Low)
  - 운영 자격증명 확정 조건: 'real' 접미사, `IS_DEBUG=false` 분기, `src/main/resources/` 경로
  - 동일 파일 내 다수 라인 → 1 finding + `lines` 배열 나열
- **Step 6: SENSITIVE_LOGGING 심각도 단위 병합** 지침 추가
  - `info/warn/error/fatal` 버킷 → `DATA-LOG-001` Critical 1건으로 통합
  - `debug/trace` 버킷 → `DATA-LOG-002` Info 1건으로 통합
  - **FP 컨설턴트 노트 기재 기준** 명시: Kotlin 문자열 보간, 로그 문자열 내 PII 키워드 포함 케이스
  - 대응 방안: MaskingUtils.mask() 즉시 조치 + Logback MessageConverter 전역 마스킹 근본 조치
- **출력 형식 전면 개정**: 병합 finding 구조, ID 명명 규칙 (`DATA-SEC-NNN`, `DATA-LOG-001/002`), `consolidation_note` 필드
- 컨텍스트 업데이트: Step 5/6 명시

#### docs/sec-audit-static/task-25_data-protection.md — v1.3.0

- Flowchart에 Step 5/6 병합 노드 추가 (`task25_llm.json`이 병합·확정 전체 출력임 명시)
- 산출물 구조 분리: `task25.json` = 수정 금지 증적 보존 / `task25_llm.json` = Confluence 게시 소스
- HARDCODED_SECRET 23→8건, SENSITIVE_LOGGING 197→2건 병합 결과 대응표 추가
- 예시 JSON: `consolidation_note`, `data_protection_assessment` 통계 필드 포함

#### 테스트19 OCB Sugar Stage — task25_llm.json 병합 갱신

- HARDCODED_SECRET 23건 → 8건 (DATA-SEC-001~008) 파일/환경 단위 통합
- SENSITIVE_LOGGING 197건 → 2건 (DATA-LOG-001 Critical 117건, DATA-LOG-002 Info 80건)
- FP 컨설턴트 노트: InternalNbtAdisonController.kt:61 Kotlin 코드 FP 가능성 명시
- `consolidation_note` + `data_protection_assessment` 통계 필드 포함

---

## [v4.10.0] - 2026-03-11

### Fixed/Added — scan_xss.py: Persistent XSS 판정 로직 수정 + P1/P2 고도화

#### Persistent XSS 판정 로직 근본 수정

- **오류**: REST/JSON 반환타입("브라우저가 JSON을 파싱하지 않음")을 Stored XSS 차단 근거로 잘못 적용
- **수정**: Stored XSS 위험은 데이터 저장 여부와 렌더링 컨텍스트의 함수 — 응답 타입은 무관
- **2계층 DB 쓰기 분석** 도입:
  - Phase 1: Controller 레벨 `.insert/.update/.save/.merge/.delete/.persist/.modify` 패턴 → 144건 취약 확정
  - Phase 2: Service 레벨 의존성 추적 (Kotlin `val fieldName: ServiceType`, Java `private ServiceType name`) → 47건 추가 확정
  - 총 191건 취약 확정, 30건 정보 유지 (Feign/RestTemplate/Kafka 정적 분석 한계 명시)

#### P1: 전역 XSS 필터 결함 탐지 3종 신규

- `_P3_FAILOPEN_RE`: `.orElse(true)` Fail-Open 패턴 탐지 (기본값이 필터 비활성화)
- `_count_blacklist_items()`: `Arrays.asList` 내 항목 수 집계 → 8개 미만 시 불충분한 블랙리스트 판정
- `_getinputstream_missing_filter()`: `getInputStream()` 오버라이드 메서드 바디에 `cleanXss` 계열 호출 부재 탐지
- `build_global_filter_status()`: 3종 결함 집계 → `custom_filter_info` 에 `failopen_files`, `insufficient_blacklist_files`, `getinputstream_no_filter` 필드 추가
- `check_persistent_xss()`: `custom_wrapper` 레벨에서 결함 발견 시 `정보 → 취약` 자동 상향

#### P2: HTML_VIEW 오탐 제거

- `_P1_PROTO_API_RT_RE` 확장: DTO/Response/VO suffix 타입 + List/Map/Collection 베이스 타입 패턴 추가
- `@RequestBody` 파라미터 탐지 (`has_request_body_param`): `@Controller` 메서드에서 `@RequestBody`가 있으면 REST_JSON으로 강제 분류

---

## [v4.9.6] - 2026-03-11

### Fixed — Confluence 앵커 링크 수정

#### generate_finding_report.py — md2cf 모드 앵커 토큰 누락 버그

- `_anchor()` 함수: md2cf 분기에서 `""` 반환하던 버그 수정 → `[[ANCHOR:name]]` 반환
- `generate_summary_table()` md2cf 분기: 요약 테이블 헤딩 앞 `[[ANCHOR:summary-table]]` 추가
- Finding 상세 루프 md2cf 분기: 각 finding 헤딩 앞 `[[ANCHOR:finding-{id}]]` 추가
- `generate_instance_appendix()` md2cf 분기: 부록 헤딩 앞 `[[ANCHOR:appendix-instances]]` 추가

#### publish_confluence.py — 인페이지 앵커 링크 Confluence 포맷 변환

- `_postprocess_anchor_links()` 함수 신규 추가
  - `<a href="#anchor-name">text</a>` → `<ac:link ac:anchor="anchor-name"><ac:plain-text-link-body><![CDATA[text]]></ac:plain-text-link-body></ac:link>` 변환
  - Confluence Server/DC에서 `<a href="#...">` 는 인페이지 스크롤을 지원하지 않음 — Confluence 전용 링크 매크로 필요
- postprocessing 파이프라인에 `_postprocess_anchor_links()` 단계 추가

---

## [v4.9.5] - 2026-03-09

### Changed — 전체 프로젝트 severity 공식 등급 표준화

### Changed — 전체 프로젝트 severity 공식 등급 표준화

사내 공식 취약점 등급 기준서(Risk 1~5)를 기준으로 모든 스크립트 및 문서의 severity 값을 일괄 수정.

#### scan_data_protection.py v1.2.0

| 카테고리 | 항목 | 변경 전 | 변경 후 |
|---------|------|---------|---------|
| SENSITIVE_LOGGING | info/fatal 레벨 취약 | `High` | `Critical` (Risk 5) |
| SENSITIVE_LOGGING | debug/trace 레벨 정보 | `Low` | `Medium` (Risk 3) |
| WEAK_CRYPTO | MD5/SHA-1/DES/RC4/ECB | `High` | `Medium` (Risk 3) |
| JWT_INCOMPLETE | parseUnsecuredClaims() | `High` | `Critical` (Risk 5) |
| JWT_INCOMPLETE | JWT 서명 키 미설정 파서 | `High` | `Critical` (Risk 5) |
| CORS_MISCONFIG | allowedOrigins(*)+allowCredentials | `High` | `Medium` (Risk 3) |
| CORS_MISCONFIG | Origin 헤더 그대로 반영 | `High` | `Medium` (Risk 3) |

*(NoOpPasswordEncoder Critical, HARDCODED_SECRET AWS/GCP Critical, DB PW High, JWT Secret High 유지)*

#### scan_injection_enhanced.py — severity 자동 산출 추가

- `_judgment_to_severity()` 헬퍼 함수 신규 추가
  - `[실제]` SQL Injection → `Risk 5` (Critical)
  - `[잠재]` SQL Injection → `Risk 4` (High)
  - 양호/정보 → `Risk 2` (Low)
- `EndpointDiagnosis` 생성 시 `severity=_judgment_to_severity(judgment)` 자동 반영
- OS Command Injection / SSI Injection findings에 `"severity": "Risk 5"` 추가

#### scan_file_processing.py

| 카테고리 | 항목 | 변경 전 | 변경 후 |
|---------|------|---------|---------|
| UPLOAD | UUID+ExtWL 모두 미적용 (웹쉘 위험) | `High` | `Critical` (Risk 5) |
| UPLOAD | 일부 검증 미흡 (정보) | `Low` | `Medium` (Risk 3) |
| DOWNLOAD | Path Traversal / LFI | `High` | `Critical` (Risk 5) |
| RFI/SSRF | URL Whitelist 미확인 | `High` | `High` (Risk 4, 유지) |

#### 문서 갱신

- `skills/sec-audit-static/references/severity_criteria.md` — 공식 등급 정의 + 취약점별 매핑 테이블 전면 재작성
- `docs/sec-audit-static/task-22_injection.md` — 산출물 severity 예시 Risk 4→5
- `docs/sec-audit-static/task-24_file-handling.md` — 산출물 severity 예시 High→Critical
- `docs/sec-audit-static/task-25_data-protection.md` — 카테고리 테이블 Risk 등급 컬럼 추가, 흐름도 severity 값 갱신

---

### Fixed — scan_data_protection.py v1.1.0

#### 작업 1 — SENSITIVE_LOGGING 정밀도 및 가독성 향상

- **로그 레벨 기반 심각도 차등화** 신규 적용
  - `log.info/warn/error/fatal` + PII 변수 → `result: "취약"`, `severity: "Critical"` (상용 환경 노출 위험)
  - `log.debug/trace` + PII 변수 → `result: "정보"`, `severity: "Medium"` (개발/검증계 노출 위험)
- **파일 단위 그룹화(Grouping)** 신규 적용
  - 동일 파일 내 복수 로그 취약점 → 파일당 1개 Finding으로 병합
  - `evidence.vulnerable_lines[]` 배열에 해당 라인 번호 전체 기록
  - 900건 이상 탐지 건수 폭증 방지
- 신규 정규식: `_L_LOG_PII_HIGH_RE`, `_L_LOG_PII_LOW_RE`, `_L_LOG_PARAM_BIND_HIGH_RE`, `_L_LOG_PARAM_BIND_LOW_RE`
- `collections.defaultdict` import 추가

#### 작업 2 — JWT_INCOMPLETE 알고리즘 none 오탐 제거 확인

- `scan_jwt_issues()` 내 JWT import 체크 (`_J_JWT_IMPORT_RE`) 기존 구현 확인 완료 (추가 변경 없음)

#### 작업 3 — .properties/.yml 평문 시크릿 탐지 개선

- `_S_PROP_PASS_RE` 정규식 개선: `token` 키워드 추가, YAML 앵커(`&/*`) 제외, 빈 값 제외 강화
- `_iter_props()` 확장: `application*.properties` → `*.properties`, `*.yml`, `*.yaml` 전체

#### 작업 4 — WEAK_CRYPTO 룰셋 조정

- `_C_WEAK_CIPHER_RE`에 `SEED/ECB` 패턴 추가 (국산 암호화 미탐 방지)
- `RSA/ECB/OAEPPadding` 및 `RSA/ECB/OAEPWith...` 제외 확인 주석 명시 (`(?!OAEP)` 룩어헤드)

---

### Fixed — scan_injection_enhanced.py — result/severity 필드 누락 버그

- `scan_global_patterns()` 반환값에서 `os_command_injection.findings[]` 및 `ssi_injection.findings[]` 각 항목에 `result`/`severity` 필드 누락 버그 수정
- `asdict(f)` → `{**asdict(f), "result": "정보", "severity": "Risk 5"}` 로 변경 (두 섹션 모두)
- 통계 집계 및 merge_results.py 처리 시 result/severity 필드 누락 방지

---

### Added — docs/sec-audit-static/ 문서 저장소 신규 생성

- `docs/sec-audit-static/README.md`: 전체 워크플로 Mermaid 다이어그램 + 컴포넌트 위치 + 갱신 규칙
- `docs/sec-audit-static/RELEASE_NOTES.md`: 통합 버전 이력 (이 파일)
- `docs/sec-audit-static/task-11_asset-identification.md`
- `docs/sec-audit-static/task-21_api-inventory.md`
- `docs/sec-audit-static/task-22_injection.md`
- `docs/sec-audit-static/task-23_xss.md`
- `docs/sec-audit-static/task-24_file-handling.md`
- `docs/sec-audit-static/task-25_data-protection.md`
- `docs/sec-audit-static/phase-4_reporting.md`

---

## [v4.9.4] - 2026-03-06

### Chore — 미사용 파일 정리 (17개 삭제)

#### docs/ 구세대 절차 문서 전체 제거 (10개)

`skills/` 기반 워크플로 이전 전 작성된 단계별 절차 문서가 `task_prompts/` + `workflow.md`로 완전히 대체됨을 확인하고 삭제.

- `docs/00_overview.md`, `PLAYBOOK_GUIDE.md`
- `docs/10_asset_identification.md` ~ `25_data_protection_review.md` (5개)
- `docs/20_static_analysis.md`, `21_api_inventory.md`
- `docs/ANALYSIS_REPORT_INJECTION_XSS.md` (2026-03-04 스크립트 분석 보고서 — 내용 반영 완료)

#### references/ 미참조 파일 제거 (2개)

전체 프로젝트에서 참조 없음 확인 후 삭제.

- `skills/sec-audit-static/references/static_sources.md` — `SKILL.md` Resources 섹션으로 대체됨
- `skills/sec-audit-static/references/task_prompts/task_23_xss_report_format.md` — `task_23_xss_review.md` 미연동

#### tools/scripts/ 사실상 미사용 스크립트 제거 (4개) + static_scripts.md 정리

- `extract_endpoints_rg.py` / `extract_endpoints_treesitter.py` — `scan_api.py` v3.2로 대체됨
- `migrate_test_groups.py` / `rename_remove_prefix.py` — 일회성 마이그레이션 유틸

**결과:** `docs/`에 `정책보고서.md` 1개만 잔존. `tools/scripts/`는 워크플로 실운용 스크립트만 유지.

---

## [v4.9.3] - 2026-03-06

### Fixed — scan_injection_enhanced.py: iBatis 누락 버그 + DTO Taint 단절 해결

#### 수정 1 — `build_mybatis_index()`: iBatis `<sqlMap>` 파일 완전 누락 버그 수정

- **버그 1** (Quick filter): `"<sqlMap " not in content` → 속성 없는 `<sqlMap>` 태그 (`<sqlMap>`) 스킵 → `re.search(r'<(?:sqlMap|mapper)[\s>]', content)` 로 교체
- **버그 2** (Namespace fallback): 빈 namespace 시 `continue` → `xml_file.stem`을 pseudo-namespace로 사용, `ibatis_no_namespace=True` 플래그로 FQN 중복 등록 방지
- **효과**: 구형 iBatis 프로젝트 XML 매핑 전량 인식

#### 수정 2 — `_propagate_taint_by_index()`: DTO 래핑 시 Taint 단절 해결

- **Strategy 1** (기존 유지): 인수 내 `\b{taint_var}\b` 단어 경계 탐지
- **Strategy 2** (신규): `\b{taint_var}\.` DTO 접근자 패턴 탐지 (`t.getXxx()`, `t.field`)
- `conservative_fallback: bool = False` 파라미터 추가 → Service→Repository 호출 시 `True` 설정으로 taint 보존
- **효과**: `new XxxRequest(param)` 래핑 케이스에서 taint 흐름 단절 방지

#### 수정 3 — `manual_review_prompt.md`: SQL Injection Taint 역추적 진단 프롬프트 추가

`db_operations` 비어 있거나 `access_type=unknown` 항목에 대한 LLM 역추적 지시문:
- **역추적 우선순위 1**: DTO/Map 파라미터 래핑 확인 (a~d 단계)
- **역추적 우선순위 2**: SQL ID 동적 생성 3가지 위험 패턴
- 입력/출력 형식 + `taint_path` 필드 JSON 스키마

---

## [v4.9.2] - 2026-03-06

### Fixed — scan_injection_enhanced.py: @Query 파싱 완성 + QueryDSL stringTemplate() 세분화

#### @Query 어노테이션 전체 인수 파싱

- **이전**: `"..."` 첫 번째 문자열 리터럴만 캡처 → `+` 연결이 따옴표 밖에 있으면 탐지 불가
- **이후**: `(?:[^)"]|"(?:[^"\\]|\\.)*")*` 패턴으로 전체 어노테이션 인수 캡처
- `nativeQuery=true` 속성 탐지 → `diagnosis_type`에 JDBC native SQL 명시
- `?\d*` → `?\d+` 수정 (positional param `?1` 정확 탐지)
- `"..." + var` / `var + "..."` 패턴만 취약 판정 (`:param`, `?1` 있으면 안전)

#### QueryDSL `Expressions.stringTemplate()` 세분화

- **이전**: `stringTemplate()` 호출 모두 취약 판정
- **이후**: `_ST_CONCAT_RE`로 첫 번째 인수에 `+` 직접 연결 여부 확인
  - `"template" + var` → **취약** (`raw_concat`)
  - `{0}` / `{1}` 플레이스홀더 → **양호** (PreparedStatement 바인딩)

---

## [v4.9.1] - 2026-03-06

### Fixed — scan_injection_enhanced.py: MyBatis `<include>` 인라인 치환 로직 전면 재작성

#### `_resolve_sql_text()` 신규 함수

이전 방식(append-at-end)은 `<include>` 위치 정보를 무시하여 SQL 구조 왜곡 발생.
재귀 트리 워커로 대체하여 정확한 인라인 치환 수행.

- `<sql id="...">` 태그를 Element 객체로 `sql_fragments` 딕셔너리에 저장 (Phase A)
- DML 파싱 시 `_resolve_sql_text()` 호출로 `<include refid="...">` 정확 위치 치환 (Phase B)
- Namespace 한정 refid (`ns.fragId`) 및 단순 ID 동시 지원
- `frozenset visited` + `depth > 10` 가드로 순환 참조 및 무한 재귀 방지
- 중첩 include (`<include>` 내부의 또 다른 `<include>`) 정확 처리

---

## [v4.9.0] - 2026-03-06

### Fixed — scan_injection_enhanced.py: P1/P2 "정보" 판정 고도화 (외부 의존성 + XML 미발견 감소)

#### P2 — HTTP 클라이언트 패턴 탐지 (신규 `http_client` access_type)

Phase 13 (외부 모듈 서비스 미발견) 판정 시, Controller 메서드 본문 및 클래스 전체에서
`RestTemplate`, `WebClient`, `FeignClient`, `HttpClient`, `OkHttpClient` 등 HTTP 클라이언트 패턴을 탐지합니다.

- 탐지 시 → `access_type="http_client"` → `_assess_op()` priority=0 → **양호**
- 미탐지 시 → 기존 `external_module` → **정보 (수동 확인 필요)**

#### P2 — 비DB 서비스명 패턴 (`_NON_DB_SERVICE_RE`) 추가

`Push|Notification|Email|Sms|Redis|Cache|Kafka|Fcm|Apns|Scheduler` 등 DB 접근 불필요한
클래스명 패턴을 탐지하여 `access_type="none"` → **양호**로 확정.

#### P1 — `@Mapper` 어노테이션 기반 양호 확정

Phase 10/18 XML 미발견 시, `@Mapper` 어노테이션이 있고 `${}` 패턴이 파일에 없으면
`"추정"` 없이 **양호 확정** (needs_review=False). 개선 전 "정보"로 처리되던 항목 감소.

**예상 효과 (msgsugar_new_ 기준):**

| 분류 | 개선 전 | 개선 후 |
|---|---|---|
| 정보 (외부 의존성) | 95건 | ~20건 |
| 정보 (XML 미발견) | 76건 | ~36건 |
| 합계 정보 | 171건 | **~56건** (67% 감소) |

---

### Fixed — scan_data_protection.py v1.1.0: 주요 FP 3종 수정

#### [L] SENSITIVE_LOGGING 단어 경계 오탐 수정 (927건 → 대폭 감소)

`_L_LOG_PII_RE` 패턴에 `(?<!\w)` 음성 룩비하인드 추가.
`mbrCi`, `mbrDi`, `userCi` 등 접미사 패턴에서 `ci`/`di`가 오탐되던 문제 해결.

#### [J] JWT_INCOMPLETE FP 수정 (20건 → 0건 예상)

- `_J_ALG_NONE_RE`: `.orElse("none")` 패턴 오탐 수정 — `.algorithm("none")` 메서드 체인으로 한정
- `scan_jwt_issues()`: JWT 라이브러리 import 없는 파일 자동 제외 필터 추가 (`_J_JWT_IMPORT_RE`)

#### [C] WEAK_CRYPTO RSA/ECB/OAEP FP 수정

`_C_WEAK_CIPHER_RE`: `RSA/ECB/OAEPWith...` 패턴에 부정 룩어헤드 `(?!OAEP)` 추가.
OAEP 패딩은 RSA 암호화에서 안전하므로 취약으로 분류하지 않음.

---

## [v4.8.0] - 2026-03-05

### Added — scan_data_protection.py v1.0.0: Task 2-5 데이터 보호 전용 스캐너 신규

Task 2-5가 기존 LLM 수동 분석 방식에서 **Python 자동화 스캐너 + LLM 보조 분석** 구조로 전환됩니다.

#### 7개 진단 모듈

| 모듈 | 대상 | CWE |
|---|---|---|
| `HARDCODED_SECRET` | AWS 자격증명(AKIA 패턴), GCP private_key, JWT Secret, DB 비밀번호 하드코딩 | CWE-798 |
| `SENSITIVE_LOGGING` | 주민번호·전화번호·카드번호·이메일·비밀번호 직접 로깅 | CWE-532 |
| `WEAK_CRYPTO` | MD5·SHA-1 해시, DES·3DES·RC4·AES/ECB 암호화 | CWE-327 |
| `JWT_ISSUE` | `parseUnsecuredClaims()`, `SignatureAlgorithm.NONE`, 취약 Secret Key | CWE-347 |
| `DTO_EXPOSURE` | 응답 DTO 민감 필드(`@JsonIgnore` 미적용) — API 인벤토리 연계 | CWE-200 |
| `CORS_MISCONFIGURATION` | `allowedOrigins("*")`, Origin 헤더 직접 반영, `@CrossOrigin` 무제한 | CWE-942 |
| `SECURITY_HEADER` | `.headers().disable()`, CSRF 비활성화, Clickjacking 보호 미설정 | CWE-693 |

#### 핵심 설계

- **오탐 감소**: 네거티브 룩어헤드(`(?!.*\$\{)`) + `@Value`/`System.getenv` 안전 참조 필터
- **테스트 코드 분리**: `_is_test_file()` — test/spec/mock 경로 자동 감지 → Critical → Info 하향
- **API 인벤토리 연계**: `response_dto_names` 세트로 실제 응답 DTO 우선 분석
- **needs_review 플래그**: 자동 판정 한계 항목 → `manual_review_prompt.md` 케이스 A/B/C 수동 판단

```bash
python tools/scripts/scan_data_protection.py <source_dir> \
    --api-inventory state/<prefix>_api_inventory.json \
    -o state/<prefix>_task25.json \
    [--skip secret logging]  # 특정 모듈 제외
```

#### manual_review_prompt.md: Task 2-5 수동 판단 케이스 3종 추가

- **케이스 A** — 하드코딩 시크릿: Prod 키 vs. 테스트 더미 판별 (8가지 증거 테이블)
- **케이스 B** — 민감정보 로깅: MaskingUtils 래핑 여부 검증 (6가지 패턴 판정)
- **케이스 C** — 커스텀 암호화 유틸: AES/GCM·SecureRandom IV·PBKDF2 키 파생 안전성 체크리스트

#### 연관 문서 업데이트

- `workflow.md`: Task 2-5 스크립트 실행 단계(4d) 추가, Phase 3-2 수동 판단 케이스 명시
- `task_prompts/task_25_data_protection.md`: 자동 스캔 결과 연계 + LLM 보조 분석 구조로 전면 개편
- `docs/25_data_protection_review.md`: 7개 모듈·CLI 사용법·업데이트된 판정 기준 반영

---

## [v4.7.2] - 2026-03-05

### Changed — scan_xss.py v2.4.0: FP 제거 + 커스텀 필터 탐지 + View XSS 프롬프트

#### Step 1: Reflected XSS Taint Flow 검증 (`check_reflected_xss_taint` 신규)
- `REST_HTML_RISK` 컨트롤러에서 HTTP 파라미터 → HTML 출력 Taint Flow 3단계 검증
  1. 파라미터 변수명 추출 (`_P1_TAINT_PARAM_EXTRACT`)
  2. HTML 안전 인코딩 함수 존재 시 Taint 해제 (`_P1_ESCAPE_SAFE_RE`)
  3. `return`/`write` 구문의 tainted 변수 연결 탐지 (`_P1_TAINT_CONCAT_RE`)
- 판정: `taint_confirmed` → 취약 / `has_escape` → 양호 / 미확인 → 정보

#### Step 2: DOM XSS 라이브러리 파일 제외 (`_P6_DOM_EXCLUDE_RE`)
- `jquery`, `bootstrap`, `vendors`, `dist`, `min.js` 경로 패턴 → DOM XSS 스캔 제외
- FP(서드파티 라이브러리 내 `innerHTML` 등) 대폭 감소

#### Step 3: 커스텀 XSS 필터 탐지 (`_P3_CUSTOM_WRAPPER_RE` 등 3종)
- `sanitize`, `escapeHtml`, `xssClean` 커스텀 래퍼 메서드 탐지
- `blacklist.replace(/<|>/g, '')` 블랙리스트 방식 탐지 (우회 가능 → 경고)
- `build_global_filter_status()`: `custom_wrapper` filter_level 추가

#### Step 4: View XSS AI 수동 진단 프롬프트
- `manual_review_prompt.md`에 View XSS 판단 섹션 추가
- Thymeleaf `th:utext` / JSP `<%=` / Freemarker `${...?no_esc}` 우선 확인 기준 포함

---

## [v4.7.1] - 2026-03-04

### Fixed — scan_xss.py v2.3.2: DTO 필드 1레벨 검사 (`_inspect_dto_fields` 신규)
- `@RequestBody` Java record 타입 balanced-parenthesis 파싱
  - 기존 `[^)]+` regex → `@Min(1)` 중첩 괄호에서 파싱 실패 수정
- API inventory `type: "body"` 필드 감지 추가 (`"@RequestBody" in ann` 보완)
- 결과: `ExchangePointsRequestDto`(`Integer goldenEggsCnt` 단일 필드) → 양호 정확 판정

### Verified
- okick-reward: 양호 7 / 취약 3 / 정보 0 (양호+1 개선)
- okick-event: 양호 14 / 취약 5 / 정보 0 (회귀 없음)

---

## [v4.7.0] - 2026-03-03

### Added — scan_xss.py v2.1.0~v2.3.1: XSS 스캐너 신규 및 전면 개편

#### scan_xss.py v2.3.1: publish_confluence.py XSS 보고서 렌더링 전면 개편
- `_simplify_xss_category(ep)`: 카테고리 분류 (Persistent/Reflected/View XSS, Open Redirect 등)
- `_render_xss_ep_detail(ep)`: 엔드포인트 상세 정보 테이블 + 코드 증거
- `_json_to_xhtml_enhanced_xss()` 전면 재작성:
  - 카테고리별 그룹핑 + 대표 케이스 + Expand 매크로
  - DOM XSS 하단 분리
  - XSS 전역 필터 상태 → info/warning 매크로 박스

#### scan_xss.py v2.3.0: SET/WHERE 절 구분 + 헥사고날 아키텍처 구현체 해석
- `_resolve_svc_impl_body()`: UseCase → Service, Port → Adapter 구현체 해석
- `_has_param_in_direct_call()`: repo 호출 인수의 HTTP param standalone 전달 확인
- `_check_repo_param_context()`: SET/WHERE 절 구조 판정 (변수명 무관, 패턴 기반)
  - QueryDSL `.set(col, val)`, JPA `entity.setXxx(val)`, Builder `.field(val)` → "set"
  - `.where(...)` 단독 → "where"
- `_trace_persistent_xss_taint()` 수정: svc_body 폴백 + repo 루프 전면 교체
- `/api/internal/rewards/failure/retry` → 취약(FP) → 양호 정확 판정

#### scan_xss.py v2.2.0: 판정 Regression 수정
- `check_persistent_xss` "잠재" 반환 2곳 → "취약" 변경
- `judge_xss_endpoint` "잠재" 핸들러 → worst-case 강제 (≥ 연산)

#### scan_xss.py v2.1.0: FP 제거 3종
- `_sqli_has_db_write`: jpa_builtin/querydsl_safe → detail에 save/insert/update 키워드 확인
  (기존: access_type만으로 판정 → SELECT QueryDSL도 write 오인 → FP)
- `_check_enum_validation` + `_P5_SANITIZE_PATTERNS`: Enum.from()/Integer.parseInt()/UUID.fromString() taint 해제
- `_has_freetext_params`: Integer/Boolean/UUID/날짜 타입만 있으면 즉시 양호

---

## [v4.6.3] - 2026-02-28

### Fixed — scan_injection_enhanced.py v4.6.3: Call Graph 완성 (5종 버그 수정)
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
- okick-event (19 ep): 양호 19 / 취약 0 / 정보 0 — PASS
- okick-reward (10 ep): 양호 10 / 취약 0 / 정보 0 — PASS

---

## [v4.6.2] - 2026-02-27

### Fixed — scan_injection_enhanced.py v4.6.2: Call Graph Disconnection
- `build_class_index` → `(class_index, impl_index)` 튜플 반환 (구현체 O(1) 조회)
- `_resolve_impl_class(name, class_index, impl_index)` — impl_index 우선 조회
- Phase 17: domain Repository 인터페이스 → JPA 구현체 해석 블록 추가
- Phase 11: `_port_like_fields` 있으면 `[non-DB]` continue 스킵
- Phase 4b: trace_endpoint — Controller private 헬퍼 내 Port 호출 추적
- Phase 17d: `entityManager.persist/merge/remove` → `jpa_builtin` 판정
- Phase 17e: Reflection API + DB indicator 없음 → `none` 판정

---

## [v4.6.1] - 2026-02-26

### Fixed — scan_injection_enhanced.py v4.6.1: `findAllBy` → "DB 미접근" 오분류
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

### Added — publish_confluence.py v4.6.1: main_report 타입 신규
- `_json_to_xhtml_main_report()`: 섹션 1(개요)/8(한계)만 추출, JSON 기반 종합 요약 계산
- `_build_main_summary_table()`: injection/xss JSON에서 수치 계산 (단일 소스)
- `_build_main_api_inventory()`: method/api 또는 http_method/request_mapping 자동 감지
- `confluence_page_map.json`: 테스트13/14 → `"type": "main_report"` + `"task_sources"` 구조

---

## [v4.6.0] - 2026-02-25

### Added — scan_injection_enhanced.py v4.6.0: Phase 17 Hexagonal Architecture (Port & Adapter 패턴) 지원
- `_TRACEABLE_COMPONENT_SUFFIXES`에 `Port` 추가 (13종)
- `extract_constructor_deps`: bean_suffixes에 `Port` 추가
- `analyze_repository_method`: QueryDSL JPAQueryFactory 안전 탐지
  - `queryFactory.` / `JPAQueryFactory.` → `.where().eq()` → PreparedStatement 바인딩 → 양호
  - `Expressions.stringTemplate()` → 취약 판정
- `trace_endpoint`: Domain Repository 인터페이스 → JPA 구현체 해석
- Phase 15 stub regex에 Port/UseCase/Adapter 패턴 추가 (오탐 방지)

---

## [v4.5.2] - 2026-02-24

### Fixed — scan_injection_enhanced.py v4.5.2 / publish_confluence.py
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
- pcona-console (110 ep): 양호 92 / 취약 18(실제16+잠재2) / 정보 0 — PASS
- ocb-community (226 ep): 양호 218 / 취약 6 / 정보 2 — PASS
- msgsugar (598 ep): 양호 485 / 취약 0 / 정보 113 — PASS

---

## [v4.5.1] - 2026-02-24

### Fixed — scan_injection_enhanced.py v4.5.1
- DTO 랩핑 taint 전파 오류
  - `repo_tainted or svc_tainted or None` — empty set 시 name-based 폴백 활성화
  - 영향: `ordering` param이 `CommentGetRequest` DTO에 랩핑된 경우 `[잠재]` → `[실제]` 정확 판정
- Kotlin `${if(expr)}` 복잡 표현식 키워드 오탐
  - `_KT_KEYWORDS` 모듈 상수화 (frozenset)
  - `var_name`이 키워드(`if`)일 때 표현식 전체 비-키워드 식별자 교차 검증

---

## [v4.5.0] - 2026-02-24

### Added — scan_injection_enhanced.py v4.5.0: Phase 24 Positional Index Taint Tracking
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

### Added — scan_injection_enhanced.py v4.4.0 / publish_confluence.py
- Taint Tracking 초기 구현 (변수명 교차 검증)
- `_extract_kt_sql_varname(op)`: Kotlin SQL injection op에서 삽입 변수명 추출
- Worst-Case Override: 모든 db_ops 평가 후 최악 케이스 선택
- `publish_confluence.py`: `_simplify_category()` — 개발자 친화적 카테고리 분류
  - 취약: `[실제 위협] SQL Injection` / `[잠재적 위협] 취약한 쿼리 구조`
  - 정보: `외부 의존성 호출` / `XML 미발견 패턴 추정` / `호출 경로 추적 불가`
  - 양호: `JPA & ORM 방식` / `MyBatis #{} 바인딩` / `DB 미접근 엔드포인트` / `제어 흐름상 안전`

---

## [v4.3.0] - 2026-02-23

### Added — scan_injection_enhanced.py v4.3.0: Phase 23 Kotlin SQL Builder 위임 탐지
- Java Repository → `XxxKt.func()` → Kotlin top-level 함수의 `$var`/`${expr}` SQL 인젝션
- `_analyze_kotlin_sql_builder(method_body, source_dir)`
- 1단계 위임 추적: `return otherFunc()` 패턴
- 지역변수 필터: `var/val` 선언 변수의 `$var` 제외 (false positive 방지)

---

## [v3.5.0] - 2026-02-23

### Added — scan_injection_enhanced.py v3.5.0: Phase 10~16 완성
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
