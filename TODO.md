# TODO — AI-SEC-OPS Playbook

> 진단 자동화 프레임워크 개선 과제 목록입니다.

## 범례

| 상태 | 아이콘 | 설명 |
|------|--------|------|
| 대기 | ⬜ | 미착수 |
| 진행중 | 🔄 | 현재 작업 중 |
| 완료 | ✅ | 작업 완료 |
| 보류 | ⏸ | 외부 의존성/우선순위로 중단 |

| 우선순위 | 아이콘 |
|---------|--------|
| 높음 | 🔴 |
| 보통 | 🟡 |
| 낮음 | 🟢 |

| 복잡도 | 의미 |
|--------|------|
| S | 1~2일 이내 |
| M | 1주 이내 |
| L | 2~4주 |
| XL | 1개월 이상 / 설계 필요 |

---

## 과제 목록

| # | 항목 | 우선순위 | 복잡도 | 상태 | 관련 컴포넌트 | 시작일 | 완료일 | 참고/링크 |
|---|------|---------|--------|------|--------------|--------|--------|-----------|
| T-07 | **Task 2-3~2-5 진단 자동화 고도화**<br>XSS / 파일처리 / 데이터보호 진단을<br>SQL Injection 수준의 자동화로 끌어올림<br>• `scan_xss.py` v2.4.0: ✅ Reflected Taint Flow 검증, DOM 라이브러리 제외, 커스텀 필터 탐지<br>• `scan_file_processing.py` v1.0: ✅ Upload/Download/LFI/RFI 자동 탐지 완성<br>• `scan_data_protection.py` v1.1.0: ✅ CORS/Secrets/JWT/Crypto/Logging 7개 모듈 + FP 3종 수정 | 🔴 | L | ✅ 완료 | `tools/scripts/`<br>`skills/sec-audit-static/references/task_prompts/` | 2026-02-25 | 2026-03-06 | v4.7.0~v4.9.0 |
| T-01 | 보고서 상단에 서비스 설명 및 자산 구조 명시<br>(URL, IP, Repo, 담당자) | 🔴 | M | ⬜ 대기 | `publish_confluence.py`<br>`generate_finding_report.py` | - | - | - |
| T-02 | 보안진단 완료 후 PoC/테스트 코드 자동 생성<br>(JUnit / Fuzz / ZAP 활용, 검증용) | 🔴 | XL | ⬜ 대기 | `scan_injection_enhanced.py`<br>`skills/sec-audit-static/` | - | - | - |
| T-03 | 검증 절차 자동화<br>1차: AI 진단 → 보고서 자동 생성<br>2차: 인력 검토 → Confirm<br>오탐/과탐 체크 워크플로우 | 🔴 | L | ⬜ 대기 | 전체 파이프라인 | - | - | - |
| T-04 | Diff 기반 seed 설정 + RAG 형식 프롬프트 연동<br>(변경된 코드 diff를 RAG로 구성하여 진단 프롬프트에 추가) | 🟡 | L | ⬜ 대기 | `scan_injection_enhanced.py`<br>`skills/` 프롬프트 | - | - | [참고: hoyeon](https://github.com/team-attention/hoyeon) |
| T-05 | Redis / 파일 DB (Elasticsearch 등) 대상 진단 지원 | 🟡 | L | ⬜ 대기 | `scan_injection_enhanced.py`<br>`skills/sec-audit-static/` | - | - | - |
| T-06 | 보고서 출력 개발자 친화적 개선<br>(실제 코드 수정 가이드 포함, 취약 라인 직접 링크) | 🟡 | M | ⬜ 대기 | `publish_confluence.py`<br>`generate_finding_report.py` | - | - | - |
| T-08 | **Language-Server-MCP-Bridge 도입**<br>• 기존 Regex 기반 AST 파싱 한계(변수명 변경·인터페이스 매핑 유실) 극복<br>• LSP(Language Server Protocol)를 Anthropic MCP로 연동하여 IDE 수준의 시맨틱 분석 확보<br>• `textDocument/references` 등으로 Taint Tracking 완전 자동화 → 오탐률 획기적 감소<br>• 단기: Java/Kotlin LSP 연동 PoC / 중기: `scan_injection_enhanced.py` impl_index 대체 | 🔴 | XL | ⬜ 대기 | `scan_injection_enhanced.py`<br>`tools/scripts/` | - | - | [Language-Server-MCP-Bridge](https://github.com/sehejjain/Language-Server-MCP-Bridge) |

---

## Phase 1 — 다중 SAST 도구 통합 및 정규화 (Single Pane of Glass)

> 자체 AI 기반 정적 분석(A)과 상용/오픈소스 SAST 도구(Fortify, FindSecBugs) 진단 결과를 단일 뷰로 통합한다.
> **핵심 설계 원칙**: CWE 번호를 병합 Key로 사용. AI 역할을 "탐지"에서 "FP 심판관"으로 전환하여 토큰 비용 절감 + 정확도 극대화.

| # | 항목 | 우선순위 | 복잡도 | 상태 | 관련 컴포넌트 | 비고 |
|---|------|---------|--------|------|--------------|------|
| P1-01 | **Fortify 결과 파서 구현**<br>• FPR(zip 압축 XML) 언패킹 및 파싱<br>• XML/JSON 출력 포맷 지원<br>• 공통 스키마(CWE Key 기반)로 변환 | 🔴 | M | ⬜ 대기 | `tools/scripts/parse_fortify.py` (신규) | FPR = zip+XML |
| P1-02 | **Fortify 취약점 분류 → 공통 스키마 매핑**<br>• Kingdom/Category → CWE 번호 매핑 테이블<br>• 심각도 정규화 (Critical/High/Medium/Low)<br>• `source_tool=Fortify` 필드 추가 | 🔴 | M | ⬜ 대기 | `tools/scripts/parse_fortify.py` | - |
| P1-03 | **Fortify FP 2차 필터링 AI 프롬프트 작성**<br>• 입력: Fortify finding + 소스 스니펫 + 호출 컨텍스트<br>• 출력: result / fp_reason / confidence<br>• AI = "이 취약점이 실제 코드 문맥상 진짜인가?" 심판관 역할 | 🔴 | M | ⬜ 대기 | `skills/sec-audit-static/` 프롬프트 | 토큰 절감 전략 포함 |
| P1-04 | **FindSecBugs 결과 파서 구현**<br>• SpotBugs XML(BugCollection) 파싱<br>• HTML 리포트 fallback 파싱<br>• BugPattern → CWE 매핑 후 공통 스키마 출력 | 🟡 | M | ⬜ 대기 | `tools/scripts/parse_findsecbugs.py` (신규) | - |
| P1-05 | **FindSecBugs 취약점 유형 → 공통 스키마 매핑**<br>• BugPattern 코드 → CWE 매핑 테이블<br>• 심각도 정규화 (SCARY/TROUBLING/OF_CONCERN → High/Medium/Low) | 🟡 | S | ⬜ 대기 | `tools/scripts/parse_findsecbugs.py` | - |
| P1-06 | **A + F + F 결과 병합 — De-duplication 및 교차 검증**<br>• CWE + 파일경로 + 라인 기준 중복 병합<br>• 복수 도구 동시 탐지 시 `confidence=High` 상향<br>• `detected_by[]` 배열로 출처 추적<br>• `merge_results.py` 고도화로 구현 | 🔴 | L | ⬜ 대기 | `tools/scripts/merge_results.py` | - |
| P1-07 | **통합 보안 진단 리포트 자동 생성 파이프라인**<br>• merge → generate_finding_report → publish_confluence 연결<br>• 도구별 탐지 건수 / 교차검증 건수 / 최종 집계 포함<br>• Confluence 게시 시 통합 요약 섹션 자동 추가 | 🔴 | L | ⬜ 대기 | `tools/scripts/generate_finding_report.py`<br>`tools/scripts/publish_confluence.py` | - |

---

## Phase 2 — 전방위 보안 진단(DevSecOps) 영역 확장

> SAST를 넘어 런타임(DAST), 오픈소스(SCA), 인프라(IaC/CSPM), 파이프라인(CI/CD)까지 SDLC 전 구간 자동화.

| # | 항목 | 우선순위 | 복잡도 | 상태 | 관련 컴포넌트 | 비고 |
|---|------|---------|--------|------|--------------|------|
| P2-01 | **SCA — 의존성 파일 스캔 및 CVE 매핑**<br>• 대상: pom.xml, build.gradle, package.json, requirements.txt<br>• 라이브러리 버전 추출 → NVD/OSV CVE DB 조회<br>• CVSS 점수 및 영향 버전 범위 매핑<br>• 결과를 공통 스키마(`source_tool=SCA`)로 출력 | 🔴 | L | ⬜ 대기 | `tools/scripts/scan_sca.py` (신규) | - |
| P2-02 | **SCA — CVE Exploit/PoC 악용 가능성 자동 분석**<br>• ExploitDB / GitHub PoC / CISA KEV 조회<br>• Exploit 존재 시 severity 상향 조정<br>• AI: "이 서비스가 해당 취약 컴포넌트를 실제로 사용하는지" 문맥 판별 | 🟡 | L | ⬜ 대기 | `tools/scripts/scan_sca.py` | - |
| P2-03 | **DAST 결과 임포트 모듈 개발 (ZAP / Burp Suite)**<br>• OWASP ZAP XML/JSON 리포트 파서<br>• Burp Suite XML 리포트 파서<br>• 공통 스키마(`source_tool=DAST`)로 변환 및 CWE 매핑 | 🟡 | M | ⬜ 대기 | `tools/scripts/parse_dast.py` (신규) | - |
| P2-04 | **SAST-DAST 교차 검증 — 코드 취약점의 런타임 재현 여부 확인**<br>• CWE + URL 엔드포인트 기준 SAST ↔ DAST 매칭<br>• 양쪽 동시 탐지 → `confidence=Critical`, 즉시 조치 권고<br>• SAST 탐지 / DAST 미탐 → "잠재적 취약점 — 추가 검증 필요" | 🟡 | L | ⬜ 대기 | `tools/scripts/merge_results.py` | P2-03 완료 후 착수 |
| P2-05 | **IaC/CSPM — 서버·Nginx/Tomcat 설정 파일 취약점 분석**<br>• 대상: nginx.conf, server.xml, httpd.conf, OS 설정<br>• 탐지 항목: SSL/TLS 버전, 약한 암호 스위트, 디렉토리 리스팅, 에러 페이지 노출<br>• 결과를 공통 스키마(`source_tool=IaC`)로 출력 | 🟡 | M | ⬜ 대기 | `tools/scripts/scan_iac.py` (신규) | - |
| P2-06 | **IaC/CSPM — Docker/K8s 설정 오류 스캔**<br>• Dockerfile: root 실행 / 불필요한 포트 / 시크릿 COPY<br>• docker-compose.yml: privileged 모드, 취약 볼륨 마운트<br>• K8s YAML: 과도한 RBAC / securityContext 미설정 / 시크릿 평문 저장 | 🟡 | M | ⬜ 대기 | `tools/scripts/scan_iac.py` (신규) | - |
| P2-07 | **CI/CD 파이프라인 보안 점검 — 시크릿 노출 및 권한 탈취 탐지**<br>• 대상: Jenkinsfile, .github/workflows/*.yml, .gitlab-ci.yml<br>• 탐지 항목: 평문 시크릿 하드코딩, 과도한 권한(sudo/root), 신뢰할 수 없는 외부 액션 참조<br>• 결과를 공통 스키마(`source_tool=CICD`)로 출력 | 🟡 | M | ⬜ 대기 | `tools/scripts/scan_cicd.py` (신규) | - |

---

## 완료 과제

| # | 항목 | 완료일 | 버전 | 비고 |
|---|------|--------|------|------|
| ✅ | Phase 24: Positional Index Taint Tracking 구현 | 2026-02-24 | v4.5.0 | HTTP param → SQL 계층간 taint 전파 |
| ✅ | DTO 랩핑 taint 전파 오류 수정 | 2026-02-24 | v4.5.1 | `ordering` via DTO → `[실제]` 정확 판정 |
| ✅ | Kotlin `${if(expr)}` 키워드 오탐 수정 | 2026-02-24 | v4.5.1 | `_KT_KEYWORDS` 모듈 상수화 |
| ✅ | `_extract_call_args` 선언부 오탐(FP) 수정 | 2026-02-24 | v4.5.2 | `.methodName(` 우선순위 적용 |
| ✅ | Confluence code macro kotlin → java 수정 | 2026-02-25 | v4.5.2 | Server/DC `InvalidValueException` 해결 |
| ✅ | Bitbucket push 증분 커밋 히스토리 보존 | 2026-02-25 | - | `BB_HISTORY_REF` 방식 도입 |
| ✅ | `.gitignore` 고객사 파일 누락 항목 보완 | 2026-02-25 | - | `보고서예시/`, Office 문서 등 |
| ✅ | `scan_xss.py` v1.1.0 XSS 진단 고도화 | 2026-02-26 | v1.1.0 | per-type 판정(Reflected/View/Persistent/Redirect/DOM) 5종, Phase 6 DOM XSS 전역 스캔, task_23 DOM XSS 기준 추가 |
| ✅ | `scan_injection_enhanced.py` v4.6.0 Hexagonal Architecture 지원 | 2026-02-25 | v4.6.0 | Phase 17: Port/Adapter suffix 치환, QueryDSL JPAQueryFactory 안전 탐지 |
| ✅ | `scan_injection_enhanced.py` v4.6.1 findAllBy 오분류 + main_report 타입 | 2026-02-26 | v4.6.1 | interface body guard, Phase 17b/17c, `_QUERYDSL_HINT_RE` 확장, publish_confluence main_report |
| ✅ | `scan_injection_enhanced.py` v4.6.2 Call Graph Disconnection 수정 | 2026-02-27 | v4.6.2 | impl_index 구축, _resolve_impl_class, Phase 17 JPA 해석 블록 |
| ✅ | `scan_injection_enhanced.py` v4.6.3 Call Graph 완성 (Fix A~E) | 2026-02-28 | v4.6.3 | okick-event/reward 전량 양호 달성 |
| ✅ | `scan_xss.py` v2.1.0~v2.3.2 FP 제거 + SET/WHERE 구분 + DTO 필드 검사 | 2026-03-03~04 | v2.3.2 | 3종 FP 수정, Hexagonal 구현체 해석, DTO record balanced-paren 파싱 |
| ✅ | `publish_confluence.py` XSS 보고서 렌더링 전면 개편 | 2026-03-03 | v2.3.1 | 카테고리 그룹핑 + Expand 매크로 + DOM XSS 분리 + 필터 info/warning 박스 |
| ✅ | `docs/ANALYSIS_REPORT_INJECTION_XSS.md` 설계 분석 보고서 작성 | 2026-03-04 | - | Hexagonal 추적, SET/WHERE 구분, FN 방어, 폴백/교차검증 기술 문서화 |
| ✅ | Task 2-3~2-5 진단 자동화 고도화 완성 (T-07) | 2026-03-06 | v4.7.0~v4.9.0 | scan_xss v2.4.0 / scan_file_processing v1.0 / scan_data_protection v1.1.0 |
| ✅ | MyBatis `<include>` 인라인 치환 로직 전면 재작성 (`_resolve_sql_text`) | 2026-03-06 | v4.9.1 | 순환 참조 방지 + 중첩 include + namespace 한정 refid 지원 |
| ✅ | @Query 어노테이션 전체 인수 파싱 + nativeQuery 탐지 | 2026-03-06 | v4.9.2 | `+` 연결 취약 판정, `:param`/`?1` 안전 판정 분리 |
| ✅ | QueryDSL `Expressions.stringTemplate()` `{0}` 플레이스홀더 → 양호 세분화 | 2026-03-06 | v4.9.2 | `_ST_CONCAT_RE` 신규 패턴 도입 |
| ✅ | iBatis `<sqlMap>` namespace 누락 버그 2종 수정 | 2026-03-06 | v4.9.3 | Quick filter regex 교체 + xml_file.stem pseudo-namespace fallback |
| ✅ | DTO Taint 단절 해결 — DTO 접근자 패턴 + `conservative_fallback` | 2026-03-06 | v4.9.3 | `_propagate_taint_by_index` Strategy 2 추가 |
| ✅ | `manual_review_prompt.md` SQL Injection Taint 역추적 프롬프트 추가 | 2026-03-06 | v4.9.3 | DTO/Map 래핑, 동적 SQL ID 생성 2대 역추적 시나리오 + `taint_path` 스키마 |
| ✅ | 미사용 파일 17개 정리 (docs/ 10개, references/ 2개, scripts/ 4개 + old docx 4개) | 2026-03-06 | v4.9.4 | 구세대 절차 문서 제거, 대체된 스크립트 삭제 |
| ✅ | severity 공식 등급 표준화 (SENSITIVE_LOGGING Critical, WEAK_CRYPTO Medium 등) + `docs/sec-audit-static/` 신규 생성 | 2026-03-09 | v4.9.5 | 7개 task 절차 문서 초기 생성 |
| ✅ | Confluence 앵커 링크 수정 — `ac:link ac:anchor` 변환 + md2cf 모드 `[[ANCHOR:name]]` 누락 버그 수정 | 2026-03-11 | v4.9.6 | `generate_finding_report.py` + `publish_confluence.py` |
| ✅ | `scan_xss.py` Persistent XSS 판정 로직 수정 (REST/JSON 반환타입 오류 제거) | 2026-03-11 | v4.10.0 | DB 저장 경로와 응답 타입은 무관 — 2계층 분석으로 191건 취약 확정 |
| ✅ | `scan_xss.py` P1: 전역 XSS 필터 결함 탐지 3종 (Fail-Open, 불충분한 블랙리스트, getInputStream 미필터) | 2026-03-11 | v4.10.0 | `_P3_FAILOPEN_RE`, `_count_blacklist_items`, `_getinputstream_missing_filter` 신규 |
| ✅ | `scan_xss.py` P2: HTML_VIEW 오탐 제거 (DTO/Collection 반환타입, `@RequestBody` 파라미터 강제 REST_JSON 분류) | 2026-03-11 | v4.10.0 | `_P1_PROTO_API_RT_RE` 확장 + `has_request_body_param` 감지 |
| ✅ | Task 2-5 데이터보호 진단 병합/고도화 — HARDCODED_SECRET 23→8건, SENSITIVE_LOGGING 197→2건 | 2026-03-12 | v4.10.1 | `task25_llm.json` + task_prompt Step 5/6 + docs 갱신 |

---

## 추가 제안 항목 (미확정)

| # | 항목 | 우선순위 | 복잡도 | 비고 |
|---|------|---------|--------|------|
| A-01 | SARIF 포맷 출력 지원 (IDE 연동) | 🟡 | M | VS Code / IntelliJ Security 플러그인 연동 |
| A-02 | 진단 결과 Delta 비교 (이전 스캔 대비 변경점) | 🟡 | M | 신규/수정/해결된 취약점 추적 |
| A-03 | GitHub Actions CI 연동 (PR 시 자동 진단) | 🟢 | M | 개발 파이프라인 통합 |
| A-04 | 다국어 보고서 지원 (영문 보고서) | 🟢 | S | 해외 협업 시 필요 |
| A-05 | **Sourcegraph / Zoekt / OpenGrok 전사 코드 인덱싱 도입**<br>• 멀티레포/MSA 환경에서 타 마이크로서비스 호출 코드 추적 맹점 극복<br>• 전사 코드베이스 통합 인덱싱으로 0.1초 내 취약 패턴 검색<br>• Cross-Repository 진단 파이프라인 구축<br>• Variant Analysis(변형 취약점 일괄 탐지) 자동화 | 🟡 | XL | 외부 인프라 구축 필요; 장기 로드맵 |
