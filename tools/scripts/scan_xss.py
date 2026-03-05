#!/usr/bin/env python3
"""
XSS 취약점 자동 진단 스크립트 v2.0.0

scan_api.py 결과를 기반으로 각 API endpoint에 대해
6가지 Phase로 XSS 취약 여부를 자동 판정합니다.

  Phase 1: Controller 분류 및 Content-Type 기반 방어 판정
            @RestController / @ResponseBody / ResponseEntity → JSON API
            produces=text/html 또는 오류 응답 leak → 🚨 취약 판정
            @Controller + String/ModelAndView 반환 → HTML View (Phase 2 진입)
  Phase 2: View 렌더링 추적 (Outbound Escaping)
            JSP: ${value} vs <c:out> / fn:escapeXml()
            Thymeleaf: th:utext (취약) vs th:text (안전)
            Handlebars: {{{variable}}} (취약) vs {{variable}} (안전)
  Phase 3: 전역 XSS 필터 탐지 (Inbound Sanitizing)
            Lucy XSS Filter / AntiSamy / ESAPI
            Jackson ObjectMapper XSS Deserializer
            Lucy 존재 시 MultipartFilter 순서 검증 (Bypass 위험 확인)
  Phase 4: Redirect / Open Redirect 취약 패턴 탐색
            서버사이드: sendRedirect(userInput) / return "redirect:" + var
            클라이언트사이드: location.href= / window.location=
  Phase 5: Persistent XSS Taint Tracking (v2.0.0 전면 강화)
            Controller HTTP param → Service → Repository write(save/insert/update)
            전역 필터 미적용 + taint 확정 → 🚨 [취약-잠재적위협]
  Phase 6: DOM XSS 전역 스캔
            innerHTML= / document.write() / eval() / dangerouslySetInnerHTML
            insertAdjacentHTML() / jQuery .html() / Vue v-html

출력 카테고리:
  🚨 취약 — [실제위협] Reflected/View XSS, [잠재적위협] Persistent/Encoding 누락
  ⚠️ 정보 — 전역 필터 미설정/우회 가능성, 특수 엔드포인트 수동 확인
  ✅ 양호 — 입력 파라미터 없음, DB 저장 없는 단순 조회, 명시적 escaping 확인

변경 이력:
  v1.0.0 - 초기 구현 (Phase 1~5)
  v1.1.0 - per-type 판정 필드, Phase 6 DOM XSS, summary per-type 통계
  v1.1.1 - 커스텀 @RestController 메타 어노테이션 탐지
  v2.0.0 - Phase 5 Taint Tracking (Controller→Service→Repo write),
            Phase 3 Lucy multipart bypass 검증,
            Phase 1 REST text/html 취약 판정,
            Phase 4 클라이언트 리다이렉트 패턴 추가,
            xss_category 필드 + 출력 카테고리 재편
  v2.1.0 - Fix 1: sqli DB write 정확도 향상 (jpa_builtin READ → write 키워드 있을 때만 write 간주)
            Fix 2: Enum/Type Casting Taint 해제 (Event.from(), parseInt() 등 → 양호)
                   @AuthenticationPrincipal param taint 추적 제외
                   1레벨 Command/DTO 클래스 내 Enum 검증 탐지
            Fix 3: 자유 텍스트 파라미터 없으면 조기 양호 반환
  v2.2.0 - Fix 1/2/3 통과 후 잔여 Persistent XSS → 무조건 "취약" 승급 (Regression 수정)
            check_persistent_xss: "잠재" 리스크 → "취약" 리스크로 변경
            judge_xss_endpoint: Worst-case 강제 — "잠재"/"취약" 모두 취약 승급
            severity: taint 경로 자동 확인 시 "High", DB write 경로 불명 시 "Medium"
  v2.3.0 - SET/WHERE 절 구분 + 헥사고날 아키텍처 구현체 해석 (FP 수정)
  v2.3.1 - Worst-case 원칙 강화 + persist(new ...) 탐지 + interface 메서드 휴리스틱
            _P5_PERSIST_NEW_RE: persist(new Entity(...)) → SET 컨텍스트 탐지
            _check_repo_param_context: interface 메서드 empty body → read 접두사 → "where"
            _trace_persistent_xss_taint: svc_has_any_write 가드 추가
              - repo_calls 내 write 메서드 존재 시 WHERE-only sanitize 절대 금지
              - 엔티티 래핑(_has_param_in_direct_call=False) write 경로 FN 방지
            _resolve_svc_impl_body(): UseCase/Port 인터페이스 → Service/Adapter 구현체 해석
            _has_param_in_direct_call(): HTTP 파라미터 standalone 직접 전달 확인
            _check_repo_param_context(): repo 메서드 본문에서 SET vs WHERE 절 구조 판정
            _trace_persistent_xss_taint(): svc_body 빈 경우 구현체 해석 폴백 + repo 루프 교체
            결과: /api/internal/rewards/failure/retry FP 제거 (취약→양호)
  v2.3.2 - DTO 필드 1레벨 검사 (_inspect_dto_fields 신규):
            @RequestBody DtoClass → 모든 필드가 Integer/Boolean/UUID/날짜 등 비-자유텍스트이면 양호
            FP 제거: ExchangePointsRequestDto(Integer goldenEggsCnt) → 양호
            _has_freetext_params: class_index/source_dir 선택적 수신, DTO 필드 검사 폴백 적용
  v2.4.0 - Step 1: Reflected XSS Taint Flow 검증 추가 (REST_HTML_RISK FP 제거)
            check_reflected_xss_taint(): 사용자 입력 파라미터 → 문자열 연결 → text/html 반환 흐름 추적
            Taint 미확인 시 "취약" 대신 "정보"로 하향; HtmlUtils/Encode.forHtml 감지 시 양호
           Step 2: DOM XSS 라이브러리 파일 제외 필터 추가 (FP 제거)
            _P6_DOM_EXCLUDE_RE: *.min.js / jquery.* / bootstrap.* / /lib/ /vendor/ 등 제외
            scan_dom_xss_global(): files_excluded / excluded_files 리포트 필드 추가
           Step 3: 커스텀 XSS 필터 탐지 로직 추가 (미탐 방지)
            _P3_CUSTOM_WRAPPER_RE: HttpServletRequestWrapper 상속 클래스 탐지
            _P3_CUSTOM_CLEAN_METHOD_RE: cleanXss/stripXss 등 커스텀 메서드 탐지
            _P3_BLACKLIST_REPLACE_RE: replace("<script", "") 블랙리스트 방식 탐지
            filter_level "custom_wrapper" 신규 추가 — "[정보 - 커스텀 XSS 필터 발견]" 분류
           Step 4: View XSS AI 수동 진단 프롬프트 템플릿 추가
            skills/sec-audit-static/references/manual_review_prompt.md 에 View XSS 섹션 추가

사용법:
    python scan_xss.py <source_dir> --api-inventory <json>
    python scan_xss.py testbed/myapp/ \\
        --api-inventory state/api.json \\
        --sqli-result  state/sqli.json \\
        -o state/xss_result.json
"""

import json
import re
import sys
import argparse
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional
from datetime import datetime

# scan_injection_enhanced.py 공유 유틸 임포트
sys.path.insert(0, str(Path(__file__).parent))
from scan_injection_enhanced import (
    read_file_safe,
    extract_class_name,
    extract_method_body,
    build_class_index,
    extract_constructor_deps,
    extract_method_calls,
)


# ============================================================
#  0. 상수 / 컴파일된 패턴
# ============================================================

_SCRIPT_VERSION = "2.4.0"

# View 파일 확장자
_JSP_EXTS       = frozenset({".jsp", ".jspf", ".jspx"})
_THYMELEAF_EXTS = frozenset({".html", ".htm", ".xhtml"})
_ALL_VIEW_EXTS  = _JSP_EXTS | _THYMELEAF_EXTS

# 빌드/테스트 디렉터리 제외
_EXCLUDE_DIRS = frozenset({
    "test", "Test", "target", "build",
    "node_modules", ".git", "__pycache__", "generated",
})

# Phase 1: Content-Type 분류 패턴 -----------------------------------

# 클래스 레벨 @RestController
_P1_REST_CLASS = re.compile(r'@RestController\b')
# 메서드 레벨 @ResponseBody
_P1_RESPONSE_BODY = re.compile(r'@ResponseBody\b')
# produces = application/json
_P1_PRODUCES_JSON = re.compile(
    r'produces\s*=\s*(?:MediaType\.APPLICATION_JSON(?:_VALUE|_UTF8_VALUE)?'
    r'|["\']application/json["\'])',
    re.IGNORECASE,
)
# produces = text/html
_P1_PRODUCES_HTML = re.compile(
    r'produces\s*=\s*(?:MediaType\.TEXT_HTML(?:_VALUE)?|["\']text/html["\'])',
    re.IGNORECASE,
)
# Gson disableHtmlEscaping
_P1_GSON_UNSAFE = re.compile(r'\.disableHtmlEscaping\s*\(\s*\)', re.IGNORECASE)
# REST 메서드에서 명시적 text/html 반환 (취약)
# 대상: setContentType("text/html"), MediaType.TEXT_HTML, header.add/set("Content-Type", "text/html")
_P1_REST_HTML_CT = re.compile(
    r'MediaType\.TEXT_HTML'
    r'|setContentType\s*\([^)]*text/html'
    r'|(?:header|headers|response)\s*[\.\[].*["\'](?:Content-Type|content-type)["\']'
    r'\s*[,\]]\s*["\']text/html["\']'
    r'|["\']text/html["\']',
    re.IGNORECASE,
)
# 오류/예외 핸들러에서 입력값 직접 반영 패턴
_P1_ERROR_REFLECT = re.compile(
    r'@ExceptionHandler|getMessage\s*\(\s*\)|getLocalizedMessage\s*\(\s*\)',
    re.IGNORECASE,
)

# ── Step 1: Reflected XSS Taint Flow 추적 패턴 (v2.4.0) ────────────────────

# 사용자 입력 파라미터 변수명 추출:
#   @RequestParam [Type] varName / @PathVariable [Type] varName /
#   String varName = request.getParameter("...") 패턴
_P1_TAINT_PARAM_EXTRACT = re.compile(
    r'@(?:RequestParam|PathVariable|RequestHeader|RequestPart)'
    r'(?:\s*\([^)]*\))?\s+'
    r'(?:(?:final|required)\s+)?'
    r'(?:[\w<>\[\]?,\s]+?\s+)'
    r'(\w+)'
    r'|'
    r'(?:request|req)\s*\.\s*getParameter\s*\(\s*"[^"]+"\s*\)'
    r'\s*;\s*'
    r'(?:final\s+)?(?:String\s+)?(\w+)\s*=',
    re.MULTILINE,
)

# 반환 문자열 내 변수 연결(Taint) 탐지:
#   return "..." + var / return var + "..." / response.getWriter().write(var)
_P1_TAINT_CONCAT_RE = re.compile(
    r'return\s+(?:["\'][^"\']*["\']|[^;]+?)\s*\+\s*(\w+)'
    r'|return\s+(\w+)\s*\+\s*(?:["\'][^"\']*["\']|[^;]+?)'
    r'|(?:response|resp)\s*\.\s*(?:getWriter\s*\(\s*\)\s*\.\s*(?:write|print)'
    r'|getOutputStream\s*\(\s*\)\s*\.\s*write)\s*\(\s*(\w+)',
    re.MULTILINE,
)

# HTML 출력 안전 인코딩 함수 (Taint 해제 조건)
_P1_ESCAPE_SAFE_RE = re.compile(
    r'HtmlUtils\.htmlEscape\s*\('
    r'|StringEscapeUtils\.escapeHtml[24]?\s*\('
    r'|Encode\.forHtml\s*\('
    r'|ESAPI\.encoder\s*\(\s*\)\s*\.\s*encodeForHTML\s*\('
    r'|HtmlEscapers\.htmlEscaper\s*\(\s*\)\s*\.\s*escape\s*\('
    r'|org\.springframework\.web\.util\.HtmlUtils',
    re.IGNORECASE,
)

# Phase 2: JSP 출력 패턴 --------------------------------------------

# fn:escapeXml() 사용 여부
_P2_JSP_ESCAPE_XML = re.compile(r'\bfn:escapeXml\s*\(', re.MULTILINE)
# <c:out escapeXml="false"> → 취약
_P2_JSP_COUT_UNSAFE = re.compile(
    r'<c:out\b[^>]*escapeXml\s*=\s*["\']false["\']',
    re.MULTILINE | re.IGNORECASE,
)
# <c:out value="..."> (escapeXml 기본값 true) → 안전
_P2_JSP_COUT_SAFE = re.compile(
    r'<c:out\b[^>]*value\s*=\s*"[^"]*"(?![^>]*escapeXml\s*=\s*["\']false)',
    re.MULTILINE | re.IGNORECASE,
)
# JSP 스크립틀릿에서 직접 파라미터 출력
_P2_JSP_SCRIPTLET_PARAM = re.compile(
    r'<%=\s*request\.getParameter\s*\(', re.MULTILINE
)
# model.addAttribute("key", ...) 에서 키 추출
_P2_MODEL_ATTR = re.compile(r'model\.addAttribute\s*\(\s*"([^"]+)"', re.MULTILINE)

# Phase 2: Thymeleaf 패턴 -------------------------------------------

# th:utext → HTML escape 없음 (취약)
_P2_TH_UTEXT = re.compile(r'\bth:utext\s*=\s*["\']?\$\{', re.MULTILINE)
# th:text → 자동 escape (안전)
_P2_TH_TEXT  = re.compile(r'\bth:text\s*=\s*["\']?\$\{', re.MULTILINE)

# Phase 2: Handlebars 취약 패턴 (Triple-stache → HTML escape 없음)
_P2_HANDLEBARS_UNSAFE = re.compile(r'\{\{\{[^}]+\}\}\}', re.MULTILINE)
# Handlebars 안전 패턴 (Double-stache → 자동 escape)
_P2_HANDLEBARS_SAFE = re.compile(r'\{\{[^{][^}]+\}\}', re.MULTILINE)

# Phase 3: 전역 XSS 필터 패턴 ----------------------------------------

_P3_LUCY       = re.compile(
    r'LucyXss(?:Servlet)?Filter|XssEscapeServletFilter|lucy-xss',
    re.IGNORECASE,
)
_P3_ANTISAMY   = re.compile(r'AntiSamy|org\.owasp\.validator\.html', re.IGNORECASE)
_P3_ESAPI      = re.compile(r'ESAPI\.encoder\(\)|ESAPIFilter|org\.owasp\.esapi', re.IGNORECASE)
_P3_SS_XSS     = re.compile(r'\.xssProtection\s*\(|XContentTypeOptionsHeaderWriter', re.IGNORECASE)
_P3_JACK_DESER = re.compile(
    r'@JsonDeserialize\s*\([^)]*using\s*=\s*\w*[Xx][Ss][Ss]\w*\.class',
    re.IGNORECASE,
)
_P3_JACK_MOD   = re.compile(
    r'addDeserializer\s*\([^)]*,\s*new\s+\w*[Xx][Ss][Ss]\w*',
    re.IGNORECASE,
)
# Phase 3: MultipartFilter 관련 패턴 (Lucy Bypass 검증용)
_P3_MULTIPART_RE = re.compile(
    r'MultipartFilter|CommonsMultipartResolver|StandardServletMultipartResolver'
    r'|MultipartConfigElement',
    re.IGNORECASE,
)
_P3_LUCY_FILTER_BEAN = re.compile(
    r'LucyXss(?:Servlet)?Filter|XssEscapeServletFilter',
    re.IGNORECASE,
)

# ── Step 3: 커스텀 XSS 필터 탐지 패턴 (v2.4.0) ──────────────────────────────

# HttpServletRequestWrapper 상속 커스텀 래퍼 클래스 탐지
_P3_CUSTOM_WRAPPER_RE = re.compile(
    r'extends\s+HttpServletRequestWrapper'
    r'|implements\s+(?:[\w,\s]+,\s*)*HttpServletRequestWrapper',
    re.MULTILINE,
)

# 커스텀 XSS 클렌징 메서드명 패턴
_P3_CUSTOM_CLEAN_METHOD_RE = re.compile(
    r'\b(?:clean|strip|remove|sanitize|filter|escape|replace)Xss\s*\('
    r'|\bxss(?:Clean|Strip|Filter|Sanitize|Escape|Remove)\s*\('
    r'|\bxssFilter\s*\('
    r'|\bXssUtil(?:s)?\s*\.\s*\w+\s*\(',
    re.IGNORECASE,
)

# 블랙리스트 방식 필터링 탐지: replace로 특정 HTML 공격 키워드 제거
_P3_BLACKLIST_REPLACE_RE = re.compile(
    r'\.replace\s*\(\s*'
    r'(?:"(?:<script|</script|<iframe|<object|onerror|onload|javascript:|alert\s*\()'
    r"|'(?:<script|</script|<iframe|<object|onerror|onload|javascript:|alert\s*\())"
    r'\s*,',
    re.IGNORECASE,
)

# 안전하지 않은 replace: HTML 특수문자를 빈 문자열로 제거 (화이트리스트 아님)
_P3_UNSAFE_REPLACE_RE = re.compile(
    r'\.replace\s*\(\s*(?:"<"|\'<\'|">"|\'>\'")\s*,\s*(?:""|\'\')',
    re.IGNORECASE,
)

# Phase 4: Redirect 취약 패턴 (서버사이드) ---------------------------
# (pattern, description)
_P4_REDIRECT_PATTERNS = [
    (
        re.compile(
            r'(?:response\.)?sendRedirect\s*\(\s*(?!["\'](?:/|https?://))',
            re.MULTILINE,
        ),
        "sendRedirect(variable) — 동적 리다이렉트 대상",
    ),
    (
        re.compile(r'return\s+"redirect:"\s*\+', re.MULTILINE),
        'return "redirect:" + variable — 동적 Spring 리다이렉트',
    ),
    (
        re.compile(
            r'response\.(?:setHeader|addHeader)\s*\(\s*"Location"\s*,\s*(?!["\'])',
            re.MULTILINE,
        ),
        'setHeader("Location", variable) — 동적 Location 헤더',
    ),
    (
        re.compile(
            r'UriComponentsBuilder\.fromUriString\s*\(\s*(?!["\'])',
            re.MULTILINE,
        ),
        "UriComponentsBuilder.fromUriString(variable) — 동적 URI 조합",
    ),
    (
        re.compile(
            r'(?:HttpHeaders\s*\(\s*\)\s*\.setLocation|new\s+URI\s*\()\s*(?!["\'])',
            re.MULTILINE,
        ),
        "HttpHeaders.setLocation(variable) / new URI(variable) — 동적 Location",
    ),
]

# Phase 4: 클라이언트 사이드 리다이렉트 패턴 (JS/JSP 인라인 스크립트)
_P4_CLIENT_REDIRECT_PATTERNS = [
    (
        re.compile(r'location\.href\s*=\s*(?!["\'])', re.MULTILINE),
        "location.href = variable — 클라이언트 사이드 오픈 리다이렉트",
    ),
    (
        re.compile(r'window\.location(?:\.href)?\s*=\s*(?!["\'])', re.MULTILINE),
        "window.location = variable — 클라이언트 사이드 오픈 리다이렉트",
    ),
    (
        re.compile(r'window\.location\.replace\s*\(\s*(?!["\'])', re.MULTILINE),
        "window.location.replace(variable) — 클라이언트 사이드 리다이렉트",
    ),
]

# @RequestParam / getParameter 근거 패턴 (Redirect confidence 향상용)
_P4_USER_PARAM_CTX = re.compile(
    r'@RequestParam|getParameter\s*\(|@PathVariable|HttpServletRequest',
)

# Phase 5: Repository write 메서드명 패턴 (Persistent XSS Taint용) ----
_P5_WRITE_METHOD_RE = re.compile(
    r'^(?:save|insert|update|store|persist|create|add|put|merge|upsert'
    r'|register|write|bulk|batch|modify|edit|upload|post)\w*$',
    re.IGNORECASE,
)
# Service/UseCase/Repository 계층 suffix
_P5_SVC_SUFFIXES  = ("Service", "UseCase", "Facade", "Manager", "Handler")
_P5_REPO_SUFFIXES = ("Repository", "Dao", "Mapper", "Store", "Port", "Adapter")

# Phase 5: Fix 1 — sqli result에서 DB write 키워드 확인용
_P5_WRITE_DETAIL_RE = re.compile(
    r'\b(?:save|saveAll|saveAndFlush|insert|update|persist|merge|upsert'
    r'|store|create|add|modify|delete|remove|deleteAll|bulkInsert|bulk_insert)\b',
    re.IGNORECASE,
)

# Phase 5: Fix 2 — Enum/Type Casting Taint 해제 패턴 (변수명 캡처그룹 1)
_P5_SANITIZE_PATTERNS = [
    # SomeEnum.from(var) / SomeEnum.valueOf(var) / SomeEnum.of(var)
    re.compile(r'[A-Z]\w*\.(?:from|fromString|valueOf|of)\s*\(\s*(\w+)\s*\)'),
    # Integer/Long/Double 등 parse: Integer.parseInt(var)
    re.compile(
        r'(?:Integer|Long|Double|Float|Short|Byte|BigDecimal|BigInteger)\.parse\w*\s*\(\s*(\w+)\s*\)',
        re.IGNORECASE,
    ),
    # UUID.fromString(var)
    re.compile(r'UUID\.fromString\s*\(\s*(\w+)\s*\)', re.IGNORECASE),
    # Boolean.parseBoolean(var) / Boolean.valueOf(var)
    re.compile(r'Boolean\.(?:parseBoolean|valueOf)\s*\(\s*(\w+)\s*\)', re.IGNORECASE),
    # Kotlin: var.toInt() / var.toLong() / var.toDouble() 등
    re.compile(r'(\w+)\.to(?:Int|Long|Double|Float|Boolean)\s*\(\s*\)'),
]

# Phase 5: Fix 2 — Command/DTO factory 메서드 패턴 (1레벨 Enum 검증 추적용)
_P5_CMD_FACTORY_RE  = re.compile(r'([A-Z]\w+)\.(?:of|from|create|build)\s*\(')
_P5_CMD_SUFFIXES    = ("Command", "Request", "Dto", "DTO", "Param", "Form", "Input", "Payload")

# Phase 5: Fix 3 — 자유 텍스트 아닌 파라미터 타입 (Enum/Numeric/Boolean/날짜 등)
_P5_NON_FREETEXT_TYPES: frozenset = frozenset({
    "int", "long", "double", "float", "boolean", "byte", "short",
    "Integer", "Long", "Double", "Float", "Boolean", "Byte", "Short",
    "UUID", "LocalDate", "LocalDateTime", "ZonedDateTime", "OffsetDateTime",
    "Date", "BigDecimal", "BigInteger", "Number",
})

# Phase 5: v2.3.0 — 읽기 전용 메서드 명칭 패턴 (Controller-level Port read 확인용)
_P5_READ_METHOD_RE = re.compile(
    r'^(?:find|get|list|fetch|count|exists|search|load|retrieve|select|query)\w*$',
    re.IGNORECASE,
)

# Phase 5: v2.3.0 — UseCase/Port 인터페이스 → 구현체 suffix 매핑
_P5_IFACE_TO_IMPL_SUFFIX: tuple = (
    ("UseCase", "Service"),
    ("Port",    "Adapter"),
)

# QueryDSL SET 절 패턴: .set(Q.field, var) → 저장 컨텍스트
_P5_QDSL_SET_RE = re.compile(
    r'\.set\s*\(\s*[\w.]+\s*,\s*\w+',
    re.IGNORECASE,
)

# JPA entity setter: entity.setXxx(var) → 저장 컨텍스트
_P5_ENTITY_SETTER_RE = re.compile(
    r'\.set[A-Z]\w*\s*\(\s*\w+\s*\)',
)

# Builder pattern: .builder()...field(var) → 저장 컨텍스트
_P5_BUILDER_SET_RE = re.compile(
    r'\.builder\s*\(\s*\)(?:[.\w\s()\n]*?)\.([a-z]\w*)\s*\(\s*\w+\s*\)',
    re.DOTALL,
)

# JPA entityManager.persist(new Entity(...)) — 엔티티 생성자 래핑 = SET 컨텍스트
# Entity 생성자에 파라미터가 직접 들어가는 패턴 탐지 (entity.setXxx 없이 INSERT 수행)
_P5_PERSIST_NEW_RE = re.compile(
    r'\bpersist\s*\(\s*new\s+\w+\s*\(',
    re.IGNORECASE,
)

# Phase 6: DOM XSS 취약 패턴 (JavaScript / HTML / Vue) ---------------

_P6_DOM_VULN_PATTERNS = [
    (
        re.compile(r'\.innerHTML\s*=\s*(?!["\'\s]*["\'])', re.MULTILINE),
        "innerHTML = variable — DOM XSS 위험 (HTML escape 없음)",
    ),
    (
        re.compile(r'\.outerHTML\s*=\s*(?!["\'])', re.MULTILINE),
        "outerHTML = variable — DOM XSS 위험",
    ),
    (
        re.compile(r'\bdocument\.write\s*\(\s*(?!["\'])', re.MULTILINE),
        "document.write(variable) — DOM XSS 위험",
    ),
    (
        re.compile(r'\bdocument\.writeln\s*\(\s*(?!["\'])', re.MULTILINE),
        "document.writeln(variable) — DOM XSS 위험",
    ),
    (
        re.compile(r'\beval\s*\(\s*(?!["\'])', re.MULTILINE),
        "eval(variable) — DOM XSS / Code Injection 위험",
    ),
    (
        re.compile(
            r'\.insertAdjacentHTML\s*\(\s*["\'][^"\']*["\'],\s*(?!["\'])',
            re.MULTILINE,
        ),
        "insertAdjacentHTML(pos, variable) — DOM XSS 위험",
    ),
    (
        re.compile(r'\$\([^)]+\)\.html\s*\(\s*(?!["\'])', re.MULTILINE),
        "jQuery .html(variable) — DOM XSS 위험 (안전: .text())",
    ),
    (
        re.compile(r'dangerouslySetInnerHTML\s*=\s*\{', re.MULTILINE),
        "React dangerouslySetInnerHTML — 직접 HTML 삽입 (DOMPurify 적용 여부 확인)",
    ),
    (
        re.compile(r'\bv-html\s*=', re.MULTILINE),
        "Vue v-html — 직접 HTML 삽입 (DOMPurify 적용 여부 확인)",
    ),
    (
        re.compile(r'\[innerHTML\]\s*=', re.MULTILINE),
        "Angular [innerHTML] 바인딩 — 직접 HTML 삽입 (DomSanitizer 사용 권장)",
    ),
    (
        re.compile(r'\bsetTimeout\s*\(\s*(?!["\'])', re.MULTILINE),
        "setTimeout(variable) — 동적 코드 실행 가능성 (Code Injection)",
    ),
    (
        re.compile(r'\bsetInterval\s*\(\s*(?!["\'])', re.MULTILINE),
        "setInterval(variable) — 동적 코드 실행 가능성 (Code Injection)",
    ),
    (
        re.compile(r'\{\{\{[^}]+\}\}\}', re.MULTILINE),
        "Handlebars {{{variable}}} — Triple-stache HTML escape 없음",
    ),
]

# DOM XSS 안전 패턴 (DOMPurify 등 — 바로 뒤에 sanitize 적용 시 FP 감소)
_P6_DOM_SAFE_CTX = re.compile(
    r'DOMPurify\.sanitize|dompurify\.sanitize|sanitizeHtml|escapeHtml|innerText\s*=',
    re.IGNORECASE,
)

# JavaScript/TypeScript/Vue 파일 확장자 (DOM XSS 스캔 대상)
_JS_SCAN_EXTS = frozenset({".js", ".jsx", ".ts", ".tsx", ".vue"})

# ── Step 2: DOM XSS 스캔 제외 대상 (라이브러리/벤더 파일) (v2.4.0) ──────────
# 파일명 또는 상대 경로에 매칭 시 스캔 제외
_P6_DOM_EXCLUDE_RE = re.compile(
    r'(?:'
    r'\.min\.js$'
    r'|jquery(?:[.\-][\d.]+)?(?:\.min)?\.js$'
    r'|bootstrap(?:[.\-][\d.]+)?(?:\.min)?\.js$'
    r'|(?:angular|react|react-dom|vue|ember|backbone|underscore|lodash)'
    r'(?:[.\-][\d.]+)?(?:\.min)?\.js$'
    r'|jquery[-.](?:ui|validate|cookie|form|migrate|fileupload)'
    r'(?:[.\-][\d.]+)?(?:\.min)?\.js$'
    r'|(?:owl\.carousel|slick|swiper|select2|chosen|moment)'
    r'(?:[.\-][\d.]+)?(?:\.min)?\.js$'
    r'|[\\/](?:lib|vendor|common[/\\]js|dist|bower_components|'
    r'node_modules|static[/\\]js[/\\]lib|webapp[/\\]js[/\\]lib)[\\/]'
    r')',
    re.IGNORECASE,
)

# 커스텀 @RestController 메타 어노테이션 탐지 패턴
_P1_META_REST = re.compile(r'@RestController\b')
_P1_ANN_DECL  = re.compile(r'@interface\s+(\w+)')


# ============================================================
#  1. 데이터 구조
# ============================================================

@dataclass
class XssEndpointResult:
    """XSS 진단 최종 결과 (endpoint별)"""
    no: str
    http_method: str      = ""
    request_mapping: str  = ""
    process_file: str     = ""
    handler: str          = ""
    parameters: str       = ""

    # Phase 1
    controller_type: str  = ""  # REST_JSON | HTML_VIEW | unknown

    # 최종 종합 판정 (worst-case)
    result: str           = "양호"   # 양호 / 취약 / 정보
    severity: str         = "N/A"
    xss_type: str         = ""       # 취약/정보 유형 요약
    diagnosis_detail: str = ""

    # v2.0.0: 출력 카테고리
    # 취약: 실제위협 / 잠재적위협 / 인코딩누락
    # 정보: 수동확인필요 / 우회가능성
    # 양호: 입력없음 / DB저장없음 / escaping확인
    xss_category: str     = ""

    # ── 유형별 개별 판정 (v1.1.0 NEW) ──────────────────────
    # 값: 양호 / 취약 / 정보 / 해당없음
    reflected_xss:  str   = "해당없음"   # Phase 1+2: @RestController → 양호, HTML_VIEW → Phase 2
    view_xss:       str   = "해당없음"   # Phase 2:  JSP/Thymeleaf View 직접 출력 패턴
    persistent_xss: str   = "해당없음"   # Phase 5:  POST/PUT + DB write + 필터
    redirect_xss:   str   = "해당없음"   # Phase 4:  sendRedirect / return "redirect:" + var
    dom_xss:        str   = "해당없음"   # Phase 6:  전역 스캔 결과 참조 (endpoint별 N/A)

    phase_details: dict   = field(default_factory=dict)
    evidence: list        = field(default_factory=list)
    needs_review: bool    = False


# ============================================================
#  2. 인덱스 구축
# ============================================================

def build_view_index(source_dir: Path) -> dict:
    """JSP / HTML(Thymeleaf) 뷰 파일 인덱스 구축

    Returns: {filename_stem_lower: Path}
    """
    idx: dict = {}
    for ext in _ALL_VIEW_EXTS:
        for p in source_dir.rglob(f"*{ext}"):
            if any(ex in p.parts for ex in _EXCLUDE_DIRS):
                continue
            key = p.stem.lower()
            if key not in idx:
                idx[key] = p
    return idx


def _detect_view_prefix_suffix(source_dir: Path) -> tuple:
    """application.properties / application.yml 에서 ViewResolver 설정 탐지

    Returns: (prefix, suffix)  예: ("/WEB-INF/views/", ".jsp")
    """
    prefix, suffix = "", ".jsp"

    for props in source_dir.rglob("application.properties"):
        if any(ex in props.parts for ex in _EXCLUDE_DIRS):
            continue
        content = read_file_safe(props)
        m_p = re.search(r'spring\.mvc\.view\.prefix\s*=\s*(.+)', content)
        m_s = re.search(r'spring\.mvc\.view\.suffix\s*=\s*(.+)', content)
        if m_p:
            prefix = m_p.group(1).strip()
        if m_s:
            suffix = m_s.group(1).strip()
        break

    if not prefix:
        for yml in source_dir.rglob("application.yml"):
            if any(ex in yml.parts for ex in _EXCLUDE_DIRS):
                continue
            content = read_file_safe(yml)
            m_p = re.search(r'prefix:\s*(.+)', content)
            m_s = re.search(r'suffix:\s*(.+)', content)
            if m_p:
                prefix = m_p.group(1).strip()
            if m_s:
                suffix = m_s.group(1).strip()
            break

    return prefix, suffix


def _resolve_view_file(view_name: str,
                       view_index: dict,
                       source_dir: Path,
                       prefix: str,
                       suffix: str) -> Optional[Path]:
    """뷰 이름 → 실제 파일 경로 탐색

    탐색 순서:
      1. prefix + view_name + suffix 구성 후 rglob
      2. view_index stem 매칭 (정확)
      3. view_index stem 부분 매칭 (폴백)
    """
    # 1. 직접 경로 구성
    if suffix:
        candidate_name = view_name.lstrip("/").split("/")[-1]
        if not any(candidate_name.endswith(e) for e in _ALL_VIEW_EXTS):
            candidate_name += suffix
        for p in source_dir.rglob(candidate_name):
            if any(ex in p.parts for ex in _EXCLUDE_DIRS):
                continue
            return p

    # 2. stem 정확 매칭
    stem = view_name.lstrip("/").split("/")[-1].lower()
    for ext in _ALL_VIEW_EXTS:
        if stem.endswith(ext):
            stem = stem[: -len(ext)]
            break
    if stem in view_index:
        return view_index[stem]

    # 3. 부분 매칭
    for key, path in view_index.items():
        if stem in key or key in stem:
            return path

    return None


# ============================================================
#  3. Phase 1: Controller 분류
# ============================================================

def _extract_method_region(content: str, method_name: str,
                            pre_window: int = 800) -> str:
    """메서드 선언 전 어노테이션 포함 영역 추출"""
    m = re.search(
        rf'(?:(?:public|protected|private|static|final|synchronized)\s+){{0,4}}'
        rf'[\w<>\[\],?\s]+\s+{re.escape(method_name)}\s*\(',
        content,
    )
    if not m:
        m = re.search(rf'\b{re.escape(method_name)}\s*\(', content)
    if not m:
        return ""
    start = max(0, m.start() - pre_window)
    return content[start: m.end() + 50]


def _extract_return_type(content: str, method_name: str) -> str:
    """메서드 반환 타입 추출 (제네릭 제외 베이스 타입)"""
    m = re.search(
        rf'(?:public|protected|private|static|final|\s)+\s+'
        rf'([\w<>\[\],?\s]+?)\s+{re.escape(method_name)}\s*\(',
        content,
    )
    if not m:
        return ""
    raw = m.group(1).strip()
    return raw.split("<")[0].strip()


def build_custom_rest_annotations(source_dir: Path) -> frozenset:
    """소스코드 전역에서 @RestController를 메타 어노테이션으로 포함하는
    커스텀 어노테이션 이름 집합을 반환합니다.
    """
    custom: set = set()
    for fp in source_dir.rglob("*.java"):
        if any(ex in fp.parts for ex in _EXCLUDE_DIRS):
            continue
        content = read_file_safe(fp)
        if not content:
            continue
        if _P1_ANN_DECL.search(content) and _P1_META_REST.search(content):
            m = _P1_ANN_DECL.search(content)
            if m:
                custom.add(m.group(1))
    return frozenset(custom)


def classify_controller(ctrl_content: str, handler_method: str,
                        extra_rest_annotations: frozenset = frozenset()) -> dict:
    """Phase 1: Controller/메서드 분류 및 Content-Type 기반 방어 판정

    controller_type:
      REST_JSON       — JSON 응답, 브라우저 HTML 해석 불가 → Reflected XSS 기본 양호
      REST_HTML_RISK  — @RestController이나 text/html 강제 또는 오류 반영 취약
      HTML_VIEW       — @Controller + View name 반환 → Phase 2 (View 분석) 필요
      unknown         — 판정 불가
    """
    is_rest_class   = bool(_P1_REST_CLASS.search(ctrl_content))
    if not is_rest_class and extra_rest_annotations:
        for ann in extra_rest_annotations:
            if re.search(rf'@{re.escape(ann)}\b', ctrl_content):
                is_rest_class = True
                break
    method_region   = _extract_method_region(ctrl_content, handler_method)
    method_body     = extract_method_body(ctrl_content, handler_method) or ""
    return_type     = _extract_return_type(ctrl_content, handler_method)

    has_response_body = bool(_P1_RESPONSE_BODY.search(method_region))
    produces_json     = bool(_P1_PRODUCES_JSON.search(method_region))
    produces_html     = bool(_P1_PRODUCES_HTML.search(method_region))
    gson_unsafe       = bool(_P1_GSON_UNSAFE.search(ctrl_content))

    # text/html 강제 설정 (메서드 본문 내)
    rest_html_ct  = bool(_P1_REST_HTML_CT.search(method_body)) if method_body else False
    error_reflect = bool(_P1_ERROR_REFLECT.search(method_region))

    returns_re = return_type.startswith("ResponseEntity")
    base_rt    = return_type

    # ---- 분류 결정 ----
    if is_rest_class or has_response_body or produces_json:
        if produces_html or rest_html_ct:
            ct = "REST_HTML_RISK"
        else:
            ct = "REST_JSON"
    elif returns_re:
        ct = "HTML_VIEW" if produces_html else "REST_JSON"
    elif base_rt in ("String", "ModelAndView", "View") or produces_html:
        ct = "HTML_VIEW"
    elif base_rt == "void":
        ct = "HTML_VIEW" if not is_rest_class else "REST_JSON"
    elif not base_rt:
        ct = "unknown"
    else:
        ct = "HTML_VIEW"

    return {
        "is_rest_class":     is_rest_class,
        "has_response_body": has_response_body,
        "produces_json":     produces_json,
        "produces_html":     produces_html,
        "return_type":       base_rt or "unknown",
        "gson_unsafe":       gson_unsafe,
        "rest_html_ct":      rest_html_ct,
        "error_reflect":     error_reflect,
        "controller_type":   ct,
    }


# ── Step 1: Reflected XSS Taint Flow 검증 함수 (v2.4.0) ─────────────────────

def check_reflected_xss_taint(method_body: str, ctrl_content: str) -> dict:
    """Step 1: REST_HTML_RISK 컨트롤러에서 사용자 입력 → HTML 출력 Taint Flow 검증.

    Taint Flow 확정 조건:
      1. 메서드 본문에서 사용자 입력 파라미터 변수명 추출
      2. return 문 또는 response.write()에서 해당 변수가 문자열 연결로 포함
      3. HTML 인코딩 함수(_P1_ESCAPE_SAFE_RE)가 경로에 없을 것

    Returns:
      taint_confirmed: True  → 실제 Reflected XSS 위험
      taint_confirmed: False → Taint Flow 미확인 (양호 또는 수동확인 필요)
    """
    # 1. 사용자 입력 파라미터 변수명 추출
    param_names: set = set()
    for m in _P1_TAINT_PARAM_EXTRACT.finditer(method_body):
        name = m.group(1) or m.group(2)
        if name:
            param_names.add(name)

    if not param_names:
        return {
            "taint_confirmed": False,
            "param_names":     [],
            "tainted_params":  [],
            "has_escape":      False,
            "reason":          "사용자 입력 파라미터 없음 — Taint Flow 불가 (양호)",
        }

    # 2. HTML 안전 인코딩 함수 존재 시 Taint 해제
    has_escape = bool(_P1_ESCAPE_SAFE_RE.search(method_body))
    if has_escape:
        return {
            "taint_confirmed": False,
            "param_names":     sorted(param_names),
            "tainted_params":  [],
            "has_escape":      True,
            "reason":          "HTML 인코딩 함수 적용 확인 (HtmlUtils/Encode.forHtml 등) — 양호",
        }

    # 3. return/write 구문에서 tainted 변수 연결 탐지
    tainted: list = []
    for m in _P1_TAINT_CONCAT_RE.finditer(method_body):
        var = m.group(1) or m.group(2) or m.group(3)
        if var and var in param_names:
            tainted.append(var)

    # 4. ResponseEntity.ok().body() 또는 ResponseEntity.ok(var) 내 변수 포함 여부
    resp_entity_re = re.compile(
        r'ResponseEntity\s*(?:<[^>]+>)?\s*\.\s*(?:ok|status)\s*\([^)]*\)'
        r'(?:\s*\.\s*body\s*\()?([^;)]+)',
        re.IGNORECASE | re.DOTALL,
    )
    for m in resp_entity_re.finditer(method_body):
        body_expr = m.group(1)
        for p in param_names:
            if re.search(rf'\b{re.escape(p)}\b', body_expr):
                tainted.append(p)

    tainted = list(dict.fromkeys(tainted))  # 중복 제거

    if tainted:
        return {
            "taint_confirmed": True,
            "param_names":     sorted(param_names),
            "tainted_params":  tainted,
            "has_escape":      False,
            "reason":          (
                f"사용자 입력 파라미터 {tainted} 가 HTML 인코딩 없이 "
                "text/html 응답에 직접 연결(Taint 확정) — Reflected XSS 실제위협"
            ),
        }

    return {
        "taint_confirmed": False,
        "param_names":     sorted(param_names),
        "tainted_params":  [],
        "has_escape":      False,
        "reason":          (
            "text/html Content-Type 설정 확인되나 "
            f"입력 파라미터 {sorted(param_names)} 의 return/write 직접 연결 미확인 — "
            "양호 (수동 확인 권장)"
        ),
    }


# ============================================================
#  4. Phase 2: View 파일 분석 (Outbound Escaping)
# ============================================================

def _extract_view_name(method_body: str) -> Optional[str]:
    """Controller 메서드 본문에서 반환 View 이름 추출"""
    m = re.search(r'return\s+"([^"]+)"', method_body)
    if m:
        name = m.group(1)
        if name.startswith(("redirect:", "forward:")):
            return None
        return name
    m = re.search(r'new\s+ModelAndView\s*\(\s*"([^"]+)"', method_body)
    if m:
        return m.group(1)
    m = re.search(r'setViewName\s*\(\s*"([^"]+)"', method_body)
    if m:
        return m.group(1)
    return None


def _extract_model_attributes(method_body: str) -> set:
    """model.addAttribute("key", ...) 에서 키 집합 추출"""
    return set(_P2_MODEL_ATTR.findall(method_body))


def _analyze_jsp(content: str, model_attrs: set) -> dict:
    """JSP 파일 취약/안전 출력 패턴 분석"""
    lines           = content.splitlines()
    has_direct_el   = False
    has_cout_unsafe = bool(_P2_JSP_COUT_UNSAFE.search(content))
    has_cout_safe   = bool(_P2_JSP_COUT_SAFE.search(content))
    has_escape_xml  = bool(_P2_JSP_ESCAPE_XML.search(content))
    has_scriptlet   = bool(_P2_JSP_SCRIPTLET_PARAM.search(content))
    vulnerable_lines: list = []

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if _P2_JSP_COUT_UNSAFE.search(stripped):
            vulnerable_lines.append((i, stripped[:120]))

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        el_hits = re.findall(r'\$\{([^}]+)\}', stripped)
        if not el_hits:
            continue
        if re.search(r'<c:out\b[^>]*value\s*=\s*"[^"]*\$\{', stripped, re.IGNORECASE):
            continue
        if re.search(r'fn:escapeXml\s*\(\s*\$\{', stripped):
            continue
        if re.search(r'<c:(?:if|when|forEach|choose)\b[^>]*\$\{', stripped, re.IGNORECASE):
            continue
        if re.search(r'\bth:(?:text|value|href|src|action)\s*=\s*["\'][^"\']*\$\{', stripped):
            continue
        has_direct_el = True
        vulnerable_lines.append((i, stripped[:120]))

    if has_scriptlet:
        for i, line in enumerate(lines, 1):
            if _P2_JSP_SCRIPTLET_PARAM.search(line):
                vulnerable_lines.append((i, line.strip()[:120]))

    return {
        "view_type":        "JSP",
        "has_direct_el":    has_direct_el,
        "has_cout_unsafe":  has_cout_unsafe,
        "has_cout_safe":    has_cout_safe,
        "has_escape_xml":   has_escape_xml,
        "has_scriptlet_out": has_scriptlet,
        "vulnerable_lines": vulnerable_lines[:10],
    }


def _analyze_thymeleaf(content: str) -> dict:
    """Thymeleaf 파일 취약/안전 출력 패턴 분석"""
    lines     = content.splitlines()
    has_utext = False
    has_text  = bool(_P2_TH_TEXT.search(content))
    vulnerable_lines: list = []

    for i, line in enumerate(lines, 1):
        if _P2_TH_UTEXT.search(line):
            has_utext = True
            vulnerable_lines.append((i, line.strip()[:120]))

    # Handlebars {{{...}}} 패턴도 확인
    has_handlebars_unsafe = bool(_P2_HANDLEBARS_UNSAFE.search(content))
    if has_handlebars_unsafe:
        for i, line in enumerate(lines, 1):
            if _P2_HANDLEBARS_UNSAFE.search(line):
                vulnerable_lines.append((i, line.strip()[:120]))

    return {
        "view_type":              "Thymeleaf",
        "has_utext":              has_utext,
        "has_text":               has_text,
        "has_handlebars_unsafe":  has_handlebars_unsafe,
        "vulnerable_lines":       vulnerable_lines[:10],
    }


def analyze_view_file(view_file: Path, model_attrs: set) -> dict:
    """View 파일 타입에 따라 JSP / Thymeleaf 분석 분기"""
    content = read_file_safe(view_file)
    if not content:
        return {"error": "파일 읽기 실패", "view_file": str(view_file)}

    ext = view_file.suffix.lower()
    if ext in _JSP_EXTS:
        result = _analyze_jsp(content, model_attrs)
    else:
        result = _analyze_thymeleaf(content)

    result["view_file"]        = str(view_file)
    result["model_attributes"] = list(model_attrs)
    return result


# ============================================================
#  5. Phase 3: 전역 XSS 필터 탐지 (Inbound Sanitizing)
# ============================================================

def _check_lucy_multipart_order(source_dir: Path) -> dict:
    """Lucy XSS Filter 존재 시 MultipartFilter 체인 순서 검증

    MultipartFilter가 LucyXssFilter 앞에 오면 Lucy 우회 가능.
    web.xml 또는 Spring Java Config에서 필터 등록 순서를 파싱.

    Returns:
      {"bypass_risk": True/False/None, "detail": str}
      True  = MultipartFilter가 Lucy보다 앞에 등록됨 (bypass 가능)
      False = Lucy가 MultipartFilter보다 앞에 등록됨 (정상)
      None  = 판단 불가 (설정 파일 미탐지)
    """
    # web.xml 탐색
    for webxml in source_dir.rglob("web.xml"):
        if any(ex in webxml.parts for ex in _EXCLUDE_DIRS):
            continue
        content = read_file_safe(webxml)
        if not content:
            continue

        # <filter-mapping> 순서로 Lucy vs Multipart 위치 비교
        lucy_pos     = -1
        multipart_pos = -1
        for i, line in enumerate(content.splitlines()):
            if _P3_LUCY_FILTER_BEAN.search(line):
                if lucy_pos == -1:
                    lucy_pos = i
            if _P3_MULTIPART_RE.search(line):
                if multipart_pos == -1:
                    multipart_pos = i

        if lucy_pos != -1 and multipart_pos != -1:
            if multipart_pos < lucy_pos:
                return {
                    "bypass_risk": True,
                    "detail": (
                        f"web.xml: MultipartFilter(line {multipart_pos+1})가 "
                        f"LucyXssFilter(line {lucy_pos+1}) 앞에 등록됨 — "
                        "multipart/form-data 요청 파라미터가 Lucy 필터를 우회할 수 있음"
                    ),
                }
            else:
                return {
                    "bypass_risk": False,
                    "detail": (
                        f"web.xml: LucyXssFilter(line {lucy_pos+1})가 "
                        f"MultipartFilter(line {multipart_pos+1}) 앞에 등록됨 — 정상"
                    ),
                }
        elif lucy_pos != -1:
            return {
                "bypass_risk": None,
                "detail": "web.xml: LucyXssFilter 발견되나 MultipartFilter 미탐지 — 수동 확인 필요",
            }

    # Java Config에서 AbstractAnnotationConfigDispatcherServletInitializer 탐색
    for fp in source_dir.rglob("*.java"):
        if any(ex in fp.parts for ex in _EXCLUDE_DIRS):
            continue
        content = read_file_safe(fp)
        if not content:
            continue
        if not (_P3_LUCY_FILTER_BEAN.search(content) or _P3_MULTIPART_RE.search(content)):
            continue

        has_lucy      = bool(_P3_LUCY_FILTER_BEAN.search(content))
        has_multipart = bool(_P3_MULTIPART_RE.search(content))
        if has_lucy and has_multipart:
            # 라인 순서 기반 간이 판단
            lines = content.splitlines()
            lp, mp = -1, -1
            for i, line in enumerate(lines):
                if _P3_LUCY_FILTER_BEAN.search(line) and lp == -1:
                    lp = i
                if _P3_MULTIPART_RE.search(line) and mp == -1:
                    mp = i
            if lp != -1 and mp != -1:
                try:
                    rel = str(fp.relative_to(source_dir))
                except ValueError:
                    rel = str(fp)
                if mp < lp:
                    return {
                        "bypass_risk": True,
                        "detail": (
                            f"{rel}: MultipartFilter 등록(line {mp+1})이 "
                            f"LucyXssFilter(line {lp+1}) 앞에 위치 — 우회 가능성 있음"
                        ),
                    }
                else:
                    return {
                        "bypass_risk": False,
                        "detail": f"{rel}: LucyXssFilter → MultipartFilter 순서 — 정상",
                    }

    return {
        "bypass_risk": None,
        "detail": "MultipartFilter 설정 위치 확인 불가 — 수동 검토 필요",
    }


def build_global_filter_status(source_dir: Path) -> dict:
    """Phase 3 (v2.4.0): web.xml / *Config.java / *Filter.java / *XSS*.java 에서
    전역 XSS 필터 탐지 후 종합 판정. Step 3 커스텀 필터 탐지 추가.

    filter_level:
      none                   — XSS 필터 미발견
      header_only            — X-XSS-Protection 헤더만 (불충분)
      inbound                — Lucy/AntiSamy/ESAPI/Jackson 입력 새니타이징
      inbound_multipart_risk — Lucy 존재하나 multipart 우회 가능성
      custom_wrapper         — 커스텀 HttpServletRequestWrapper 탐지 (수동 점검 필요)
    """
    found_lucy     = False
    found_antisamy = False
    found_esapi    = False
    found_ss_xss   = False
    found_jack     = False
    # Step 3: 커스텀 필터 추적 변수
    found_custom_wrapper  = False
    found_custom_method   = False
    custom_wrapper_files: list = []
    custom_method_files:  list = []
    has_blacklist_pattern = False
    filter_files: list = []

    glob_patterns = [
        "web.xml", "*Config*.java", "*Filter*.java",
        "*XSS*.java", "*Xss*.java", "*xss*.java",
        "*Security*.java", "*WebMvc*.java",
        # Step 3 추가: 래퍼/유틸 클래스 포함
        "*Wrapper*.java", "*Util*.java", "*Utils*.java",
    ]
    scanned: set = set()

    for glob in glob_patterns:
        for fp in source_dir.rglob(glob):
            if any(ex in fp.parts for ex in _EXCLUDE_DIRS):
                continue
            if fp in scanned:
                continue
            scanned.add(fp)

            content = read_file_safe(fp)
            if not content:
                continue

            try:
                rel = str(fp.relative_to(source_dir))
            except ValueError:
                rel = str(fp)

            hit = False
            if _P3_LUCY.search(content):
                found_lucy = True;     hit = True
            if _P3_ANTISAMY.search(content):
                found_antisamy = True; hit = True
            if _P3_ESAPI.search(content):
                found_esapi = True;    hit = True
            if _P3_SS_XSS.search(content):
                found_ss_xss = True;   hit = True
            if _P3_JACK_DESER.search(content) or _P3_JACK_MOD.search(content):
                found_jack = True;     hit = True

            # Step 3: 커스텀 필터 탐지
            if _P3_CUSTOM_WRAPPER_RE.search(content):
                found_custom_wrapper = True
                hit = True
                custom_wrapper_files.append(rel)
                if (_P3_BLACKLIST_REPLACE_RE.search(content)
                        or _P3_UNSAFE_REPLACE_RE.search(content)):
                    has_blacklist_pattern = True

            if _P3_CUSTOM_CLEAN_METHOD_RE.search(content):
                found_custom_method = True
                hit = True
                if rel not in custom_method_files:
                    custom_method_files.append(rel)
                if (_P3_BLACKLIST_REPLACE_RE.search(content)
                        or _P3_UNSAFE_REPLACE_RE.search(content)):
                    has_blacklist_pattern = True

            if hit and rel not in filter_files:
                filter_files.append(rel)

    # Lucy multipart bypass 검증
    lucy_multipart = None
    if found_lucy:
        lucy_multipart = _check_lucy_multipart_order(source_dir)

    # Step 3: 커스텀 필터 메타 정보
    custom_filter_info: Optional[dict] = None
    if found_custom_wrapper or found_custom_method:
        blacklist_warning = (
            " 블랙리스트(replace) 방식 필터링 패턴 탐지 — 우회 가능성 높음."
            if has_blacklist_pattern else
            " 필터 로직 안전성(루프 결함, 우회 가능성) 수동 점검 필요."
        )
        custom_filter_info = {
            "detected":           True,
            "wrapper_files":      custom_wrapper_files[:5],
            "method_files":       custom_method_files[:5],
            "has_blacklist":      has_blacklist_pattern,
            "manual_review_note": (
                "[정보 - 커스텀 XSS 필터 발견: 블랙리스트 방식 여부 수동 점검 필요]"
                + blacklist_warning
            ),
        }

    # 종합 판정 (공인 라이브러리 우선)
    if found_lucy:
        bypass_risk = lucy_multipart.get("bypass_risk") if lucy_multipart else None
        if bypass_risk is True:
            filter_type   = "Lucy XSS Filter (Multipart 우회 위험)"
            filter_detail = (
                "Lucy XSS Servlet Filter 적용 중이나, MultipartFilter가 앞단에 배치되어 "
                "multipart/form-data 요청 파라미터가 Lucy 필터를 우회할 수 있습니다. "
                f"상세: {lucy_multipart['detail']}"
            )
            filter_level = "inbound_multipart_risk"
        elif bypass_risk is None:
            filter_type   = "Lucy XSS Filter (Multipart 체인 불명확)"
            filter_detail = (
                "Lucy XSS Servlet Filter 적용 중. "
                f"multipart/form-data 우회 가능성: {lucy_multipart['detail'] if lucy_multipart else '확인 불가'}"
            )
            filter_level = "inbound_multipart_risk"
        else:
            filter_type   = "Lucy XSS Filter"
            filter_detail = (
                "Lucy XSS Servlet Filter 적용 중. "
                f"MultipartFilter 순서 정상 확인: {lucy_multipart['detail'] if lucy_multipart else 'N/A'}"
            )
            filter_level = "inbound"
    elif found_antisamy:
        filter_type  = "AntiSamy"
        filter_detail = "OWASP AntiSamy HTML sanitizer 적용 중."
        filter_level = "inbound"
    elif found_esapi:
        filter_type  = "ESAPI"
        filter_detail = "OWASP ESAPI encoder 적용 중."
        filter_level = "inbound"
    elif found_jack:
        filter_type  = "Jackson XSS Deserializer"
        filter_detail = "Jackson ObjectMapper에 커스텀 XSS Deserializer 등록 확인."
        filter_level = "inbound"
    # Step 3: 커스텀 필터만 발견된 경우
    elif found_custom_wrapper or found_custom_method:
        blacklist_tag = " [블랙리스트 방식 의심]" if has_blacklist_pattern else ""
        filter_type  = f"커스텀 XSS 필터{blacklist_tag}"
        filter_detail = (
            "[정보 - 커스텀 XSS 필터 발견: 블랙리스트 방식 여부 수동 점검 필요] "
            f"HttpServletRequestWrapper 상속 클래스: {custom_wrapper_files[:3]} / "
            f"커스텀 클렌징 메서드: {custom_method_files[:3]}. "
            "공인 라이브러리(Lucy/AntiSamy/ESAPI)가 아닌 자체 구현 필터입니다. "
            "HTML Entity 인코딩 방식(화이트리스트) 여부, 루프 결함, 인코딩 재처리 우회 등을 "
            "보안 담당자가 직접 점검하십시오."
        )
        filter_level = "custom_wrapper"
    elif found_ss_xss:
        filter_type  = "Spring Security XSS Header"
        filter_detail = (
            "X-XSS-Protection 응답 헤더 설정 확인. "
            "헤더 기반 방어로 최신 브라우저에서는 효과 제한적 — Outbound Escaping 병행 필요."
        )
        filter_level = "header_only"
    else:
        filter_type  = "없음"
        filter_detail = "XSS 전역 필터 미발견 — 취약 가능"
        filter_level = "none"

    is_inbound = filter_level in ("inbound", "inbound_multipart_risk")

    return {
        "has_filter":          is_inbound or filter_level == "header_only",
        "has_inbound_filter":  is_inbound,
        "filter_type":         filter_type,
        "filter_detail":       filter_detail,
        "filter_level":        filter_level,
        "has_lucy":            found_lucy,
        "has_antisamy":        found_antisamy,
        "has_esapi":           found_esapi,
        "has_ss_xss":          found_ss_xss,
        "has_jackson_xss":     found_jack,
        "lucy_multipart":      lucy_multipart,
        "filter_files":        filter_files,
        # Step 3 신규 필드
        "has_custom_filter":   found_custom_wrapper or found_custom_method,
        "custom_filter_info":  custom_filter_info,
    }


# ============================================================
#  6. Phase 4: Redirect / Open Redirect 패턴 탐색
# ============================================================

def analyze_redirect_patterns(method_body: str) -> dict:
    """Phase 4: 메서드 본문에서 서버사이드 + 클라이언트사이드 Redirect 취약 패턴 탐색

    confidence:
      high   — @RequestParam / getParameter 등 사용자 입력 컨텍스트 확인
      medium — redirect 패턴 발견되나 입력 출처 불분명
    """
    findings: list = []
    lines = method_body.splitlines()

    has_user_ctx = bool(_P4_USER_PARAM_CTX.search(method_body))

    # 서버사이드 패턴
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        for pattern, desc in _P4_REDIRECT_PATTERNS:
            if pattern.search(stripped):
                if re.search(r'sendRedirect\s*\(\s*"[^"]*"\s*\)', stripped):
                    continue
                findings.append({
                    "type":       desc,
                    "side":       "server",
                    "line":       i,
                    "snippet":    stripped[:120],
                    "confidence": "high" if has_user_ctx else "medium",
                })
                break

    # 클라이언트사이드 패턴 (JSP 인라인 JS / 메서드 본문 내 스크립트 블록)
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("//"):
            continue
        for pattern, desc in _P4_CLIENT_REDIRECT_PATTERNS:
            if pattern.search(stripped):
                findings.append({
                    "type":       desc,
                    "side":       "client",
                    "line":       i,
                    "snippet":    stripped[:120],
                    "confidence": "medium",
                })
                break

    return {
        "has_redirect_risk": bool(findings),
        "findings":          findings[:10],
    }


# ============================================================
#  7. Phase 5: Persistent XSS — Taint Tracking (v2.0.0 전면 강화)
# ============================================================

# ── Fix 1: sqli_result DB write 정확도 향상 ──────────────────

def _sqli_has_db_write(sqli_result: dict, ep_api: str) -> tuple:
    """sqli_result에서 DB write 경로 확인 (write 키워드 기반 정밀 판별).

    jpa_builtin / querydsl_safe 등은 READ 경로도 포함하므로,
    detail 또는 method_name에 write 키워드가 있을 때만 write로 간주.

    Returns: (has_write: bool, detail_snippet: str)
    """
    for diag in sqli_result.get("endpoint_diagnoses", []):
        if diag.get("request_mapping", "") != ep_api:
            continue
        for op in diag.get("db_operations", []):
            access_type = op.get("access_type", "")
            if access_type in ("none", "unknown", "non-DB", ""):
                continue
            detail      = op.get("detail", "")
            method_name = op.get("method_name", op.get("method", ""))
            # 모호한 access_type → detail / method_name에서 write 키워드 확인
            if access_type in ("jpa_builtin", "querydsl_safe", "mybatis_safe"):
                if (_P5_WRITE_DETAIL_RE.search(detail)
                        or _P5_WRITE_DETAIL_RE.search(method_name)):
                    return True, detail[:80]
                continue  # write 키워드 없음 → READ 경로 → skip
            # 명시적 취약/불명확 access_type → 보수적으로 write 간주
            return True, detail[:80]
        break
    return False, ""


# ── Fix 2: Enum/Type Casting Taint 해제 ─────────────────────

def _check_enum_validation(code: str, param_names: set) -> set:
    """코드에서 Enum/Type 화이트리스트 검증 패턴 탐지.

    _P5_SANITIZE_PATTERNS 목록으로 Enum.from(var), Integer.parseInt(var) 등
    단일 인수 type-safe 변환 패턴을 탐지하여 검증된 파라미터 이름 집합을 반환.

    Returns: sanitized param names (param_names 교차 결과)
    """
    sanitized: set = set()
    for pattern in _P5_SANITIZE_PATTERNS:
        for m in pattern.finditer(code):
            var = m.group(1)
            if var in param_names:
                sanitized.add(var)
    return sanitized


# ── Fix 3: 보수적 폴백 완화 (자유 텍스트 파라미터 없으면 양호) ──

def _inspect_dto_fields(dto_type: str,
                        class_index: dict,
                        source_dir: Path) -> Optional[bool]:
    """@RequestBody DTO/Record 클래스 필드를 1레벨 검사 — 모두 비-자유텍스트인지 확인.

    Returns:
      True  → 전체 필드가 비-자유텍스트(Integer/Boolean/UUID/날짜 등) → XSS 불가
      False → 자유텍스트(String 등) 필드 존재
      None  → 판정 불가 (파일 미탐색 또는 필드 미추출)
    """
    dto_file = class_index.get(dto_type) if class_index else None
    if not dto_file and source_dir:
        hits = (list(source_dir.rglob(f"{dto_type}.java"))
                + list(source_dir.rglob(f"{dto_type}.kt")))
        if hits:
            dto_file = hits[0]
    if not dto_file:
        return None

    content = read_file_safe(dto_file)
    if not content:
        return None

    # Java record: record Foo(@Min(1) Integer name1, Type2 name2, ...)
    # [^)]+ 대신 균형 괄호 탐색: @Min(1) 같은 중첩 괄호 어노테이션 처리
    record_start = re.search(r'\brecord\s+\w+\s*\(', content)
    if record_start:
        pos = record_start.end() - 1  # 첫 '(' 위치
        depth = 0
        end = pos
        for i in range(pos, len(content)):
            ch = content[i]
            if ch == '(':
                depth += 1
            elif ch == ')':
                depth -= 1
                if depth == 0:
                    end = i
                    break
        inner = content[pos + 1:end]
        # inner를 쉼표로 분할하되 괄호 내부 쉼표는 무시
        components: list = []
        cur: list = []
        d = 0
        for ch in inner:
            if ch == '(':
                d += 1
                cur.append(ch)
            elif ch == ')':
                d -= 1
                cur.append(ch)
            elif ch == ',' and d == 0:
                components.append(''.join(cur))
                cur = []
            else:
                cur.append(ch)
        if cur:
            components.append(''.join(cur))

        types = []
        for comp in components:
            comp = comp.strip()
            if not comp:
                continue
            # 어노테이션 제거: @Min(1) Integer name → Integer name
            comp = re.sub(r'@\w+(?:\s*\([^)]*\))?\s*', '', comp)
            # 줄바꿈/탭 등 공백 정규화
            comp = re.sub(r'\s+', ' ', comp).strip()
            parts = comp.split()
            if parts:
                base = parts[0].split("<")[0].split(".")[-1]
                types.append(base)
        if types:
            return all(t in _P5_NON_FREETEXT_TYPES for t in types)

    # 일반 클래스 필드: private/public/protected [final] Type name
    field_re = re.compile(
        r'(?:private|protected|public)\s+(?:final\s+)?(\w+(?:<[^>]+>)?)\s+\w+\s*[=;,\)]'
    )
    found = []
    for m in field_re.finditer(content):
        base = m.group(1).split("<")[0].split(".")[-1]
        if base in ("Logger", "ObjectMapper", "serialVersionUID"):
            continue
        found.append(base)
    if not found:
        return None
    return all(t in _P5_NON_FREETEXT_TYPES for t in found)


def _has_freetext_params(endpoint: dict,
                         class_index: Optional[dict] = None,
                         source_dir: Optional[Path] = None) -> bool:
    """HTTP 파라미터 중 자유 텍스트(String) 입력이 존재하는지 확인.

    Returns:
      True  → String/Object 입력 가능 → Persistent XSS 추적 필요
      False → 모든 파라미터가 비-자유텍스트(Integer/Enum/인증객체 등) → XSS 불가
    """
    params = endpoint.get("parameters", [])
    if not params:
        return False  # 파라미터 없음 → 사용자 자유 입력 없음

    for p in params:
        ann   = p.get("annotation", "").strip()
        dtype = p.get("data_type", p.get("type", "")).strip()
        base  = dtype.split("<")[0].split(".")[-1].strip()

        # 인증 객체 (@AuthenticationPrincipal, @SessionAttribute) → 자유 입력 아님
        if "@AuthenticationPrincipal" in ann or "@SessionAttribute" in ann:
            continue
        if base in ("User", "Principal", "Authentication", "UserDetails",
                    "CustomUserDetails"):
            continue

        # 명시적 비-자유텍스트 원시/값 타입
        if base in _P5_NON_FREETEXT_TYPES:
            continue

        # @RequestBody → DTO 필드 1레벨 검사 (v2.3.2)
        # annotation 필드 또는 type 필드("body")로 @RequestBody 감지
        is_request_body = "@RequestBody" in ann or p.get("type", "") == "body"
        if is_request_body:
            if base and class_index is not None and source_dir is not None:
                all_nonfree = _inspect_dto_fields(base, class_index, source_dir)
                if all_nonfree is True:
                    continue  # 모든 필드 비-자유텍스트 → 이 파라미터는 freetext 아님
            return True

        # 타입 미상 또는 String → freetext
        if not dtype or dtype in ("String", "string", "Object", "Any", "object"):
            return True

        # @PathVariable/@RequestParam + 대문자 비-String 타입 → Enum 추정 → non-freetext
        # (실제 Enum 검증 여부는 Fix 2에서 별도 확인)
        if base and base[0].isupper() and base not in _P5_NON_FREETEXT_TYPES:
            if "@PathVariable" in ann or "@RequestParam" in ann:
                continue

        # 기타 → 보수적으로 freetext 가정
        return True

    return False  # 모든 파라미터가 non-freetext


def _resolve_svc_impl_body(svc_type: str, svc_method: str,
                            class_index: dict, source_dir: Path) -> tuple:
    """UseCase/Port 인터페이스 → Service/Adapter 구현체 이름 변환 후 메서드 본문 반환.

    1. class_index 직접 조회  2. source_dir glob 폴백 (.java / .kt)
    Returns: (method_body: str, impl_content: str) — 실패 시 ("", "")
    """
    for iface_suf, impl_suf in _P5_IFACE_TO_IMPL_SUFFIX:
        if not svc_type.endswith(iface_suf):
            continue
        impl_name = svc_type[: -len(iface_suf)] + impl_suf
        impl_file = class_index.get(impl_name)
        if not impl_file:
            hits = (list(source_dir.rglob(f"{impl_name}.java"))
                    + list(source_dir.rglob(f"{impl_name}.kt")))
            if hits:
                impl_file = hits[0]
        if not impl_file:
            continue
        impl_content = read_file_safe(impl_file)
        if not impl_content:
            continue
        body = extract_method_body(impl_content, svc_method) or ""
        if body:
            return body, impl_content
    return "", ""


def _has_param_in_direct_call(svc_body: str, repo_field: str,
                               repo_method: str, param_names: set) -> bool:
    """Repository 호출 인수에 HTTP 파라미터가 standalone 변수로 직접 전달되는지 확인.

    'log.dto().id()' → id는 method chain → 제외 (DTO 래핑에서도 entity 자체만 보임).
    패턴: (?<![.\\w])varName(?!\\s*\\() — 앞에 '.' 없고 뒤에 '(' 없는 식별자.
    """
    call_re = re.compile(
        rf'(?<![.\w]){re.escape(repo_field)}\.{re.escape(repo_method)}\s*\(([^)]*)\)',
    )
    standalone_re = re.compile(r'(?<![.\w])(\w+)(?!\s*\()')
    for m in call_re.finditer(svc_body):
        args_str = m.group(1)
        for vm in standalone_re.finditer(args_str):
            if vm.group(1) in param_names:
                return True
    return False


def _check_repo_param_context(repo_content: str, repo_method: str,
                               param_names: set) -> str:
    """Repository 메서드 본문에서 SET(저장) vs WHERE(필터) 구조 판정.

    변수명 매칭 없이 구조적 패턴으로 판정 (repo 내부 param명이 다를 수 있으므로).

    Returns:
      "set"     → SET 절 패턴 발견 → taint 확인
      "where"   → WHERE 절만, SET/UPDATE/INSERT 없음 → taint 해제
      "unknown" → 판정 불가 → 보수적 폴백
    """
    repo_body = extract_method_body(repo_content, repo_method) or ""
    if not repo_body:
        # 인터페이스/추상 메서드 — 메서드 명칭 휴리스틱으로 판정
        # read 접두사(find/get/list/...) → 읽기 전용 관례 → "where"
        # write 접두사는 호출 측에서 _P5_WRITE_METHOD_RE로 별도 처리
        if _P5_READ_METHOD_RE.match(repo_method):
            return "where"
        return "unknown"

    # SET 절 지시자 우선 확인
    if _P5_QDSL_SET_RE.search(repo_body):          # QueryDSL .set(col, val)
        return "set"
    if _P5_ENTITY_SETTER_RE.search(repo_body):      # JPA entity.setXxx(val)
        return "set"
    if _P5_BUILDER_SET_RE.search(repo_body):        # Builder .builder().field(val)
        return "set"
    if _P5_PERSIST_NEW_RE.search(repo_body):        # persist(new Entity(...)) — 엔티티 생성자 INSERT
        return "set"

    # WHERE 절 지시자 (SELECT/WHERE only → 안전)
    has_where = bool(
        re.search(r'\.where\s*\(', repo_body, re.IGNORECASE)
        or re.search(r'\bWHERE\b', repo_body)
    )
    has_update_insert = bool(
        re.search(r'\bUPDATE\b|\bINSERT\b|\bpersist\b|\bmerge\b',
                  repo_body, re.IGNORECASE)
    )
    if has_where and not has_update_insert:
        return "where"

    return "unknown"


def _trace_persistent_xss_taint(endpoint: dict,
                                  ctrl_content: str,
                                  handler_method: str,
                                  source_dir: Path,
                                  class_index: dict) -> dict:
    """Controller HTTP 파라미터 → Service → Repository write 메서드 Taint Tracking

    Returns:
      {
        "taint_confirmed": Optional[bool],
        "call_chain": list,           # [ctrl_method, svc.method, repo.method]
        "write_method": str,          # 마지막 write 메서드명
        "reason": str,
      }
      taint_confirmed = True  → HTTP 입력이 DB write 경로로 흐름 확정
      taint_confirmed = False → Repository write 경로 미확인
      taint_confirmed = None  → 추적 불가 (Controller 본문 없음, Service 탐지 실패 등)
    """
    # HTTP 파라미터 이름 추출 (인증 객체 제외 — 사용자 자유 입력만 추적)
    params = endpoint.get("parameters", [])
    param_names: set = set()
    for _p in params:
        _name = _p.get("name", "")
        if not _name:
            continue
        _ann   = _p.get("annotation", "")
        _dtype = _p.get("data_type", _p.get("type", "")).split("<")[0].split(".")[-1].strip()
        # @AuthenticationPrincipal / 인증 객체 타입 → 자유 입력 아님 → taint 제외
        if "@AuthenticationPrincipal" in _ann or "@SessionAttribute" in _ann:
            continue
        if _dtype in ("User", "Principal", "Authentication", "UserDetails",
                      "CustomUserDetails"):
            continue
        param_names.add(_name)

    if not param_names:
        if params:
            # 파라미터는 있지만 모두 인증 객체 → 자유 텍스트 입력 없음
            return {
                "taint_confirmed": False,
                "sanitized":       True,
                "reason":          "모든 HTTP 파라미터가 인증 객체 — 사용자 자유 텍스트 입력 없음",
            }
        return {"taint_confirmed": None, "reason": "HTTP 파라미터 정보 없음 — 추적 불가"}

    # Step 1: Controller 메서드 본문
    ctrl_body = extract_method_body(ctrl_content, handler_method) or ""
    if not ctrl_body:
        return {"taint_confirmed": None, "reason": "Controller 메서드 본문 추출 실패"}

    # Step 1.5: Fix 2 — Enum/Type 화이트리스트 검증 탐지 (taint 해제)
    _sanitized = _check_enum_validation(ctrl_body, param_names)
    # 1레벨: Command/DTO factory method → 해당 클래스 body에서도 검증 패턴 탐지
    for _m in _P5_CMD_FACTORY_RE.finditer(ctrl_body):
        _cls = _m.group(1)
        if _cls.endswith(_P5_CMD_SUFFIXES):
            _fp = class_index.get(_cls) if class_index else None
            if not _fp:
                # Java record / inner class 등 class_index 누락 대비 glob 폴백
                _hits = list(source_dir.rglob(f"{_cls}.java"))
                if _hits:
                    _fp = _hits[0]
            if _fp:
                _cnt = read_file_safe(_fp)
                if _cnt:
                    _sanitized |= _check_enum_validation(_cnt, param_names)
    if _sanitized:
        _remaining = param_names - _sanitized
        if not _remaining:
            # 모든 추적 대상 파라미터가 Enum/Type 검증으로 taint 해제됨
            return {
                "taint_confirmed":  False,
                "sanitized":        True,
                "sanitized_params": sorted(_sanitized),
                "reason": (
                    f"HTTP 파라미터 {sorted(_sanitized)} 가 Enum/Type 화이트리스트 검증으로 "
                    "taint 해제 — Persistent XSS 불가"
                ),
            }
        param_names = _remaining  # 잔여 파라미터만 taint 추적 계속

    # Step 2: Controller → Service 의존성 파악
    ctrl_deps = extract_constructor_deps(ctrl_content)
    svc_fields = [
        (name, typ) for name, typ in ctrl_deps
        if any(typ.endswith(s) for s in _P5_SVC_SUFFIXES)
    ]

    if not svc_fields:
        return {"taint_confirmed": None, "reason": "Service 계층 의존성 탐지 실패"}

    # Step 3: Controller 본문에서 Service 메서드 호출 추출
    svc_field_names = [name for name, _ in svc_fields]
    svc_calls = extract_method_calls(ctrl_body, svc_field_names)

    if not svc_calls:
        return {"taint_confirmed": None, "reason": "Controller 본문 내 Service 호출 없음"}

    # Step 4: 각 Service 메서드 본문에서 Repository write 호출 탐색
    for svc_field, svc_method in svc_calls:
        svc_type = next((typ for name, typ in svc_fields if name == svc_field), None)
        if not svc_type:
            continue

        svc_file = class_index.get(svc_type)
        if not svc_file:
            # 구현체 이름으로 폴백 (e.g., FooServiceImpl)
            svc_file = class_index.get(svc_type + "Impl")
        if not svc_file:
            continue

        svc_content = read_file_safe(svc_file)
        if not svc_content:
            continue

        svc_body = extract_method_body(svc_content, svc_method) or ""
        if not svc_body:
            # v2.3.0: UseCase/Port 인터페이스 → Service/Adapter 구현체 해석
            svc_body, svc_content = _resolve_svc_impl_body(
                svc_type, svc_method, class_index, source_dir
            )
            if not svc_body:
                continue

        # Repository/DAO 의존성 파악
        svc_deps = extract_constructor_deps(svc_content)
        repo_fields = [
            (name, typ) for name, typ in svc_deps
            if any(typ.endswith(s) for s in _P5_REPO_SUFFIXES)
        ]
        if not repo_fields:
            continue

        repo_field_names = [name for name, _ in repo_fields]
        repo_calls = extract_method_calls(svc_body, repo_field_names)

        # v2.3.0: WHERE 절 확인 기반 안전성 판정 (모든 repo 메서드 순회)
        where_confirmed_params: set = set()

        for repo_field, repo_method in repo_calls:
            # HTTP param이 이 repo 메서드 인수에 standalone으로 직접 전달되는지 확인
            if not _has_param_in_direct_call(svc_body, repo_field, repo_method, param_names):
                # DTO 래핑 등으로 직접 전달 안 됨 → 추적 계속 (sanitized 처리 안 함)
                continue

            # param이 직접 전달됨 → repo 메서드 본문에서 SET vs WHERE 판정
            repo_type = next(
                (typ for name, typ in repo_fields if name == repo_field), None
            )
            repo_file = class_index.get(repo_type) if repo_type else None
            if not repo_file and repo_type:
                hits = (list(source_dir.rglob(f"{repo_type}.java"))
                        + list(source_dir.rglob(f"{repo_type}.kt")))
                if hits:
                    repo_file = hits[0]

            if repo_file:
                repo_content_data = read_file_safe(repo_file)
                if repo_content_data:
                    ctx = _check_repo_param_context(
                        repo_content_data, repo_method, param_names
                    )
                    if ctx == "where":
                        # WHERE 절만 사용 확인 → 이 파라미터들은 안전
                        where_confirmed_params |= param_names
                        continue
                    elif ctx == "set":
                        # SET 절 사용 확인 → DB 저장 → taint 확인
                        return {
                            "taint_confirmed": True,
                            "call_chain": [
                                handler_method,
                                f"{svc_field}.{svc_method}()",
                                f"{repo_field}.{repo_method}()",
                            ],
                            "write_method": f"{repo_field}.{repo_method}",
                            "reason": (
                                f"HTTP 파라미터 → {svc_field}.{svc_method}() → "
                                f"{repo_field}.{repo_method}() SET 절 DB 저장 경로 확인"
                            ),
                        }
                    # ctx == "unknown" → fall through

            # repo 파일 못 찾거나 unknown context → write 메서드이면 보수적 taint 확인
            if _P5_WRITE_METHOD_RE.match(repo_method):
                return {
                    "taint_confirmed": True,
                    "call_chain": [
                        handler_method,
                        f"{svc_field}.{svc_method}()",
                        f"{repo_field}.{repo_method}()",
                    ],
                    "write_method": f"{repo_field}.{repo_method}",
                    "reason": (
                        f"HTTP 파라미터 → {svc_field}.{svc_method}() → "
                        f"{repo_field}.{repo_method}() DB 저장 경로 확인"
                    ),
                }

        # WHERE 절로 확인된 파라미터가 모든 추적 대상을 포함하면 → 안전 후보
        # ★ Worst-case 원칙: 서비스 메서드 내 write 접두사 메서드가 하나라도 존재하면
        #   _has_param_in_direct_call=False로 스킵된 엔티티 래핑 write 경로가 있을 수 있으므로
        #   WHERE-only 판정을 절대 적용하지 않는다.
        svc_has_any_write = any(
            _P5_WRITE_METHOD_RE.match(rm) for _, rm in repo_calls
        )
        if (where_confirmed_params and where_confirmed_params >= param_names
                and not svc_has_any_write):
            return {
                "taint_confirmed": False,
                "sanitized":       True,
                "reason": (
                    f"HTTP 파라미터 {sorted(param_names)} 가 WHERE 절 조건에만 사용 확인 "
                    "(SET 절 미사용, 서비스 내 write 메서드 없음) — Persistent XSS 불가"
                ),
            }

    # Step 5 (v2.3.0): Controller 레벨 직접 Port/Repo 호출 안전성 체크
    # 헥사고날 아키텍처: Controller → FindPort(읽기 WHERE) + Controller → UseCase(도메인 객체 전달)
    # HTTP param이 Controller 레벨 읽기 Port에만 standalone 전달되고 Service 호출 인수에 없으면 → 안전
    ctrl_repo_fields = [
        (name, typ) for name, typ in ctrl_deps
        if any(typ.endswith(s) for s in _P5_REPO_SUFFIXES)
    ]
    if ctrl_repo_fields and param_names:
        ctrl_repo_calls = extract_method_calls(ctrl_body, [n for n, _ in ctrl_repo_fields])
        ctrl_where_found = False
        ctrl_write_found = False
        for repo_field, repo_method in ctrl_repo_calls:
            if not _has_param_in_direct_call(ctrl_body, repo_field, repo_method, param_names):
                continue
            # param이 standalone으로 직접 전달됨 → 메서드 명칭으로 read/write 판정
            if _P5_READ_METHOD_RE.match(repo_method):
                ctrl_where_found = True
            elif _P5_WRITE_METHOD_RE.match(repo_method):
                ctrl_write_found = True
                break  # 즉시 write 확인 → 추가 체크 불필요
        if ctrl_where_found and not ctrl_write_found:
            # HTTP param이 Service/UseCase 호출 인수에 standalone으로 전달되는지 확인
            param_in_svc = any(
                _has_param_in_direct_call(ctrl_body, sf, sm, param_names)
                for sf, sm in svc_calls
            )
            if not param_in_svc:
                return {
                    "taint_confirmed": False,
                    "sanitized":       True,
                    "reason": (
                        f"HTTP 파라미터 {sorted(param_names)} 가 Controller 레벨 "
                        "읽기(read) Port 호출 조건에만 사용 확인 "
                        "(Service/UseCase 호출에 미전달) — Persistent XSS 불가"
                    ),
                }

    return {"taint_confirmed": False, "reason": "Repository write 메서드 호출 경로 미확인"}


def check_persistent_xss(endpoint: dict,
                          sqli_result: Optional[dict],
                          filter_status: dict,
                          ctrl_content: str = "",
                          handler_method: str = "",
                          source_dir: Optional[Path] = None,
                          class_index: Optional[dict] = None) -> dict:
    """Phase 5: POST/PUT + DB write + XSS 필터 미적용 조합 판정

    risk level:
      없음          — GET endpoint / DB write 경로 명확히 없음 (Fix 1/2/3 통과)
      낮음          — Inbound XSS 필터 적용 중 (입력 새니타이징 확인)
      lucy_bypass   — Lucy 필터 있으나 Multipart 우회 가능성 → 정보
      취약          — (a) Taint 확정 + 필터 없음  (b) sqli write 확인 + 필터 없음
                      (c) POST/PUT + 자유텍스트 파라미터 + 필터 없음 (DB write 경로 불명 → 보수적 취약)
      ※ v2.2.0: Fix 1/2/3을 통과한 잠재 케이스 모두 "취약"으로 승급.
                 "없음"만이 양호를 의미한다.
    """
    http_method = endpoint.get("method", "GET").upper()
    is_write    = http_method in ("POST", "PUT", "PATCH")

    if not is_write:
        return {"risk": "없음", "reason": "GET 전용 endpoint — Persistent XSS 경로 없음"}

    # Fix 3: 자유 텍스트(String) HTTP 파라미터가 없으면 조기 양호 반환 (v2.3.2: DTO 필드 검사 포함)
    if not _has_freetext_params(endpoint, class_index=class_index, source_dir=source_dir):
        return {
            "risk":   "없음",
            "reason": "자유 텍스트(String) HTTP 입력 파라미터 없음 — Persistent XSS 입력 경로 없음",
        }

    # Taint Tracking (Phase 5 강화 - v2.0.0)
    taint_result = None
    if ctrl_content and handler_method and source_dir and class_index:
        taint_result = _trace_persistent_xss_taint(
            endpoint, ctrl_content, handler_method, source_dir, class_index
        )

    taint_confirmed = taint_result.get("taint_confirmed") if taint_result else None
    taint_sanitized = taint_result.get("sanitized", False) if taint_result else False
    call_chain      = taint_result.get("call_chain", []) if taint_result else []
    write_method    = taint_result.get("write_method", "") if taint_result else ""

    # Fix 2: Enum/Type sanitization으로 taint 해제 확정 → 즉시 양호 반환
    if taint_sanitized:
        return {
            "risk":         "없음",
            "reason":       taint_result.get("reason", "Enum/Type 화이트리스트 검증으로 XSS 불가"),
            "taint_result": taint_result,
        }

    # Fix 1: sqli_result 기반 DB write 확인 (write 키워드 기반 정밀 판별)
    has_db_write_from_sqli, db_write_detail_sqli = (
        _sqli_has_db_write(sqli_result, endpoint.get("api", ""))
        if sqli_result else (False, "")
    )

    # Taint 미확정이면 sqli_result 폴백
    if taint_confirmed is None:
        if not has_db_write_from_sqli and sqli_result:
            return {"risk": "없음", "reason": "SQL Injection 결과 내 DB write 경로 미확인"}
        elif not sqli_result:
            # sqli_result 없는 경우 — HTTP write method 자체를 잠재로 간주
            has_db_write_from_sqli = True
            db_write_detail_sqli   = "SQL Injection 결과 없음 — DB 저장 경로 추정"

    # 전역 Inbound 필터 (진짜 inbound만, multipart_risk 제외)
    filter_level = filter_status.get("filter_level", "none")
    if filter_level == "inbound":
        return {
            "risk":   "낮음",
            "reason": (
                f"전역 {filter_status['filter_type']} 입력 새니타이징 적용 중. "
                "필터 커버리지 추가 검토 권장."
            ),
            "taint_result": taint_result,
        }

    # Step 3: 커스텀 필터 발견 — 안전성 불명확 → 정보 분류
    if filter_level == "custom_wrapper":
        custom_info = filter_status.get("custom_filter_info", {})
        return {
            "risk":   "정보",
            "reason": (
                "[정보 - 커스텀 XSS 필터 발견: 블랙리스트 방식 여부 수동 점검 필요] "
                f"{filter_status.get('filter_detail', '')} "
                "커스텀 필터의 안전성(HTML Entity 인코딩 여부, 루프 결함, 우회 가능성)이 "
                "자동으로 검증되지 않아 Persistent XSS 위험 제거를 단정할 수 없음. "
                "보안 담당자의 직접 코드 리뷰 필요."
            ),
            "taint_result":       taint_result,
            "custom_filter_info": custom_info,
        }

    if filter_level == "inbound_multipart_risk":
        lucy_detail = ""
        if filter_status.get("lucy_multipart"):
            lucy_detail = filter_status["lucy_multipart"].get("detail", "")
        return {
            "risk":   "lucy_bypass",
            "reason": (
                f"Lucy XSS Filter 존재하나 multipart/form-data 우회 가능성: {lucy_detail}"
            ),
            "taint_result": taint_result,
        }

    # 필터 없음 — taint 확정 여부로 위험도 분기
    if taint_confirmed is True:
        chain_str = " → ".join(call_chain) if call_chain else write_method
        return {
            "risk":            "취약",
            "reason":          (
                f"[Taint 확정] HTTP 입력 → {chain_str} → DB 저장 경로 추적 완료. "
                "XSS 전역 필터 미적용 상태에서 저장된 스크립트가 타 컨텍스트(어드민 웹 등)에서 "
                "렌더링될 경우 Stored XSS 실현 가능."
            ),
            "taint_result":    taint_result,
            "call_chain":      call_chain,
        }
    elif has_db_write_from_sqli:
        # sqli 결과로 DB write 경로 확인 → 보수적 판정: 취약 (잠재적 위협)
        # (Taint 경로 자동 추적 실패했더라도 구조적 위험으로 간주)
        taint_note = taint_result.get("reason", "미수행") if taint_result else "미수행"
        return {
            "risk":            "취약",
            "reason":          (
                f"[DB write 확인] POST/PUT endpoint + SQL 분석 기반 DB 저장 경로 확인 "
                f"({db_write_detail_sqli}) + XSS 전역 필터 미적용. "
                "저장된 스크립트가 타 컨텍스트에서 렌더링될 경우 Stored XSS 실현 가능. "
                f"(Taint 자동 추적: {taint_note})"
            ),
            "taint_result":    taint_result,
        }
    elif taint_confirmed is False:
        # Fix 1/2/3을 모두 통과한 POST/PUT — DB write 경로 자동 추적 실패여도 보수적 "취약" 판정
        # (사용자 자유 텍스트 입력 + 전역 필터 없음 = Stored XSS 잠재적 위협)
        return {
            "risk":            "취약",
            "reason":          (
                "[DB write 확인] 자유 텍스트 입력값이 전역 필터 없이 DB에 저장됨. "
                "타 컨텍스트 렌더링 시 Stored XSS 실현 가능. "
                "(DB write 경로 자동 추적 불가 — 수동 검토 권장)"
            ),
            "taint_result":    taint_result,
        }

    # 모든 조건 미해당 — Fix 1/2/3 통과 POST/PUT + 전역 필터 없음 → 보수적 취약 판정
    return {
        "risk":         "취약",
        "reason":       (
            "[DB write 확인] 자유 텍스트 입력값이 전역 필터 없이 DB에 저장됨. "
            "타 컨텍스트 렌더링 시 Stored XSS 실현 가능."
        ),
        "taint_result": taint_result,
    }


# ============================================================
#  8. Phase 6: DOM XSS 전역 스캔
# ============================================================

def scan_dom_xss_global(source_dir: Path) -> dict:
    """Phase 6 (v2.4.0): JS/TS/Vue 파일에서 DOM XSS 취약 패턴 전역 스캔.
    Step 2: 라이브러리/벤더 파일은 _P6_DOM_EXCLUDE_RE 기준으로 스캔 제외.
    """
    findings: list      = []
    files_scanned: int  = 0
    files_excluded: int = 0
    excluded_files: list = []
    safe_ctx_files: list = []

    for ext in _JS_SCAN_EXTS:
        for fp in source_dir.rglob(f"*{ext}"):
            if any(ex in fp.parts for ex in _EXCLUDE_DIRS):
                continue

            try:
                rel_path = str(fp.relative_to(source_dir))
            except ValueError:
                rel_path = str(fp)

            # Step 2: 라이브러리 파일 제외
            if _P6_DOM_EXCLUDE_RE.search(fp.name) or _P6_DOM_EXCLUDE_RE.search(rel_path):
                files_excluded += 1
                excluded_files.append(rel_path)
                continue

            content = read_file_safe(fp)
            if not content:
                continue
            files_scanned += 1

            has_safe_ctx = bool(_P6_DOM_SAFE_CTX.search(content))
            if has_safe_ctx:
                safe_ctx_files.append(rel_path)

            lines = content.splitlines()
            for i, line in enumerate(lines, 1):
                stripped = line.strip()
                if not stripped or stripped.startswith("//"):
                    continue

                for pattern, desc in _P6_DOM_VULN_PATTERNS:
                    if pattern.search(stripped):
                        findings.append({
                            "file":         rel_path,
                            "line":         i,
                            "snippet":      stripped[:120],
                            "type":         desc,
                            "has_safe_ctx": has_safe_ctx,
                        })
                        break

    seen_types: set = set()
    deduped: list = []
    for f in findings:
        key = (f["file"], f["type"])
        if key not in seen_types:
            seen_types.add(key)
            deduped.append(f)

    risk = "잠재" if deduped else "없음"
    vuln_files = sorted({f["file"] for f in deduped if not f.get("has_safe_ctx")})

    return {
        "js_files_scanned":  files_scanned,
        "js_files_excluded": files_excluded,      # Step 2 신규
        "excluded_files":    excluded_files[:10], # Step 2 신규
        "findings_count":    len(deduped),
        "safe_ctx_files":    safe_ctx_files[:5],
        "vuln_files":        vuln_files[:10],
        "findings":          deduped[:30],
        "risk":              risk,
        "summary": (
            f"JS/TS/Vue {files_scanned}개 파일 스캔 "
            f"(라이브러리 {files_excluded}개 제외) — "
            f"DOM XSS 잠재 패턴 {len(deduped)}건 발견 "
            f"(sanitize 컨텍스트 파일 {len(safe_ctx_files)}개 포함)"
            if deduped else
            f"JS/TS/Vue {files_scanned}개 파일 스캔 "
            f"(라이브러리 {files_excluded}개 제외) — DOM XSS 패턴 미발견"
        ),
    }


# ============================================================
#  9. Endpoint별 최종 판정 (Phase 1 ~ 5 통합, per-type 판정)
# ============================================================

# 판정 순위 (숫자가 클수록 더 나쁜 결과)
_VERDICT_RANK = {"해당없음": 0, "양호": 1, "정보": 2, "취약": 3}
_SEV_RANK     = {"N/A": 0, "Info": 1, "Low": 2, "Medium": 3, "High": 4, "Critical": 5}


def _worst_verdict(*verdicts: str) -> str:
    """여러 판정 중 worst-case 반환"""
    return max(verdicts, key=lambda v: _VERDICT_RANK.get(v, 0))


def _assign_xss_category(result: str, xss_type: str, persistent_risk: str = "") -> str:
    """xss_category 값 결정

    취약:
      실제위협     — Reflected XSS, View XSS (직접 렌더링)
      잠재적위협   — Persistent XSS (저장소 오염), Redirect XSS
      인코딩누락   — 인코딩 처리 불명확
    정보:
      수동확인필요 — 판정 불가, Lucy 우회 가능성
    양호:
      안전확인     — 명시적 escaping, 입력 없음, DB 접근 없음
    """
    if result == "취약":
        if "View" in xss_type or "Reflected" in xss_type:
            return "실제위협"
        if "Persistent" in xss_type or persistent_risk in ("취약", "잠재"):
            return "잠재적위협"
        if "Redirect" in xss_type:
            return "잠재적위협"
        return "실제위협"
    if result == "정보":
        if "Persistent" in xss_type or persistent_risk in ("잠재", "lucy_bypass"):
            return "잠재적위협"
        return "수동확인필요"
    if result == "양호":
        return "안전확인"
    return "해당없음"


def judge_xss_endpoint(endpoint: dict,
                       ctrl_content: str,
                       handler_method: str,
                       view_index: dict,
                       view_prefix: str,
                       view_suffix: str,
                       filter_status: dict,
                       sqli_result: Optional[dict],
                       source_dir: Path,
                       extra_rest_annotations: frozenset = frozenset(),
                       class_index: Optional[dict] = None) -> dict:
    """단일 endpoint XSS 판정 (5가지 유형 개별 판정 + xss_category)"""
    out = {
        "result":           "양호",
        "severity":         "N/A",
        "xss_type":         "None",
        "diagnosis_detail": "",
        "xss_category":     "",
        "controller_type_detected": "",
        "phase_details":    {},
        "evidence":         [],
        "needs_review":     False,
        "reflected_xss":    "해당없음",
        "view_xss":         "해당없음",
        "persistent_xss":   "해당없음",
        "redirect_xss":     "해당없음",
        "dom_xss":          "해당없음",
    }

    # ── Phase 1 ──────────────────────────────────────────────
    p1 = classify_controller(ctrl_content, handler_method, extra_rest_annotations)
    out["phase_details"]["phase1_controller"] = p1
    ct = p1["controller_type"]
    out["controller_type_detected"] = ct

    if ct == "REST_HTML_RISK":
        # Step 1: text/html 설정 확인 + Taint Flow 검증으로 FP 제거
        method_body_for_taint = extract_method_body(ctrl_content, handler_method) or ""
        taint = check_reflected_xss_taint(method_body_for_taint, ctrl_content)
        out["phase_details"]["reflected_taint"] = taint
        out["view_xss"] = "해당없음"

        if taint["taint_confirmed"]:
            # Taint 확정 → 실제위협
            out["reflected_xss"] = "취약"
            html_reason = (
                "REST 컨트롤러에서 명시적 text/html Content-Type 설정 감지 + "
                f"사용자 입력 파라미터 {taint['tainted_params']} 의 직접 문자열 연결(Taint 확정) — "
                "Reflected XSS 실제위협."
            )
            out.update({
                "result":           "취약",
                "severity":         "High",
                "xss_type":         "[실제위협] Reflected XSS (text/html + Taint 확정)",
                "diagnosis_detail": html_reason,
                "needs_review":     False,
            })
        elif taint["has_escape"]:
            # HTML 인코딩 함수 적용 확인 → 양호
            out["reflected_xss"] = "양호"
            out.update({
                "result":           "양호",
                "severity":         "N/A",
                "xss_type":         "",
                "diagnosis_detail": taint["reason"],
                "needs_review":     False,
            })
        else:
            # text/html 있으나 Taint 미확인 → 정보 (수동 확인 권장)
            out["reflected_xss"] = "정보"
            html_reason = (
                "REST 컨트롤러에서 text/html Content-Type 설정 확인. "
                f"{taint['reason']} — 수동 확인 권장."
            )
            out.update({
                "result":           "정보",
                "severity":         "Medium",
                "xss_type":         "[수동확인필요] Reflected XSS (text/html, Taint 미확정)",
                "diagnosis_detail": html_reason,
                "needs_review":     True,
            })

    elif ct == "REST_JSON":
        if p1["gson_unsafe"]:
            out["reflected_xss"] = "정보"
            out["view_xss"]      = "해당없음"
            out.update({
                "result":           "정보",
                "severity":         "Low",
                "xss_type":         "Reflected (Gson disableHtmlEscaping)",
                "diagnosis_detail": (
                    "GsonBuilder.disableHtmlEscaping() 사용 — JSON 응답에 HTML 문자가 "
                    "이스케이프 없이 포함됨. JSON 응답을 innerHTML로 렌더링하는 "
                    "클라이언트 코드가 있을 경우 XSS 취약."
                ),
                "needs_review": True,
            })
        else:
            out["reflected_xss"] = "양호"
            out["view_xss"]      = "해당없음"
            out.update({
                "result":           "양호",
                "xss_type":         "None",
                "diagnosis_detail": (
                    "@RestController / @ResponseBody — Content-Type: application/json 반환. "
                    "브라우저 HTML 해석 차단으로 Reflected XSS 양호."
                ),
            })

    elif ct == "HTML_VIEW":
        # ── Phase 2 ──────────────────────────────────────────
        method_body  = extract_method_body(ctrl_content, handler_method) or ""
        model_attrs  = _extract_model_attributes(method_body)
        view_name    = _extract_view_name(method_body) or ""
        view_file    = None
        p2: dict     = {"view_name": view_name, "view_file": None, "analysis": None}

        if view_name:
            view_file = _resolve_view_file(
                view_name, view_index, source_dir, view_prefix, view_suffix)

        if view_file and view_file.exists():
            p2["view_file"] = str(view_file)
            analysis = analyze_view_file(view_file, model_attrs)
            p2["analysis"] = analysis

            is_jsp   = analysis.get("view_type") == "JSP"
            vuln_lines = analysis.get("vulnerable_lines", [])

            # 취약 조건: 명시적 인코딩 없이 직접 출력
            is_vuln = (
                analysis.get("has_direct_el")
                or analysis.get("has_cout_unsafe")
                or analysis.get("has_utext")
                or analysis.get("has_scriptlet_out")
                or analysis.get("has_handlebars_unsafe")
            )
            # 안전 조건: 명시적 escaping 확인
            is_safe = (
                (is_jsp
                 and (analysis.get("has_escape_xml") or analysis.get("has_cout_safe"))
                 and not analysis.get("has_direct_el")
                 and not analysis.get("has_cout_unsafe"))
                or (not is_jsp
                    and analysis.get("has_text")
                    and not analysis.get("has_utext")
                    and not analysis.get("has_handlebars_unsafe"))
            )

            if is_vuln:
                if analysis.get("has_utext"):
                    vuln_desc = "Thymeleaf th:utext — HTML escape 없이 직접 렌더링"
                elif analysis.get("has_handlebars_unsafe"):
                    vuln_desc = "Handlebars {{{variable}}} — Triple-stache HTML escape 없음"
                elif analysis.get("has_cout_unsafe"):
                    vuln_desc = '<c:out escapeXml="false"> — escapeXml 비활성화'
                elif analysis.get("has_scriptlet_out"):
                    vuln_desc = "<%= request.getParameter() %> — 스크립틀릿 직접 출력"
                else:
                    vuln_desc = "${value} 직접 출력 — HTML escape 미처리"

                # 전역 필터 있어도 View 취약 패턴은 [실제위협]
                filter_ok = filter_status.get("filter_level") == "inbound"
                if filter_ok:
                    out["reflected_xss"] = "정보"
                    out["view_xss"]      = "정보"
                    out.update({
                        "result":   "정보",
                        "severity": "Low",
                        "xss_type": "View / Reflected (필터 완화)",
                        "diagnosis_detail": (
                            f"View XSS 패턴 감지({vuln_desc}) — "
                            f"전역 {filter_status['filter_type']} 입력 필터 적용 중이나 "
                            "필터 커버리지(multipart 등) 추가 검토 필요."
                        ),
                        "needs_review": True,
                        "evidence": [{"file": str(view_file),
                                      "vulnerable_lines": vuln_lines[:5]}],
                    })
                else:
                    # 전역 필터 없음 + View 직접 출력 → [실제위협] 취약
                    out["reflected_xss"] = "취약"
                    out["view_xss"]      = "취약"
                    out.update({
                        "result":   "취약",
                        "severity": "High",
                        "xss_type": "[실제위협] View / Reflected XSS",
                        "diagnosis_detail": (
                            f"{vuln_desc} — XSS 전역 필터 미적용. "
                            "사용자 입력이 View에 이스케이프 없이 출력됨."
                        ),
                        "needs_review": False,
                        "evidence": [{"file": str(view_file),
                                      "vulnerable_lines": vuln_lines[:5]}],
                    })
            elif is_safe:
                out["reflected_xss"] = "양호"
                out["view_xss"]      = "양호"
                out.update({
                    "result":   "양호",
                    "xss_type": "None",
                    "diagnosis_detail": (
                        f"View 출력 이스케이프 처리 확인 "
                        f"({'fn:escapeXml / <c:out>' if is_jsp else 'th:text'})."
                    ),
                })
            else:
                out["reflected_xss"] = "정보"
                out["view_xss"]      = "정보"
                out.update({
                    "result":       "정보",
                    "severity":     "Info",
                    "xss_type":     "View (인코딩 처리 불명확)",
                    "diagnosis_detail": (
                        f"View 파일({view_file.name}) 확인 — "
                        "출력 이스케이프 패턴 자동 판정 불가. 수동 검토 필요."
                    ),
                    "needs_review": True,
                })
        else:
            out["reflected_xss"] = "정보"
            out["view_xss"]      = "정보"
            out.update({
                "result":       "정보",
                "severity":     "Info",
                "xss_type":     "HTML_VIEW (View 파일 미탐지)",
                "diagnosis_detail": (
                    f"@Controller View 반환 패턴 확인 — "
                    f"View 파일 자동 탐지 실패 (view_name={view_name!r}). "
                    "JSP/Thymeleaf 출력 패턴 수동 확인 필요."
                ),
                "needs_review": True,
            })

        out["phase_details"]["phase2_view"] = p2

    else:
        # unknown controller type
        out["reflected_xss"] = "정보"
        out["view_xss"]      = "정보"
        out.update({
            "result":       "정보",
            "xss_type":     "unknown",
            "diagnosis_detail": "Controller 타입 판정 불가 — 수동 검토 필요.",
            "needs_review": True,
        })

    # ── Phase 3: 전역 필터 상태 기록 ─────────────────────────
    out["phase_details"]["phase3_filter"] = filter_status

    # ── Phase 4: Redirect 패턴 탐색 ──────────────────────────
    method_body = extract_method_body(ctrl_content, handler_method) or ""
    p4 = analyze_redirect_patterns(method_body)
    out["phase_details"]["phase4_redirect"] = p4

    if p4["has_redirect_risk"]:
        high_conf = any(f["confidence"] == "high" for f in p4["findings"])
        redirect_severity = "High" if high_conf else "Medium"
        redirect_verdict  = "취약" if high_conf else "정보"

        out["redirect_xss"] = redirect_verdict

        if _SEV_RANK.get(redirect_severity, 0) > _SEV_RANK.get(out["severity"], 0):
            prev_detail = out["diagnosis_detail"]
            out.update({
                "result":   redirect_verdict,
                "severity": redirect_severity,
                "xss_type": _append_xss_type(out["xss_type"], "[잠재적위협] Redirect XSS"),
                "diagnosis_detail": (
                    (prev_detail + " | " if prev_detail else "")
                    + "Open Redirect / Redirect XSS — "
                    "사용자 입력이 리다이렉트 대상으로 사용됨. "
                    "화이트리스트 검증 필요."
                ),
                "needs_review": not high_conf,
            })
        out["evidence"].append({
            "phase":    "redirect",
            "findings": p4["findings"][:3],
        })
    else:
        out["redirect_xss"] = "양호"

    # ── Phase 5: Persistent XSS Taint Tracking ───────────────
    p5 = check_persistent_xss(
        endpoint, sqli_result, filter_status,
        ctrl_content=ctrl_content,
        handler_method=handler_method,
        source_dir=source_dir,
        class_index=class_index,
    )
    out["phase_details"]["phase5_persistent"] = p5

    http_method = endpoint.get("method", "GET").upper()
    is_write    = http_method in ("POST", "PUT", "PATCH")

    if is_write:
        risk = p5.get("risk", "없음")
        if risk == "낮음":
            out["persistent_xss"] = "양호"
        elif risk == "취약":
            # Persistent XSS 위험 확정 — Worst-case 강제 승급
            out["persistent_xss"] = "취약"
            # taint 경로 자동 추적 성공 여부로 severity 차등화
            tr = p5.get("taint_result") or {}
            taint_chain = p5.get("call_chain", [])
            write_confirmed = (tr.get("taint_confirmed") is True) or bool(taint_chain)
            sev = "High" if write_confirmed else "Medium"
            if _VERDICT_RANK.get("취약", 0) >= _VERDICT_RANK.get(out["result"], 0):
                prev_detail = out["diagnosis_detail"]
                out.update({
                    "result":   "취약",
                    "severity": sev,
                    "xss_type": _append_xss_type(
                        out["xss_type"], "[잠재적위협] Persistent XSS (저장소 오염)"
                    ),
                    "diagnosis_detail": (
                        (prev_detail + " | " if prev_detail else "")
                        + p5["reason"]
                    ),
                    "needs_review": not write_confirmed,
                })
            out["evidence"].append({
                "phase":       "persistent",
                "taint_chain": taint_chain,
                "write_method": tr.get("write_method", ""),
            })
        elif risk == "잠재":
            # v2.2.0: "잠재"도 Fix 1/2/3 통과 후 잔여 → "취약" 승급 (방어적 처리)
            out["persistent_xss"] = "취약"
            if _VERDICT_RANK.get("취약", 0) >= _VERDICT_RANK.get(out["result"], 0):
                prev_detail = out["diagnosis_detail"]
                out.update({
                    "result":   "취약",
                    "severity": "Medium",
                    "xss_type": _append_xss_type(
                        out["xss_type"], "[잠재적위협] Persistent XSS (저장소 오염)"
                    ),
                    "diagnosis_detail": (
                        (prev_detail + " | " if prev_detail else "")
                        + p5.get("reason", "POST/PUT + 자유 텍스트 입력 + 전역 필터 없음")
                    ),
                    "needs_review": True,
                })
        elif risk == "lucy_bypass":
            out["persistent_xss"] = "정보"
            if out["result"] == "양호":
                out.update({
                    "result":           "정보",
                    "severity":         "Low",
                    "xss_type":         _append_xss_type(
                        out["xss_type"], "Lucy Multipart 우회 가능성"
                    ),
                    "diagnosis_detail": p5["reason"],
                    "needs_review":     True,
                })
        elif risk == "정보":
            # Step 3: 커스텀 필터 발견 → 정보 분류 (안전성 불명확)
            out["persistent_xss"] = "정보"
            if _VERDICT_RANK.get(out["result"], 0) < _VERDICT_RANK.get("정보", 0):
                prev_detail = out["diagnosis_detail"]
                out.update({
                    "result":   "정보",
                    "severity": "Medium",
                    "xss_type": _append_xss_type(
                        out["xss_type"],
                        "[정보] Persistent XSS (커스텀 XSS 필터 수동 점검 필요)"
                    ),
                    "diagnosis_detail": (
                        (prev_detail + " | " if prev_detail else "")
                        + p5.get("reason", "커스텀 XSS 필터 안전성 수동 점검 필요")
                    ),
                    "needs_review": True,
                })
        else:
            out["persistent_xss"] = "해당없음"
    else:
        out["persistent_xss"] = "해당없음"

    # ── xss_category 결정 ─────────────────────────────────────
    out["xss_category"] = _assign_xss_category(
        out["result"], out["xss_type"],
        p5.get("risk", "없음") if is_write else ""
    )

    return out


def _append_xss_type(current: str, new_type: str) -> str:
    """XSS 타입 문자열에 새 타입 추가 (중복 제거)"""
    if not current or current == "None":
        return new_type
    if new_type in current:
        return current
    return f"{current} / {new_type}"


# ============================================================
#  10. 전체 진단 실행
# ============================================================

def _load_api_inventory(path: Path, modules: list = None) -> list:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if "endpoints" in data:
        eps = data["endpoints"]
    elif "findings" in data:
        eps = data["findings"]
    else:
        print(f"Error: 지원하지 않는 인벤토리 형식: {path}")
        sys.exit(1)
    if modules:
        eps = [e for e in eps if e.get("module", "") in modules]
    return eps


def _format_params(params: list) -> str:
    if not params:
        return "N/A"
    parts = []
    for p in params:
        name  = p.get("name", "?")
        dtype = p.get("data_type", p.get("type", ""))
        parts.append(f"{name}: {dtype}" if dtype else name)
    return ", ".join(parts)


def _resolve_ctrl_file(endpoint: dict,
                       source_dir: Path,
                       class_index: dict) -> tuple:
    """API 인벤토리 endpoint에서 Controller 파일 탐색

    Returns: (ctrl_file: Optional[Path], handler_method: str)
    """
    handler = endpoint.get("handler", "")
    m = re.match(r'(\w+)\.(\w+)\s*\(', handler)
    if not m:
        return None, ""

    ctrl_class, handler_method = m.group(1), m.group(2)
    ctrl_file = None

    file_field = endpoint.get("file", "")
    if file_field:
        fp_str    = file_field.split(":")[0]
        candidate = source_dir / fp_str
        if not candidate.exists():
            candidate = source_dir.parent / fp_str
        if not candidate.exists():
            for p in source_dir.rglob(Path(fp_str).name):
                candidate = p
                break
        if candidate.exists():
            ctrl_file = candidate

    if not ctrl_file:
        ctrl_file = class_index.get(ctrl_class)

    return ctrl_file, handler_method


def run_xss_diagnosis(source_dir: Path,
                      inventory_path: Path,
                      modules: list = None,
                      sqli_result_path: Optional[Path] = None) -> dict:
    """XSS 전체 진단 실행 (Phase 1 ~ 6)"""

    endpoints = _load_api_inventory(inventory_path, modules)
    print(f"API 인벤토리 로드: {len(endpoints)}개 endpoint")

    # 클래스 인덱스 구축 (build_class_index는 (class_index, impl_index) 튜플 반환)
    print("클래스 인덱스 구축 중...")
    _ci_result = build_class_index(source_dir)
    if isinstance(_ci_result, tuple):
        class_index, impl_index = _ci_result
    else:
        class_index, impl_index = _ci_result, {}
    print(f"  → {len(class_index)}개 클래스 인덱싱 완료")

    # View 인덱스 구축
    print("View 파일 인덱스 구축 중...")
    view_index  = build_view_index(source_dir)
    view_prefix, view_suffix = _detect_view_prefix_suffix(source_dir)
    print(f"  → {len(view_index)}개 View 파일 인덱싱 완료 "
          f"(prefix={view_prefix!r}, suffix={view_suffix!r})")

    # Phase 3: 전역 XSS 필터 탐지 (1회)
    print("전역 XSS 필터 탐지 중...")
    filter_status = build_global_filter_status(source_dir)
    flt_label = (
        f"✓ {filter_status['filter_type']}"
        if filter_status["has_filter"] else "✗ 없음"
    )
    print(f"  → XSS 필터: {flt_label}")
    if filter_status.get("filter_level") in ("inbound_multipart_risk",):
        lm = filter_status.get("lucy_multipart") or {}
        print(f"  ⚠️  Lucy Multipart 우회 가능성: {lm.get('detail', '')}")
    if filter_status["filter_files"]:
        for ff in filter_status["filter_files"][:3]:
            print(f"     {ff}")

    # SQL Injection 결과 로드 (Phase 5용, optional)
    sqli_result = None
    if sqli_result_path and sqli_result_path.exists():
        with open(sqli_result_path, encoding="utf-8") as f:
            sqli_result = json.load(f)
        print(f"SQL Injection 결과 로드: {sqli_result_path.name} "
              f"({len(sqli_result.get('endpoint_diagnoses', []))}개 진단)")

    # 커스텀 @RestController 메타 어노테이션 탐지
    print("커스텀 @RestController 메타 어노테이션 탐지 중...")
    extra_rest_annotations = build_custom_rest_annotations(source_dir)
    if extra_rest_annotations:
        print(f"  → 커스텀 REST 어노테이션 탐지: {sorted(extra_rest_annotations)}")
    else:
        print("  → 커스텀 REST 어노테이션 없음")

    # Phase 6: DOM XSS 전역 스캔
    print("DOM XSS 전역 스캔 중 (JS/TS/Vue)...")
    dom_xss_scan = scan_dom_xss_global(source_dir)
    print(f"  → {dom_xss_scan['summary']}")

    # Endpoint별 진단
    print("Endpoint별 XSS 진단 수행 중...")
    diagnoses: list = []
    for idx, ep in enumerate(endpoints, 1):
        ctrl_file, handler_method = _resolve_ctrl_file(ep, source_dir, class_index)

        if ctrl_file:
            ctrl_content = read_file_safe(ctrl_file)
        else:
            ctrl_content = ""

        if ctrl_content and handler_method:
            judgment = judge_xss_endpoint(
                ep, ctrl_content, handler_method,
                view_index, view_prefix, view_suffix,
                filter_status, sqli_result, source_dir,
                extra_rest_annotations,
                class_index=class_index,
            )
        else:
            judgment = {
                "result":           "정보",
                "severity":         "Info",
                "xss_type":         "Controller 미탐지",
                "xss_category":     "수동확인필요",
                "diagnosis_detail": "Controller 파일 탐색 실패 — 수동 검토 필요.",
                "controller_type_detected": "unknown",
                "reflected_xss":    "정보",
                "view_xss":         "정보",
                "persistent_xss":   "정보",
                "redirect_xss":     "정보",
                "dom_xss":          "해당없음",
                "phase_details":    {},
                "evidence":         [],
                "needs_review":     True,
            }

        diag = XssEndpointResult(
            no              = f"XSS-{idx}",
            http_method     = ep.get("method", ""),
            request_mapping = ep.get("api", ""),
            process_file    = ep.get("file", ""),
            handler         = ep.get("handler", ""),
            parameters      = _format_params(ep.get("parameters", [])),
            controller_type = judgment.get("controller_type_detected", "unknown"),
            result          = judgment["result"],
            severity        = judgment.get("severity", "N/A"),
            xss_type        = judgment.get("xss_type", ""),
            diagnosis_detail= judgment.get("diagnosis_detail", ""),
            xss_category    = judgment.get("xss_category", ""),
            reflected_xss   = judgment.get("reflected_xss",   "해당없음"),
            view_xss        = judgment.get("view_xss",        "해당없음"),
            persistent_xss  = judgment.get("persistent_xss",  "해당없음"),
            redirect_xss    = judgment.get("redirect_xss",    "해당없음"),
            dom_xss         = judgment.get("dom_xss",         "해당없음"),
            phase_details   = judgment.get("phase_details", {}),
            evidence        = judgment.get("evidence", []),
            needs_review    = judgment.get("needs_review", False),
        )
        diagnoses.append(diag)

    # ── 통계 집계 ─────────────────────────────────────────────
    stats   = {"양호": 0, "취약": 0, "정보": 0}
    for d in diagnoses:
        stats[d.result] = stats.get(d.result, 0) + 1

    # per-type 통계
    _TYPE_FIELDS = ["reflected_xss", "view_xss", "persistent_xss", "redirect_xss"]
    _VERDICTS    = ["양호", "취약", "정보", "해당없음"]
    per_type: dict = {}
    for fld in _TYPE_FIELDS:
        cnt = {v: 0 for v in _VERDICTS}
        for d in diagnoses:
            v = getattr(d, fld, "해당없음")
            cnt[v] = cnt.get(v, 0) + 1
        per_type[fld] = cnt

    # xss_category 통계 (v2.0.0)
    _CATEGORIES = ["실제위협", "잠재적위협", "수동확인필요", "안전확인", "해당없음"]
    cat_stats: dict = {c: 0 for c in _CATEGORIES}
    for d in diagnoses:
        cat = d.xss_category or "해당없음"
        cat_stats[cat] = cat_stats.get(cat, 0) + 1

    total   = len(diagnoses)
    decided = stats["양호"] + stats["취약"]
    rate    = round(decided / total * 100, 1) if total else 0.0
    review  = sum(1 for d in diagnoses if d.needs_review)

    print(f"\nXSS 진단 완료: {total}개 endpoint  (판정률 {rate}%)")
    print(f"  🚨 취약: {stats['취약']}건  "
          f"(실제위협 {cat_stats['실제위협']} / 잠재적위협 {cat_stats['잠재적위협']})")
    print(f"  ⚠️  정보: {stats['정보']}건  (수동확인필요 {cat_stats['수동확인필요']})")
    print(f"  ✅ 양호: {stats['양호']}건")
    if review:
        print(f"  수동 검토 필요: {review}건")
    print(f"\n[유형별 판정]")
    for fld, cnt in per_type.items():
        label = fld.replace("_", " ").title()
        print(f"  {label}: 양호={cnt['양호']} / 취약={cnt['취약']} / 정보={cnt['정보']} / 해당없음={cnt['해당없음']}")
    print(f"\n[DOM XSS 전역 스캔] {dom_xss_scan['summary']}")

    return {
        "task_id": "2-3",
        "status":  "completed",
        "scan_metadata": {
            "source_dir":               str(source_dir),
            "api_inventory":            str(inventory_path),
            "sqli_result":              str(sqli_result_path) if sqli_result_path else None,
            "modules_filtered":         modules or [],
            "total_endpoints":          total,
            "total_classes_indexed":    len(class_index),
            "total_view_files_indexed": len(view_index),
            "global_xss_filter":        filter_status,
            "dom_xss_scan":             dom_xss_scan,
            "scanned_at":               datetime.now().isoformat(),
            "script_version":           _SCRIPT_VERSION,
        },
        "endpoint_diagnoses": [asdict(d) for d in diagnoses],
        "summary": {
            "total_endpoints": total,
            "xss":             stats,
            "xss_category":    cat_stats,
            "per_type": {
                **per_type,
                "dom_xss": (
                    f"전역 스캔 결과 참조 (scan_metadata.dom_xss_scan) — "
                    f"{dom_xss_scan['summary']}"
                ),
            },
            "판정률(%)":   rate,
            "수동검토":    review,
        },
    }


# ============================================================
#  11. main
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="XSS 취약점 자동 진단 스크립트 v" + _SCRIPT_VERSION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("source_dir",    type=Path, help="소스코드 루트 디렉터리")
    parser.add_argument("--api-inventory", required=True, type=Path,
                        dest="api_inventory", help="scan_api.py 출력 JSON")
    parser.add_argument("--sqli-result", type=Path, default=None,
                        dest="sqli_result",
                        help="scan_injection_enhanced.py 출력 JSON (Phase 5 Persistent XSS용)")
    parser.add_argument("--modules", nargs="*", default=None,
                        help="분석할 모듈명 필터 (복수 지정 가능)")
    parser.add_argument("-o", "--output", type=Path, default=None,
                        help="결과 출력 JSON 파일 경로")
    args = parser.parse_args()

    source_dir = args.source_dir.resolve()
    if not source_dir.exists():
        print(f"Error: 소스 디렉터리 미존재: {source_dir}")
        sys.exit(1)

    result = run_xss_diagnosis(
        source_dir       = source_dir,
        inventory_path   = args.api_inventory,
        modules          = args.modules,
        sqli_result_path = args.sqli_result,
    )

    out_path = args.output or (
        Path("state") / f"{source_dir.name}_xss_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2, default=str)

    print(f"\n결과 저장: {out_path}")


if __name__ == "__main__":
    main()
