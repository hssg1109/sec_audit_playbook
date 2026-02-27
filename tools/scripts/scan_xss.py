#!/usr/bin/env python3
"""
XSS 취약점 자동 진단 스크립트 v1.1.0

scan_api.py 결과를 기반으로 각 API endpoint에 대해
6가지 Phase로 XSS 취약 여부를 자동 판정합니다.

  Phase 1: Controller 분류 및 Content-Type 기반 방어 판정
            @RestController / @ResponseBody / ResponseEntity → JSON API (양호)
            @Controller + String/ModelAndView 반환 → HTML View (Phase 2 진입)
  Phase 2: View 렌더링 추적 (Outbound Escaping)
            JSP: ${value} vs <c:out> / fn:escapeXml()
            Thymeleaf: th:utext (취약) vs th:text (안전)
  Phase 3: 전역 XSS 필터 탐지 (Inbound Sanitizing)
            Lucy XSS Filter / AntiSamy / ESAPI
            Jackson ObjectMapper XSS Deserializer
  Phase 4: Redirect / Open Redirect 취약 패턴 탐색
            sendRedirect(userInput) / return "redirect:" + var
  Phase 5: Persistent XSS 위험 지표
            POST/PUT + DB write 경로 + 필터 미적용 → Info(잠재)
  Phase 6: DOM XSS 전역 스캔 (NEW v1.1.0)
            innerHTML= / document.write() / eval() / dangerouslySetInnerHTML
            insertAdjacentHTML() / jQuery .html() / Vue v-html

변경 이력:
  v1.0.0 - 초기 구현 (Phase 1~5)
  v1.1.0 - per-type 판정 필드 추가 (reflected_xss, view_xss, persistent_xss,
            redirect_xss, dom_xss), Phase 6 DOM XSS 전역 스캔 추가,
            summary per-type 통계 추가

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
)


# ============================================================
#  0. 상수 / 컴파일된 패턴
# ============================================================

_SCRIPT_VERSION = "1.1.1"

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

# @RequestParam / getParameter 근거 패턴 (Redirect confidence 향상용)
_P4_USER_PARAM_CTX = re.compile(
    r'@RequestParam|getParameter\s*\(|@PathVariable|HttpServletRequest',
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
]

# DOM XSS 안전 패턴 (DOMPurify 등 — 바로 뒤에 sanitize 적용 시 FP 감소)
_P6_DOM_SAFE_CTX = re.compile(
    r'DOMPurify\.sanitize|dompurify\.sanitize|sanitizeHtml|escapeHtml|innerText\s*=',
    re.IGNORECASE,
)

# JavaScript/TypeScript/Vue 파일 확장자 (DOM XSS 스캔 대상)
_JS_SCAN_EXTS = frozenset({".js", ".jsx", ".ts", ".tsx", ".vue"})

# 커스텀 @RestController 메타 어노테이션 탐지 패턴
# ex) @RestControllerWithStatusOk 가 @RestController 를 포함하는 경우 탐지
_P1_META_REST = re.compile(r'@RestController\b')  # 어노테이션 정의 파일 내에서 메타 어노테이션 확인
_P1_ANN_DECL  = re.compile(r'@interface\s+(\w+)')  # 어노테이션 이름 추출


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
    # 확장자 제거
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
    """메서드 선언 전 어노테이션 포함 영역 추출 (접근제한자 + 반환타입 + 메서드명)"""
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
    # 제네릭 제거: ResponseEntity<Foo> → ResponseEntity
    return raw.split("<")[0].strip()


def build_custom_rest_annotations(source_dir: Path) -> frozenset:
    """소스코드 전역에서 @RestController를 메타 어노테이션으로 포함하는
    커스텀 어노테이션 이름 집합을 반환합니다.

    예: @RestControllerWithStatusOk { @RestController ... } → {"RestControllerWithStatusOk"}
    """
    custom: set = set()
    for fp in source_dir.rglob("*.java"):
        if any(ex in fp.parts for ex in _EXCLUDE_DIRS):
            continue
        content = read_file_safe(fp)
        if not content:
            continue
        # 파일 내에 @interface 선언과 @RestController 메타 어노테이션이 동시에 있는 경우
        if _P1_ANN_DECL.search(content) and _P1_META_REST.search(content):
            m = _P1_ANN_DECL.search(content)
            if m:
                custom.add(m.group(1))
    return frozenset(custom)


def classify_controller(ctrl_content: str, handler_method: str,
                        extra_rest_annotations: frozenset = frozenset()) -> dict:
    """Phase 1: Controller/메서드 분류 및 Content-Type 기반 방어 판정

    controller_type:
      REST_JSON  — JSON 응답, 브라우저 HTML 해석 불가 → Reflected XSS 기본 양호
      HTML_VIEW  — @Controller + View name 반환 → Phase 2 (View 분석) 필요
      unknown    — 판정 불가

    extra_rest_annotations: 프로젝트 고유 커스텀 @RestController 메타 어노테이션 이름 집합
    """
    is_rest_class   = bool(_P1_REST_CLASS.search(ctrl_content))
    # 커스텀 @RestController 메타 어노테이션 탐지 (예: @RestControllerWithStatusOk)
    if not is_rest_class and extra_rest_annotations:
        for ann in extra_rest_annotations:
            if re.search(rf'@{re.escape(ann)}\b', ctrl_content):
                is_rest_class = True
                break
    method_region   = _extract_method_region(ctrl_content, handler_method)
    return_type     = _extract_return_type(ctrl_content, handler_method)

    has_response_body = bool(_P1_RESPONSE_BODY.search(method_region))
    produces_json     = bool(_P1_PRODUCES_JSON.search(method_region))
    produces_html     = bool(_P1_PRODUCES_HTML.search(method_region))
    gson_unsafe       = bool(_P1_GSON_UNSAFE.search(ctrl_content))

    returns_re    = return_type.startswith("ResponseEntity")
    base_rt       = return_type  # ResponseEntity, String, ModelAndView, ...

    # ---- 분류 결정 ----
    if is_rest_class:
        ct = "REST_JSON"
    elif has_response_body or produces_json:
        ct = "REST_JSON"
    elif returns_re:
        # ResponseEntity는 기본 JSON 직렬화
        ct = "HTML_VIEW" if produces_html else "REST_JSON"
    elif base_rt in ("String", "ModelAndView", "View") or produces_html:
        ct = "HTML_VIEW"
    elif base_rt == "void":
        # void + @Controller → View 렌더링 가능성 (보수적)
        ct = "HTML_VIEW" if not is_rest_class else "REST_JSON"
    elif not base_rt:
        ct = "unknown"
    else:
        # 기타 반환 타입(@Controller 클래스): 보수적으로 HTML_VIEW
        ct = "HTML_VIEW"

    return {
        "is_rest_class":     is_rest_class,
        "has_response_body": has_response_body,
        "produces_json":     produces_json,
        "produces_html":     produces_html,
        "return_type":       base_rt or "unknown",
        "gson_unsafe":       gson_unsafe,
        "controller_type":   ct,
    }


# ============================================================
#  4. Phase 2: View 파일 분석 (Outbound Escaping)
# ============================================================

def _extract_view_name(method_body: str) -> Optional[str]:
    """Controller 메서드 본문에서 반환 View 이름 추출"""
    # return "viewName";
    m = re.search(r'return\s+"([^"]+)"', method_body)
    if m:
        name = m.group(1)
        if name.startswith(("redirect:", "forward:")):
            return None
        return name
    # return new ModelAndView("viewName")
    m = re.search(r'new\s+ModelAndView\s*\(\s*"([^"]+)"', method_body)
    if m:
        return m.group(1)
    # setViewName("viewName")
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

    # <c:out escapeXml="false"> 위치 수집
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if _P2_JSP_COUT_UNSAFE.search(stripped):
            vulnerable_lines.append((i, stripped[:120]))

    # ${value} 직접 출력 탐지 (line별)
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        el_hits = re.findall(r'\$\{([^}]+)\}', stripped)
        if not el_hits:
            continue
        # <c:out value="${...}"> 컨텍스트면 안전 → 건너뜀
        if re.search(r'<c:out\b[^>]*value\s*=\s*"[^"]*\$\{', stripped, re.IGNORECASE):
            continue
        # fn:escapeXml(${...}) 컨텍스트면 안전 → 건너뜀
        if re.search(r'fn:escapeXml\s*\(\s*\$\{', stripped):
            continue
        # JSTL 조건/반복 태그 속성 컨텍스트 (비출력)
        if re.search(r'<c:(?:if|when|forEach|choose)\b[^>]*\$\{', stripped, re.IGNORECASE):
            continue
        # th:text, th:value 등 Thymeleaf safe attributes
        if re.search(r'\bth:(?:text|value|href|src|action)\s*=\s*["\'][^"\']*\$\{', stripped):
            continue
        has_direct_el = True
        vulnerable_lines.append((i, stripped[:120]))

    # 스크립틀릿 직접 출력 위치 수집
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

    return {
        "view_type":       "Thymeleaf",
        "has_utext":       has_utext,
        "has_text":        has_text,
        "vulnerable_lines": vulnerable_lines[:10],
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

def build_global_filter_status(source_dir: Path) -> dict:
    """Phase 3: web.xml / *Config.java / *Filter.java / *XSS*.java 에서
    전역 XSS 필터 탐지 후 종합 판정

    filter_level:
      none        — XSS 필터 미발견
      header_only — X-XSS-Protection 헤더만 (불충분)
      inbound     — Lucy/AntiSamy/ESAPI/Jackson 입력 새니타이징
    """
    found_lucy    = False
    found_antisamy = False
    found_esapi   = False
    found_ss_xss  = False
    found_jack    = False
    filter_files: list = []

    # 탐색 대상 패턴 목록
    glob_patterns = [
        "web.xml", "*Config*.java", "*Filter*.java",
        "*XSS*.java", "*Xss*.java", "*xss*.java",
        "*Security*.java", "*WebMvc*.java",
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

            hit = False
            if _P3_LUCY.search(content):
                found_lucy = True;    hit = True
            if _P3_ANTISAMY.search(content):
                found_antisamy = True; hit = True
            if _P3_ESAPI.search(content):
                found_esapi = True;   hit = True
            if _P3_SS_XSS.search(content):
                found_ss_xss = True;  hit = True
            if _P3_JACK_DESER.search(content) or _P3_JACK_MOD.search(content):
                found_jack = True;    hit = True

            if hit:
                try:
                    filter_files.append(str(fp.relative_to(source_dir)))
                except ValueError:
                    filter_files.append(str(fp))

    # 종합 판정
    if found_lucy:
        filter_type  = "Lucy XSS Filter"
        filter_detail = (
            "Lucy XSS Servlet Filter 적용 중. "
            "multipart/form-data 요청에 대한 MultipartFilter 체인 포함 여부 추가 확인 필요."
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

    return {
        "has_filter":    filter_level != "none",
        "filter_type":   filter_type,
        "filter_detail": filter_detail,
        "filter_level":  filter_level,   # none / header_only / inbound
        "has_lucy":      found_lucy,
        "has_antisamy":  found_antisamy,
        "has_esapi":     found_esapi,
        "has_ss_xss":    found_ss_xss,
        "has_jackson_xss": found_jack,
        "filter_files":  filter_files,
    }


# ============================================================
#  6. Phase 4: Redirect / Open Redirect 패턴 탐색
# ============================================================

def analyze_redirect_patterns(method_body: str) -> dict:
    """Phase 4: 메서드 본문에서 서버사이드 Redirect 취약 패턴 탐색

    confidence:
      high   — @RequestParam / getParameter 등 사용자 입력 컨텍스트 확인
      medium — redirect 패턴 발견되나 입력 출처 불분명
    """
    findings: list = []
    lines = method_body.splitlines()

    # 사용자 입력 컨텍스트 (전체 메서드 본문 기준)
    has_user_ctx = bool(_P4_USER_PARAM_CTX.search(method_body))

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        for pattern, desc in _P4_REDIRECT_PATTERNS:
            if pattern.search(stripped):
                # 화이트리스트 고정 URL 패턴 (리터럴 문자열로만 구성) → 제외
                if re.search(r'sendRedirect\s*\(\s*"[^"]*"\s*\)', stripped):
                    continue
                findings.append({
                    "type":       desc,
                    "line":       i,
                    "snippet":    stripped[:120],
                    "confidence": "high" if has_user_ctx else "medium",
                })
                break  # 한 줄에서 첫 번째 패턴만

    return {
        "has_redirect_risk": bool(findings),
        "findings":          findings[:10],
    }


# ============================================================
#  7. Phase 5: Persistent XSS 위험 지표
# ============================================================

def check_persistent_xss(endpoint: dict,
                          sqli_result: Optional[dict],
                          filter_status: dict) -> dict:
    """Phase 5: POST/PUT + DB write 경로 + XSS 필터 미적용 조합 판정

    risk level:
      없음    — GET endpoint 또는 DB write 경로 미확인
      낮음    — Inbound XSS 필터 적용 중 (입력 새니타이징)
      잠재    — POST/PUT + DB write + 필터 없음 → Info 레벨 플래그
    """
    http_method = endpoint.get("method", "GET").upper()
    is_write    = http_method in ("POST", "PUT", "PATCH")

    if not is_write:
        return {"risk": "없음", "reason": "GET 전용 endpoint — Persistent XSS 경로 없음"}

    # DB write 경로 확인 (sqli_result 제공 시)
    has_db_write    = False
    db_write_detail = ""

    if sqli_result:
        ep_api = endpoint.get("api", "")
        for diag in sqli_result.get("endpoint_diagnoses", []):
            if diag.get("request_mapping", "") == ep_api:
                for op in diag.get("db_operations", []):
                    if op.get("access_type", "") not in ("none", "unknown"):
                        has_db_write    = True
                        db_write_detail = op.get("detail", "")[:80]
                        break
                break
        if not has_db_write:
            return {"risk": "없음", "reason": "SQL Injection 결과 내 DB write 경로 미확인"}
    else:
        # sqli_result 없음 → HTTP write method 자체를 잠재 위험으로 간주
        has_db_write    = True
        db_write_detail = "SQL Injection 결과 없음 — DB 저장 경로 자동 추정"

    # 전역 Inbound 필터 적용 중이면 위험도 낮춤
    if filter_status.get("filter_level") == "inbound":
        return {
            "risk":   "낮음",
            "reason": (
                f"전역 {filter_status['filter_type']} 입력 새니타이징 적용 중. "
                "필터 커버리지(multipart 요청 등) 추가 검토 권장."
            ),
        }

    return {
        "risk":            "잠재",
        "reason":          (
            f"POST/PUT endpoint + DB 저장 경로({db_write_detail}) + "
            "XSS 전역 필터 미적용 — 저장된 스크립트가 View에서 렌더링될 경우 취약."
        ),
        "db_write_detail": db_write_detail,
    }


# ============================================================
#  8. Phase 6: DOM XSS 전역 스캔 (NEW v1.1.0)
# ============================================================

def scan_dom_xss_global(source_dir: Path) -> dict:
    """Phase 6: JS/TS/Vue 파일에서 DOM XSS 취약 패턴 전역 스캔

    endpoint별 분석이 아닌 프로젝트 전체 JS 파일 스캔.
    결과는 scan_metadata.dom_xss_scan에 저장됨.

    risk:
      없음    — DOM XSS 패턴 미발견
      잠재    — DOM XSS 취약 패턴 발견 (DOMPurify 등 sanitize 적용 여부 수동 확인 필요)
    """
    findings: list = []
    files_scanned: int = 0
    safe_ctx_files: list = []

    for ext in _JS_SCAN_EXTS:
        for fp in source_dir.rglob(f"*{ext}"):
            if any(ex in fp.parts for ex in _EXCLUDE_DIRS):
                continue

            content = read_file_safe(fp)
            if not content:
                continue
            files_scanned += 1

            # DOMPurify 등 sanitize 적용 파일 → 별도 추적 (FP 감소)
            has_safe_ctx = bool(_P6_DOM_SAFE_CTX.search(content))
            if has_safe_ctx:
                try:
                    safe_ctx_files.append(str(fp.relative_to(source_dir)))
                except ValueError:
                    safe_ctx_files.append(str(fp))

            lines = content.splitlines()
            for i, line in enumerate(lines, 1):
                stripped = line.strip()
                if not stripped or stripped.startswith("//"):
                    continue

                for pattern, desc in _P6_DOM_VULN_PATTERNS:
                    if pattern.search(stripped):
                        try:
                            rel_path = str(fp.relative_to(source_dir))
                        except ValueError:
                            rel_path = str(fp)
                        findings.append({
                            "file":    rel_path,
                            "line":    i,
                            "snippet": stripped[:120],
                            "type":    desc,
                            "has_safe_ctx": has_safe_ctx,
                        })
                        break  # 한 줄에서 첫 번째 패턴만

    # findings 최대 30건 (파일당 중복 제거)
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
        "findings_count":    len(deduped),
        "safe_ctx_files":    safe_ctx_files[:5],
        "vuln_files":        vuln_files[:10],
        "findings":          deduped[:30],
        "risk":              risk,
        "summary":           (
            f"JS/TS/Vue {files_scanned}개 파일 스캔 — "
            f"DOM XSS 잠재 패턴 {len(deduped)}건 발견 "
            f"(sanitize 컨텍스트 파일 {len(safe_ctx_files)}개 포함)"
            if deduped else
            f"JS/TS/Vue {files_scanned}개 파일 스캔 — DOM XSS 패턴 미발견"
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


def judge_xss_endpoint(endpoint: dict,
                       ctrl_content: str,
                       handler_method: str,
                       view_index: dict,
                       view_prefix: str,
                       view_suffix: str,
                       filter_status: dict,
                       sqli_result: Optional[dict],
                       source_dir: Path,
                       extra_rest_annotations: frozenset = frozenset()) -> dict:
    """단일 endpoint XSS 판정 (5가지 유형 개별 판정 포함)

    반환:
      result           — 종합 worst-case 판정 (양호/취약/정보)
      severity         — 종합 worst-case 심각도
      xss_type         — 취약/정보 유형 요약 문자열
      reflected_xss    — 유형별 개별 판정
      view_xss         — 유형별 개별 판정
      persistent_xss   — 유형별 개별 판정
      redirect_xss     — 유형별 개별 판정
      dom_xss          — 전역 스캔 참조 (endpoint별 해당없음)
    """
    out = {
        "result":           "양호",
        "severity":         "N/A",
        "xss_type":         "None",
        "diagnosis_detail": "",
        "controller_type_detected": "",
        "phase_details":    {},
        "evidence":         [],
        "needs_review":     False,
        # ── per-type 판정 (v1.1.0 NEW) ──────────────────────
        "reflected_xss":    "해당없음",
        "view_xss":         "해당없음",
        "persistent_xss":   "해당없음",
        "redirect_xss":     "해당없음",
        "dom_xss":          "해당없음",  # 전역 스캔 결과는 scan_metadata에
    }

    # ── Phase 1 ──────────────────────────────────────────────
    p1 = classify_controller(ctrl_content, handler_method, extra_rest_annotations)
    out["phase_details"]["phase1_controller"] = p1
    ct = p1["controller_type"]
    out["controller_type_detected"] = ct

    if ct == "REST_JSON":
        if p1["gson_unsafe"]:
            out["reflected_xss"] = "정보"
            out["view_xss"]      = "해당없음"
            out.update({
                "result":           "정보",
                "severity":         "Low",
                "xss_type":         "Reflected (Gson)",
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

            # 취약 조건
            is_vuln = (
                analysis.get("has_direct_el")
                or analysis.get("has_cout_unsafe")
                or analysis.get("has_utext")
                or analysis.get("has_scriptlet_out")
            )
            # 안전 조건
            is_safe = (
                (is_jsp
                 and (analysis.get("has_escape_xml") or analysis.get("has_cout_safe"))
                 and not analysis.get("has_direct_el")
                 and not analysis.get("has_cout_unsafe"))
                or (not is_jsp
                    and analysis.get("has_text")
                    and not analysis.get("has_utext"))
            )

            if is_vuln:
                # 취약 상세
                if analysis.get("has_utext"):
                    vuln_desc = "Thymeleaf th:utext — HTML escape 없이 직접 렌더링"
                elif analysis.get("has_cout_unsafe"):
                    vuln_desc = '<c:out escapeXml="false"> — escapeXml 비활성화'
                elif analysis.get("has_scriptlet_out"):
                    vuln_desc = "<%= request.getParameter() %> — 스크립틀릿 직접 출력"
                else:
                    vuln_desc = "${value} 직접 출력 — HTML escape 미처리"

                filter_ok = (
                    filter_status.get("has_filter")
                    and filter_status.get("filter_level") == "inbound"
                )
                if filter_ok:
                    out["reflected_xss"] = "정보"
                    out["view_xss"]      = "정보"
                    out.update({
                        "result":   "정보",
                        "severity": "Low",
                        "xss_type": "View / Reflected",
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
                    out["reflected_xss"] = "취약"
                    out["view_xss"]      = "취약"
                    out.update({
                        "result":   "취약",
                        "severity": "High",
                        "xss_type": "View / Reflected XSS",
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
                    "xss_type":     "View (판정 불가)",
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

        # 종합 판정 업그레이드 (기존보다 더 나쁘면)
        if _SEV_RANK.get(redirect_severity, 0) > _SEV_RANK.get(out["severity"], 0):
            prev_detail = out["diagnosis_detail"]
            out.update({
                "result":   redirect_verdict,
                "severity": redirect_severity,
                "xss_type": _append_xss_type(out["xss_type"], "Redirect"),
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

    # ── Phase 5: Persistent XSS 지표 ─────────────────────────
    p5 = check_persistent_xss(endpoint, sqli_result, filter_status)
    out["phase_details"]["phase5_persistent"] = p5

    http_method = endpoint.get("method", "GET").upper()
    is_write    = http_method in ("POST", "PUT", "PATCH")

    if is_write:
        risk = p5.get("risk", "없음")
        if risk == "낮음":
            out["persistent_xss"] = "양호"
        elif risk == "잠재":
            out["persistent_xss"] = "정보"
            # 종합 판정: 기존이 양호인 경우에만 정보로 올림
            if out["result"] == "양호":
                out.update({
                    "result":           "정보",
                    "severity":         "Info",
                    "xss_type":         _append_xss_type(out["xss_type"], "Persistent (잠재)"),
                    "diagnosis_detail": p5["reason"],
                    "needs_review":     True,
                })
        else:
            # risk == "없음" (DB write 경로 미확인)
            out["persistent_xss"] = "해당없음"
    else:
        out["persistent_xss"] = "해당없음"

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

    # 인벤토리 로드
    endpoints = _load_api_inventory(inventory_path, modules)
    print(f"API 인벤토리 로드: {len(endpoints)}개 endpoint")

    # 클래스 인덱스 구축
    print("클래스 인덱스 구축 중...")
    class_index = build_class_index(source_dir)
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

    # 커스텀 @RestController 메타 어노테이션 탐지 (프로젝트 고유 어노테이션)
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
            )
        else:
            judgment = {
                "result":           "정보",
                "severity":         "Info",
                "xss_type":         "Controller 미탐지",
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

    total   = len(diagnoses)
    decided = stats["양호"] + stats["취약"]
    rate    = round(decided / total * 100, 1) if total else 0.0
    review  = sum(1 for d in diagnoses if d.needs_review)

    print(f"\nXSS 진단 완료: {total}개 endpoint  (판정률 {rate}%)")
    print(f"  양호: {stats['양호']}건")
    print(f"  취약: {stats['취약']}건")
    print(f"  정보: {stats['정보']}건")
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
            "per_type": {
                **per_type,
                "dom_xss": f"전역 스캔 결과 참조 (scan_metadata.dom_xss_scan) — {dom_xss_scan['summary']}",
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
