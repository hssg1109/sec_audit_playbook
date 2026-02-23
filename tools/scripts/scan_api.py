#!/usr/bin/env python3
"""
API 엔드포인트 인벤토리 자동 추출 스크립트

소스코드에서 Spring MVC/WebFlux 컨트롤러를 파싱하여
모든 API 엔드포인트, HTTP 메서드, 파라미터, 인증 여부 등을 추출합니다.

사용법:
    python scan_api.py <source_dir> [--output <file>]
    python scan_api.py testbed/3-pcona/pcona-env-dev@afd19907e2c/
    python scan_api.py testbed/3-pcona/pcona-env-dev@afd19907e2c/ --output state/pcona_api_inventory.json

출력 필드:
    - method: HTTP 메서드 (GET, POST, PUT, DELETE, PATCH)
    - api: 엔드포인트 경로
    - auth_required: 인증 필요 여부
    - handler: 핸들러 (클래스.메서드())
    - file: 소스 파일 경로:라인
    - description: 설명
    - parameters: 전체 파라미터 목록
"""

import json
import re
import sys
import argparse
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional


# ============================================================
#  어노테이션 파싱 유틸리티
# ============================================================

def extract_annotation_value(text: str, anno_name: str) -> Optional[str]:
    """어노테이션의 전체 내용을 추출 (괄호 매칭)
    예: @GetMapping("/api/test") -> "/api/test"
    예: @PreAuthorize("hasAnyAuthority('ADMIN')") -> "hasAnyAuthority('ADMIN')"
    """
    pattern = rf'@{anno_name}\s*\('
    match = re.search(pattern, text)
    if not match:
        return None

    start = match.end()
    depth = 1
    i = start
    while i < len(text) and depth > 0:
        if text[i] == '(':
            depth += 1
        elif text[i] == ')':
            depth -= 1
        i += 1

    if depth == 0:
        return text[start:i - 1].strip()
    return None


def extract_paths_from_annotation(anno_content: str) -> list[str]:
    """어노테이션 내용에서 경로 목록을 추출
    예: '"/api"' -> ["/api"]
    예: 'path = ["/req", "/ads"]' -> ["/req", "/ads"]
    예: 'value = ["/req"]' -> ["/req"]
    예: '' -> [""]
    """
    if not anno_content:
        return [""]

    # path = [...] 또는 value = [...] 형태
    list_match = re.search(r'(?:path|value)\s*=\s*\[([^\]]*)\]', anno_content)
    if list_match:
        items = re.findall(r'"([^"]*)"', list_match.group(1))
        return items if items else [""]

    # 단순 문자열 형태: "/path" 또는 value="/path"
    str_match = re.search(r'(?:value\s*=\s*)?["\']([^"\']*)["\']', anno_content)
    if str_match:
        return [str_match.group(1)]

    return [""]


def extract_method_from_request_mapping(anno_content: str) -> list[str]:
    """@RequestMapping의 method 속성에서 HTTP 메서드 추출
    예: 'method = [RequestMethod.GET]' -> ['GET']
    예: 'method = RequestMethod.POST' -> ['POST']
    """
    method_match = re.search(r'method\s*=\s*\[?([^\])\n]*)\]?', anno_content)
    if method_match:
        methods = re.findall(r'RequestMethod\.(\w+)', method_match.group(1))
        return [m.upper() for m in methods] if methods else ["GET"]
    return ["GET"]  # 기본값


def extract_preauthorize(text: str) -> Optional[str]:
    """@PreAuthorize 어노테이션에서 권한 표현식 추출"""
    content = extract_annotation_value(text, 'PreAuthorize')
    if content:
        # 따옴표 제거
        return content.strip('"\'')
    return None


def extract_audit_action(text: str) -> Optional[str]:
    """@PconaAudit(action="...") 에서 action 값 추출"""
    content = extract_annotation_value(text, 'PconaAudit')
    if content:
        action_match = re.search(r'action\s*=\s*["\']([^"\']*)["\']', content)
        if action_match:
            return action_match.group(1)
    return None


# ============================================================
#  인증 어노테이션 파싱
# ============================================================

# 커스텀 인증 어노테이션 레지스트리 (프로젝트별 확장 가능)
AUTH_ANNOTATIONS: set[str] = {
    'PconaSession',   # Pcona 프로젝트 세션
    'Session',        # OCB 등 커스텀 세션
    'LoginUser',      # 로그인 사용자 주입
    'AuthUser',       # 인증 사용자 주입
    'CurrentUser',    # 현재 사용자 주입
}


@dataclass
class AuthAnnotation:
    """커스텀 인증 어노테이션 파싱 결과"""
    name: str                               # "Session", "PconaSession"
    required: bool = True                   # 인증 필수 여부
    permitted: bool = False                 # 게스트 허용 여부
    attributes: dict = field(default_factory=dict)  # 원본 속성


def parse_auth_annotation(param_text: str, anno_name: str) -> AuthAnnotation:
    """커스텀 인증 어노테이션의 속성을 파싱하여 AuthAnnotation 반환

    @Session                           -> required=True, permitted=False
    @Session(required = true)          -> required=True
    @Session(required = false)         -> required=False
    @Session(permitted = true)         -> permitted=True
    @Session(permitted = true, required = true) -> required=True, permitted=True
    @Session(disallowOgeulUserCheck = true)     -> required=True (default)
    """
    attrs: dict = {}
    content = extract_annotation_value(param_text, anno_name)

    if content:
        # required = true/false
        req_m = re.search(r'required\s*=\s*(true|false)', content, re.IGNORECASE)
        if req_m:
            attrs['required'] = req_m.group(1).lower() == 'true'

        # permitted = true/false
        perm_m = re.search(r'permitted\s*=\s*(true|false)', content, re.IGNORECASE)
        if perm_m:
            attrs['permitted'] = perm_m.group(1).lower() == 'true'

        # field = true/false
        field_m = re.search(r'field\s*=\s*(true|false)', content, re.IGNORECASE)
        if field_m:
            attrs['field'] = field_m.group(1).lower() == 'true'

        # disallowOgeulUserCheck 등 기타 속성
        for extra_m in re.finditer(r'(\w+)\s*=\s*(true|false|"[^"]*"|\d+)', content):
            key = extra_m.group(1)
            if key not in attrs:
                val = extra_m.group(2).strip('"')
                if val == 'true':
                    attrs[key] = True
                elif val == 'false':
                    attrs[key] = False
                else:
                    attrs[key] = val

    required = attrs.get('required', True)   # default: true
    permitted = attrs.get('permitted', False)  # default: false

    return AuthAnnotation(
        name=anno_name,
        required=required,
        permitted=permitted,
        attributes=attrs,
    )


# ============================================================
#  파라미터 파싱
# ============================================================

@dataclass
class Parameter:
    name: str
    type: str  # query, path, body, header, pageable, session, request, response
    data_type: str = ""
    required: bool = True
    default_value: Optional[str] = None


def parse_parameter(param_text: str) -> Optional[Parameter]:
    """함수 파라미터 하나를 파싱
    예: '@RequestParam(value = "search") search: String?'
    예: '@PathVariable(value = "id") id: Long'
    예: '@RequestBody advertiser: Advertiser'
    예: '@PageableDefault(size=10, page=0) page: Pageable'
    예: '@PconaSession user: User'
    예: 'req: ServerHttpRequest'
    """
    param_text = param_text.strip()
    if not param_text:
        return None

    # @RequestParam
    rp_match = re.search(r'@RequestParam\s*(?:\(([^)]*)\))?\s*(\w+)\s*:\s*(\S+)', param_text)
    if rp_match:
        anno_args = rp_match.group(1) or ""
        param_name = rp_match.group(2)
        data_type = rp_match.group(3).rstrip(',')

        # value/name 속성에서 실제 파라미터명 추출
        value_match = re.search(r'(?:value|name)\s*=\s*["\']([^"\']*)["\']', anno_args)
        if value_match:
            param_name = value_match.group(1)

        required = True
        req_match = re.search(r'required\s*=\s*(true|false)', anno_args, re.IGNORECASE)
        if req_match:
            required = req_match.group(1).lower() == 'true'
        elif data_type.endswith('?'):
            required = False

        default = None
        def_match = re.search(r'defaultValue\s*=\s*["\']([^"\']*)["\']', anno_args)
        if def_match:
            default = def_match.group(1)
            required = False

        return Parameter(
            name=param_name, type="query", data_type=data_type,
            required=required, default_value=default
        )

    # @PathVariable
    pv_match = re.search(r'@PathVariable\s*(?:\(([^)]*)\))?\s*(\w+)\s*:\s*(\S+)', param_text)
    if pv_match:
        anno_args = pv_match.group(1) or ""
        param_name = pv_match.group(2)
        data_type = pv_match.group(3).rstrip(',')

        value_match = re.search(r'(?:value|name)\s*=\s*["\']([^"\']*)["\']', anno_args)
        if value_match:
            param_name = value_match.group(1)

        return Parameter(
            name=param_name, type="path", data_type=data_type, required=True
        )

    # @RequestBody
    rb_match = re.search(r'@RequestBody\s*(\w+)\s*:\s*(\S+)', param_text)
    if rb_match:
        return Parameter(
            name=rb_match.group(1), type="body",
            data_type=rb_match.group(2).rstrip(','), required=True
        )

    # @RequestHeader
    rh_match = re.search(r'@RequestHeader\s*(?:\(([^)]*)\))?\s*(\w+)\s*:\s*(\S+)', param_text)
    if rh_match:
        anno_args = rh_match.group(1) or ""
        param_name = rh_match.group(2)
        data_type = rh_match.group(3).rstrip(',')

        value_match = re.search(r'["\']([^"\']*)["\']', anno_args)
        if value_match:
            param_name = value_match.group(1)

        required = not data_type.endswith('?')
        req_match = re.search(r'required\s*=\s*(true|false)', anno_args, re.IGNORECASE)
        if req_match:
            required = req_match.group(1).lower() == 'true'

        return Parameter(
            name=param_name, type="header", data_type=data_type, required=required
        )

    # @PageableDefault (중첩 괄호 지원 - arrayOf() 등)
    if '@PageableDefault' in param_text:
        anno_content = extract_annotation_value(param_text, 'PageableDefault')
        # 어노테이션 끝 이후 변수명:타입 추출
        # @PageableDefault(...) varName: Type 형태
        anno_end = param_text.find('@PageableDefault')
        # 괄호 매칭으로 어노테이션 끝 찾기
        paren_start = param_text.find('(', anno_end)
        if paren_start >= 0:
            depth = 1
            idx = paren_start + 1
            while idx < len(param_text) and depth > 0:
                if param_text[idx] == '(':
                    depth += 1
                elif param_text[idx] == ')':
                    depth -= 1
                idx += 1
            after_anno = param_text[idx:].strip()
        else:
            after_anno = param_text[anno_end + len('@PageableDefault'):].strip()
        var_match = re.search(r'(\w+)\s*:\s*(\S+)', after_anno)
        if var_match:
            return Parameter(
                name=var_match.group(1), type="pageable",
                data_type="Pageable",
                required=False,
                default_value=anno_content.strip() if anno_content else None
            )

    # 커스텀 인증 어노테이션 (범용: @Session, @PconaSession, @LoginUser 등)
    for auth_anno in AUTH_ANNOTATIONS:
        # Kotlin: @Session varName: Type  또는  @Session(required = true) varName: Type
        ps_match = re.search(
            rf'@{auth_anno}\s*(?:\([^)]*\))?\s*(\w+)\s*:\s*(\S+)', param_text
        )
        if ps_match:
            auth_info = parse_auth_annotation(param_text, auth_anno)
            return Parameter(
                name=ps_match.group(1), type="session",
                data_type=ps_match.group(2).rstrip(','), required=True,
                default_value=json.dumps(asdict(auth_info)),
            )

    # @RequestPart (multipart)
    rpart_match = re.search(r'@RequestPart\s*(?:\(([^)]*)\))?\s*(\w+)\s*:\s*(\S+)', param_text)
    if rpart_match:
        anno_args = rpart_match.group(1) or ""
        param_name = rpart_match.group(2)
        value_match = re.search(r'["\']([^"\']*)["\']', anno_args)
        if value_match:
            param_name = value_match.group(1)
        return Parameter(
            name=param_name, type="multipart",
            data_type=rpart_match.group(3).rstrip(','), required=True
        )

    # ServerHttpRequest / ServerHttpResponse (no annotation)
    raw_match = re.search(r'(\w+)\s*:\s*(ServerHttpRequest|ServerHttpResponse|ServerWebExchange)', param_text)
    if raw_match:
        ptype = "request" if "Request" in raw_match.group(2) else "response"
        if "Exchange" in raw_match.group(2):
            ptype = "exchange"
        return Parameter(
            name=raw_match.group(1), type=ptype,
            data_type=raw_match.group(2), required=False
        )

    # @ModelAttribute
    ma_match = re.search(r'@ModelAttribute\s*(?:\(([^)]*)\))?\s*(\w+)\s*:\s*(\S+)', param_text)
    if ma_match:
        return Parameter(
            name=ma_match.group(2), type="model",
            data_type=ma_match.group(3).rstrip(','), required=True
        )

    # Pageable 파라미터 (어노테이션 없이 직접 사용)
    pageable_match = re.search(r'(\w+)\s*:\s*(Pageable)\b', param_text)
    if pageable_match and '@' not in param_text:
        return Parameter(
            name=pageable_match.group(1), type="pageable",
            data_type="Pageable", required=False
        )

    # 일반 파라미터 (어노테이션 없음) - 무시 가능한 타입 필터
    plain_match = re.search(r'(\w+)\s*:\s*(\S+)', param_text)
    if plain_match:
        name = plain_match.group(1)
        dtype = plain_match.group(2).rstrip(',')
        # Spring 내부 객체는 스킵
        skip_types = {
            'BindingResult', 'Errors', 'Model', 'ModelMap',
            'RedirectAttributes', 'SessionStatus', 'UriComponentsBuilder',
        }
        if dtype in skip_types:
            return None
        return Parameter(
            name=name, type="unknown", data_type=dtype, required=False
        )

    return None


def parse_parameter_java(param_text: str) -> Optional[Parameter]:
    """Java 스타일 함수 파라미터 파싱 (Type name 순서)
    예: '@RequestParam(value = "search") String search'
    예: '@PathVariable Long id'
    예: '@RequestBody UserDto dto'
    """
    param_text = param_text.strip()
    if not param_text:
        return None

    # @Valid, @NotNull 등 유효성 어노테이션 제거
    clean = re.sub(
        r'@(?:Valid|NotNull|Nullable|Nonnull|NotEmpty|NotBlank'
        r'|Size|Min|Max|Pattern|Email|Positive|Negative)\s*(?:\([^)]*\))?\s*',
        '', param_text
    )

    # Java 제네릭 타입 패턴: String, List<User>, ResponseEntity<List<User>>, byte[]
    _JTYPE = r'[\w.]+(?:<[\w<>,.?\s\[\]]+>)?(?:\[\])*(?:\.\.\.)?'

    # @RequestParam
    rp = re.search(
        rf'@RequestParam\s*(?:\(([^)]*)\))?\s*({_JTYPE})\s+(\w+)', clean
    )
    if rp:
        anno_args, data_type, param_name = rp.group(1) or "", rp.group(2), rp.group(3)
        val = re.search(r'(?:value|name)\s*=\s*["\']([^"\']*)["\']', anno_args)
        if val:
            param_name = val.group(1)
        elif '=' not in anno_args:
            val2 = re.search(r'["\']([^"\']*)["\']', anno_args)
            if val2:
                param_name = val2.group(1)
        required = True
        req = re.search(r'required\s*=\s*(true|false)', anno_args, re.IGNORECASE)
        if req:
            required = req.group(1).lower() == 'true'
        default = None
        dv = re.search(r'defaultValue\s*=\s*["\']([^"\']*)["\']', anno_args)
        if dv:
            default = dv.group(1)
            required = False
        return Parameter(name=param_name, type="query", data_type=data_type,
                         required=required, default_value=default)

    # @PathVariable
    pv = re.search(
        rf'@PathVariable\s*(?:\(([^)]*)\))?\s*({_JTYPE})\s+(\w+)', clean
    )
    if pv:
        anno_args, data_type, param_name = pv.group(1) or "", pv.group(2), pv.group(3)
        val = re.search(r'(?:value|name)\s*=\s*["\']([^"\']*)["\']', anno_args)
        if val:
            param_name = val.group(1)
        elif '=' not in anno_args:
            val2 = re.search(r'["\']([^"\']*)["\']', anno_args)
            if val2:
                param_name = val2.group(1)
        return Parameter(name=param_name, type="path", data_type=data_type, required=True)

    # @RequestBody
    rb = re.search(rf'@RequestBody\s*({_JTYPE})\s+(\w+)', clean)
    if rb:
        return Parameter(name=rb.group(2), type="body",
                         data_type=rb.group(1), required=True)

    # @RequestHeader
    rh = re.search(
        rf'@RequestHeader\s*(?:\(([^)]*)\))?\s*({_JTYPE})\s+(\w+)', clean
    )
    if rh:
        anno_args, data_type, param_name = rh.group(1) or "", rh.group(2), rh.group(3)
        val = re.search(r'["\']([^"\']*)["\']', anno_args)
        if val:
            param_name = val.group(1)
        required = True
        req = re.search(r'required\s*=\s*(true|false)', anno_args, re.IGNORECASE)
        if req:
            required = req.group(1).lower() == 'true'
        return Parameter(name=param_name, type="header", data_type=data_type,
                         required=required)

    # @PageableDefault
    if '@PageableDefault' in param_text:
        anno_content = extract_annotation_value(param_text, 'PageableDefault')
        pg = re.search(r'Pageable\s+(\w+)', param_text)
        if pg:
            return Parameter(name=pg.group(1), type="pageable",
                             data_type="Pageable", required=False,
                             default_value=anno_content.strip() if anno_content else None)

    # @RequestPart
    rpart = re.search(
        rf'@RequestPart\s*(?:\(([^)]*)\))?\s*({_JTYPE})\s+(\w+)', clean
    )
    if rpart:
        anno_args = rpart.group(1) or ""
        param_name = rpart.group(3)
        val = re.search(r'["\']([^"\']*)["\']', anno_args)
        if val:
            param_name = val.group(1)
        return Parameter(name=param_name, type="multipart",
                         data_type=rpart.group(2), required=True)

    # @ModelAttribute
    ma = re.search(
        rf'@ModelAttribute\s*(?:\(([^)]*)\))?\s*({_JTYPE})\s+(\w+)', clean
    )
    if ma:
        return Parameter(name=ma.group(3), type="model",
                         data_type=ma.group(2), required=True)

    # 커스텀 인증 어노테이션 (범용: @Session, @PconaSession 등) - Java style
    # 패턴: @Session(...) HttpServletRequest varName  또는  @Session Type varName
    for auth_anno in AUTH_ANNOTATIONS:
        auth_match = re.search(
            rf'@{auth_anno}\s*(?:\([^)]*\))?\s*({_JTYPE})\s+(\w+)', param_text
        )
        if auth_match:
            auth_info = parse_auth_annotation(param_text, auth_anno)
            return Parameter(
                name=auth_match.group(2), type="session",
                data_type=auth_match.group(1), required=True,
                default_value=json.dumps(asdict(auth_info)),
            )

    # HttpServletRequest / HttpServletResponse (no annotation)
    raw = re.search(
        r'(HttpServletRequest|HttpServletResponse|ServerHttpRequest'
        r'|ServerHttpResponse|ServerWebExchange)\s+(\w+)', clean
    )
    if raw:
        ptype = "request" if "Request" in raw.group(1) else "response"
        if "Exchange" in raw.group(1):
            ptype = "exchange"
        return Parameter(name=raw.group(2), type=ptype,
                         data_type=raw.group(1), required=False)

    # Pageable without annotation
    pg = re.search(r'Pageable\s+(\w+)', clean)
    if pg and '@' not in param_text:
        return Parameter(name=pg.group(1), type="pageable",
                         data_type="Pageable", required=False)

    # Plain parameter (no annotation): Type name
    plain = re.search(rf'({_JTYPE})\s+(\w+)\s*$', clean)
    if plain:
        dtype, name = plain.group(1), plain.group(2)
        skip_types = {
            'BindingResult', 'Errors', 'Model', 'ModelMap',
            'RedirectAttributes', 'SessionStatus', 'UriComponentsBuilder',
            'Locale', 'TimeZone', 'Principal',
        }
        if dtype in skip_types:
            return None
        return Parameter(name=name, type="unknown", data_type=dtype, required=False)

    return None


# ============================================================
#  컨트롤러 파싱
# ============================================================

@dataclass
class Endpoint:
    method: str
    api: str
    auth_required: bool
    auth_detail: str
    handler: str
    file: str
    line: int
    module: str
    description: str
    parameters: list
    middleware: list
    return_type: str
    auth_annotations: list = field(default_factory=list)


# HTTP 메서드 매핑 어노테이션
METHOD_ANNOTATIONS = {
    'GetMapping': 'GET',
    'PostMapping': 'POST',
    'PutMapping': 'PUT',
    'DeleteMapping': 'DELETE',
    'PatchMapping': 'PATCH',
}

# Kotlin: (annotations) [open|override|suspend|...] fun name(
KOTLIN_FUNC_PATTERN = re.compile(
    r'((?:\s*@\w+(?:\s*\([^)]*(?:\([^)]*\))*[^)]*\))?(?:\s*\n)?)*)'
    r'\s*(?:(?:open|override|public|private|protected|internal|abstract|final|suspend)\s+)*'
    r'fun\s+(\w+)\s*\(',
    re.MULTILINE
)

# Java: (annotations) [modifiers] ReturnType name(
JAVA_FUNC_PATTERN = re.compile(
    r'((?:\s*@\w+(?:\s*\([^)]*(?:\([^)]*\))*[^)]*\))?(?:\s*\n)?)*)'  # 어노테이션 블록
    r'\s*(?:(?:public|protected|private)\s+)?'                          # 접근 제어자
    r'(?:(?:static|final|abstract|synchronized)\s+)*'                   # 기타 제어자
    r'(?:[\w.]+(?:<[\w<>,.?\s\[\]]+>)?(?:\[\])*)'                      # 반환 타입 (제네릭 포함)
    r'\s+(\w+)\s*\(',                                                   # 메서드 이름
    re.MULTILINE
)


def detect_module(filepath: Path, source_dir: Path) -> str:
    """파일 경로에서 모듈명 추출"""
    rel = filepath.relative_to(source_dir)
    parts = rel.parts
    if parts:
        return parts[0]
    return "unknown"


def find_security_configs(source_dir: Path) -> dict[str, dict]:
    """모듈별 보안 설정을 탐색하여 기본 인증 정책 파악"""
    module_auth = {}

    # Kotlin + Java 모두 스캔
    config_files = list(source_dir.rglob("*.kt")) + list(source_dir.rglob("*.java"))
    for f in config_files:
        if any(ex in f.parts for ex in {"node_modules", ".idea", "target", "build", ".git", "test"}):
            continue

        try:
            content = f.read_text(encoding="utf-8", errors="replace")
        except (IOError, UnicodeDecodeError):
            continue

        # Spring Security 설정 탐지
        if 'SecurityWebFilterChain' in content or 'WebSecurityConfigurerAdapter' in content or 'SecurityFilterChain' in content:
            module = detect_module(f, source_dir)

            auth_paths = []
            permit_paths = []

            # pathMatchers(...).authenticated()
            for m in re.finditer(
                r'pathMatchers\s*\(([^)]*)\)\s*\.\s*authenticated\s*\(\s*\)', content
            ):
                paths = re.findall(r'"([^"]*)"', m.group(1))
                auth_paths.extend(paths)

            # pathMatchers(...).permitAll()
            for m in re.finditer(
                r'pathMatchers\s*\(([^)]*)\)\s*\.\s*permitAll\s*\(\s*\)', content
            ):
                paths = re.findall(r'"([^"]*)"', m.group(1))
                permit_paths.extend(paths)

            # .anyExchange().authenticated()
            if re.search(r'anyExchange\s*\(\s*\)\s*\.\s*authenticated', content):
                auth_paths.append("/**")

            # antMatchers(...).authenticated() (MVC style)
            for m in re.finditer(
                r'antMatchers\s*\(([^)]*)\)\s*\.\s*authenticated\s*\(\s*\)', content
            ):
                paths = re.findall(r'"([^"]*)"', m.group(1))
                auth_paths.extend(paths)

            # CSRF 비활성화 확인
            csrf_disabled = bool(re.search(r'csrf\s*(?:\(\s*\))?\s*\.\s*disable', content))

            # CORS 설정 확인
            cors_open = bool(re.search(r'allowedOrigins\s*\(\s*"\*"\s*\)', content))

            module_auth[module] = {
                "auth_paths": auth_paths,
                "permit_paths": permit_paths,
                "csrf_disabled": csrf_disabled,
                "cors_open": cors_open,
                "config_file": str(f.relative_to(source_dir)),
            }

    return module_auth


def is_path_authenticated(api_path: str, module_auth: dict) -> bool:
    """모듈 보안 설정 기반으로 경로가 인증 필요한지 판단"""
    # permitAll 먼저 체크
    for pp in module_auth.get("permit_paths", []):
        pattern = pp.replace("/**", ".*").replace("/*", "[^/]*").replace("*", ".*")
        if re.match(pattern, api_path):
            return False

    # authenticated 체크
    for ap in module_auth.get("auth_paths", []):
        pattern = ap.replace("/**", ".*").replace("/*", "[^/]*").replace("*", ".*")
        if re.match(pattern, api_path):
            return True

    return False


def split_function_params(params_text: str) -> list[str]:
    """함수 파라미터 문자열을 개별 파라미터로 분리 (중첩 괄호 + 제네릭 고려)"""
    params = []
    paren_depth = 0
    angle_depth = 0
    current = []

    for char in params_text:
        if char in '([':
            paren_depth += 1
            current.append(char)
        elif char in ')]':
            paren_depth -= 1
            current.append(char)
        elif char == '<':
            angle_depth += 1
            current.append(char)
        elif char == '>':
            angle_depth -= 1
            current.append(char)
        elif char == ',' and paren_depth == 0 and angle_depth == 0:
            params.append(''.join(current).strip())
            current = []
        else:
            current.append(char)

    if current:
        last = ''.join(current).strip()
        if last:
            params.append(last)

    return params


def generate_description(func_name: str, http_method: str, path: str,
                         audit_action: Optional[str], kdoc: str) -> str:
    """핸들러 이름과 컨텍스트에서 설명 자동 생성"""
    if kdoc:
        # KDoc 첫 줄 사용
        first_line = kdoc.strip().split('\n')[0].strip('* ').strip()
        if first_line and first_line != '/**' and first_line != '*/':
            return first_line

    if audit_action:
        return audit_action.replace('_', ' ').title()

    # 함수명에서 설명 생성
    desc = func_name
    # camelCase 분리
    desc = re.sub(r'([a-z])([A-Z])', r'\1 \2', desc).lower()
    return desc


def strip_block_comments(content: str) -> tuple[str, list[dict]]:
    """/* ... */ 블록 주석을 제거하고 주석 내 컨트롤러 정보를 수집

    Returns:
        (cleaned_content, list of commented-out controller info dicts)
    """
    commented_controllers = []
    result = []
    i = 0
    in_comment = False
    comment_buf = []

    while i < len(content):
        if not in_comment:
            # 한 줄 주석 (//) 은 유지 (어노테이션이 아니므로 무해)
            if content[i:i+2] == '/*':
                in_comment = True
                comment_buf = []
                i += 2
                continue
            result.append(content[i])
            i += 1
        else:
            if content[i:i+2] == '*/':
                in_comment = False
                comment_text = ''.join(comment_buf)
                # 주석 내에 @Controller 또는 @RestController가 있으면 기록
                ctrl_match = re.search(r'@(?:Rest)?Controller', comment_text)
                if ctrl_match:
                    class_match = re.search(r'\bclass\s+(\w+)', comment_text)
                    class_name = class_match.group(1) if class_match else "Unknown"
                    # 주석 내 엔드포인트 수 추정
                    ep_count = len(re.findall(
                        r'@(?:Get|Post|Put|Delete|Patch|Request)Mapping', comment_text
                    ))
                    commented_controllers.append({
                        "class": class_name,
                        "endpoint_count": ep_count,
                        "reason": "Block comment (/* ... */)",
                    })
                i += 2
                continue
            comment_buf.append(content[i])
            i += 1

    return ''.join(result), commented_controllers


def parse_controller_file(filepath: Path, source_dir: Path,
                          module_auth: dict) -> tuple[list, list[dict]]:
    """컨트롤러 파일을 파싱하여 엔드포인트 목록 반환

    Returns:
        (list[Endpoint], list[dict] of commented-out controllers)
    """
    endpoints = []

    try:
        raw_content = filepath.read_text(encoding="utf-8", errors="replace")
    except (IOError, UnicodeDecodeError):
        return endpoints, []

    # 블록 주석 제거 (주석 내 컨트롤러 정보 수집)
    content, commented = strip_block_comments(raw_content)
    lines = content.splitlines()

    # @RestController 또는 @Controller 확인 (주석 제거 후)
    if not re.search(r'@(?:Rest)?Controller', content):
        # 주석 처리된 컨트롤러 정보만 반환
        if commented:
            for c in commented:
                c["file"] = str(filepath.relative_to(source_dir))
        return endpoints, commented

    module = detect_module(filepath, source_dir)
    rel_path = str(filepath.relative_to(source_dir))
    mod_auth = module_auth.get(module, {})

    # 클래스명 추출 (class와 이름이 다른 줄에 있을 수 있음)
    class_match = re.search(r'\bclass\s+(\w+)', content)
    class_name = class_match.group(1) if class_match else "Unknown"

    # 클래스 레벨 @RequestMapping 베이스 경로
    base_paths = [""]
    # 클래스 어노테이션 영역에서 @RequestMapping 찾기
    class_keyword_match = re.search(r'\bclass\s', content)
    class_region = content[:class_keyword_match.start()] if class_keyword_match else ""
    rm_content = extract_annotation_value(class_region, 'RequestMapping')
    if rm_content is not None:
        base_paths = extract_paths_from_annotation(rm_content)
        if not base_paths:
            base_paths = [""]

    # 언어 감지
    is_java = filepath.suffix == '.java'
    func_pattern = JAVA_FUNC_PATTERN if is_java else KOTLIN_FUNC_PATTERN
    param_parser = parse_parameter_java if is_java else parse_parameter

    for match in func_pattern.finditer(content):
        anno_block = match.group(1)
        func_name = match.group(2)
        func_start = match.start()
        params_start = match.end()

        # 함수가 시작되는 라인 번호
        line_num = content[:func_start].count('\n') + 1

        # HTTP 메서드 어노테이션 확인
        http_methods = []
        method_paths = []

        for anno_name, http_method in METHOD_ANNOTATIONS.items():
            anno_content = extract_annotation_value(anno_block, anno_name)
            if anno_content is not None:
                http_methods.append(http_method)
                method_paths = extract_paths_from_annotation(anno_content)
            elif re.search(rf'@{anno_name}\b(?!\s*\()', anno_block):
                # 괄호 없는 @GetMapping 등
                http_methods.append(http_method)
                method_paths = [""]

        # @RequestMapping (메서드 지정)
        rm_content = extract_annotation_value(anno_block, 'RequestMapping')
        if rm_content is not None and not http_methods:
            http_methods = extract_method_from_request_mapping(rm_content)
            method_paths = extract_paths_from_annotation(rm_content)
        elif rm_content is not None:
            # 이미 다른 매핑이 있으면 경로만 업데이트
            additional_paths = extract_paths_from_annotation(rm_content)
            if additional_paths and additional_paths != [""]:
                method_paths = additional_paths

        if not http_methods:
            continue  # HTTP 매핑이 없는 함수는 스킵

        # 파라미터 영역 추출 (괄호 매칭)
        depth = 1
        i = params_start
        while i < len(content) and depth > 0:
            if content[i] == '(':
                depth += 1
            elif content[i] == ')':
                depth -= 1
            i += 1
        params_text = content[params_start:i - 1]

        # 반환 타입 추출
        return_type = ""
        after_params = content[i:i + 200]
        if is_java:
            # Java: 반환 타입은 메서드 선언 앞에 위치 (func_pattern에서 이미 스킵)
            # 어노테이션 블록 이후~메서드명 이전에서 추출 시도
            anno_end = anno_block.rstrip()
            pre_func = content[match.start() + len(anno_block):match.end()]
            rt_java = re.search(
                r'(?:(?:public|protected|private)\s+)?'
                r'(?:(?:static|final|abstract|synchronized)\s+)*'
                r'([\w.]+(?:<[\w<>,.?\s\[\]]+>)?(?:\[\])*)\s+\w+\s*$',
                pre_func.strip()
            )
            if rt_java:
                return_type = rt_java.group(1)
            # throws 절 확인
            throws_match = re.search(r'throws\s+[\w.,\s]+', after_params)
        else:
            # Kotlin: fun name(...): ReturnType
            rt_match = re.search(r':\s*([^\n{=]+)', after_params)
            if rt_match:
                return_type = rt_match.group(1).strip().rstrip('{').strip()

        # 파라미터 파싱
        param_strings = split_function_params(params_text)
        parameters = []
        for ps in param_strings:
            p = param_parser(ps)
            if p:
                parameters.append(p)

        # 인증 정보
        preauthorize = extract_preauthorize(anno_block)
        audit_action = extract_audit_action(anno_block)

        # 미들웨어 목록
        middleware = []
        if preauthorize:
            middleware.append(f'@PreAuthorize("{preauthorize}")')
        if audit_action:
            middleware.append(f"@PconaAudit(action='{audit_action}')")
        # @Secured
        secured = extract_annotation_value(anno_block, 'Secured')
        if secured:
            middleware.append(f'@Secured({secured})')

        # KDoc 주석 추출 (함수 바로 위)
        kdoc = ""
        anno_start_line = content[:match.start()].count('\n')
        # 어노테이션 블록 위 줄 검색
        search_start = max(0, anno_start_line - 15)
        pre_lines = lines[search_start:anno_start_line]
        kdoc_lines = []
        in_kdoc = False
        for pl in reversed(pre_lines):
            stripped = pl.strip()
            if stripped.endswith('*/'):
                in_kdoc = True
                kdoc_lines.insert(0, stripped)
            elif in_kdoc:
                kdoc_lines.insert(0, stripped)
                if stripped.startswith('/**') or stripped.startswith('/*'):
                    break
        if kdoc_lines:
            kdoc = '\n'.join(kdoc_lines)

        # 설명 생성
        description = generate_description(
            func_name, http_methods[0], method_paths[0] if method_paths else "",
            audit_action, kdoc
        )

        # 엔드포인트 생성 (base_path × method_path × http_method)
        for http_method in http_methods:
            for base in base_paths:
                for mpath in (method_paths if method_paths else [""]):
                    full_path = (base.rstrip('/') + '/' + mpath.lstrip('/')).rstrip('/')
                    if not full_path:
                        full_path = "/"

                    # 인증 여부 판단
                    auth_required = False
                    auth_detail = ""
                    ep_auth_annotations = []

                    # 1) @PreAuthorize
                    if preauthorize:
                        auth_required = True
                        auth_detail = preauthorize

                    # 2) @Secured
                    elif secured:
                        auth_required = True
                        auth_detail = f"@Secured({secured})"

                    # 3) Security config 경로 매칭
                    elif mod_auth:
                        auth_required = is_path_authenticated(full_path, mod_auth)
                        if auth_required:
                            auth_detail = "Security config (path-based)"

                    # 4) 커스텀 인증 어노테이션 파라미터 분석
                    #    보안 등급 (4-Level 매트릭스):
                    #      Level 1: required=true,  permitted=true  → 완전 인증 (Active User)
                    #      Level 2: required=true,  permitted=false → 기본 인증 (Logged-in Only)
                    #      Level 3: required=false, permitted=false → 비인증 (Public)
                    #      Level 4: required=false, permitted=true  → 조건부 인증 (Guest or Safe User)
                    #    auth_required 이진 분류:
                    #      required=true  → auth_required=True  (Level 1, 2)
                    #      required=false → auth_required=False (Level 3, 4)
                    session_params = [p for p in parameters if p.type == "session"]
                    for sp in session_params:
                        auth_info = None
                        if sp.default_value:
                            try:
                                auth_info = json.loads(sp.default_value)
                            except (json.JSONDecodeError, TypeError):
                                pass

                        if auth_info:
                            ep_auth_annotations.append(auth_info)
                            anno_name = auth_info.get('name', 'Unknown')
                            is_required = auth_info.get('required', True)
                            is_permitted = auth_info.get('permitted', False)

                            if is_required:
                                auth_required = True
                                if is_permitted:
                                    # Level 1: 완전 인증 - 로그인 필수 + 활동 가능 유저만
                                    if not auth_detail:
                                        auth_detail = f"@{anno_name}(required=true, permitted=true)"
                                else:
                                    # Level 2: 기본 인증 - 로그인 필수
                                    if not auth_detail:
                                        auth_detail = f"@{anno_name}(required=true)"
                            else:
                                if is_permitted:
                                    # Level 4: 조건부 인증 - 비회원 OK, 로그인 시 정상 유저만
                                    if not auth_required and not auth_detail:
                                        auth_detail = f"@{anno_name}(required=false, permitted=true)"
                                else:
                                    # Level 3: 비인증 - 누구나 접근 가능
                                    if not auth_required and not auth_detail:
                                        auth_detail = f"@{anno_name}(required=false)"
                        else:
                            # AuthAnnotation 정보 없으면 보수적으로 인증 필요 처리
                            auth_required = True
                            if not auth_detail:
                                auth_detail = "Custom auth annotation (session parameter)"

                    endpoints.append(Endpoint(
                        method=http_method,
                        api=full_path,
                        auth_required=auth_required,
                        auth_detail=auth_detail,
                        handler=f"{class_name}.{func_name}()",
                        file=rel_path,
                        line=line_num,
                        module=module,
                        description=description,
                        parameters=[asdict(p) for p in parameters],
                        middleware=middleware,
                        return_type=return_type,
                        auth_annotations=ep_auth_annotations,
                    ))

    return endpoints, commented


# ============================================================
#  DTO 연동
# ============================================================

_PRIMITIVE_TYPES = {
    'String', 'Int', 'Long', 'Double', 'Float', 'Boolean', 'Byte',
    'Short', 'Char', 'Unit', 'Void', 'void', 'Object', 'Any',
    'int', 'long', 'double', 'float', 'boolean', 'byte', 'short', 'char',
    'Integer', 'BigDecimal', 'BigInteger', 'Number',
    'Date', 'LocalDate', 'LocalDateTime', 'Instant', 'ZonedDateTime',
    'UUID', 'Pageable', 'MultipartFile', 'Part',
    'HttpServletRequest', 'HttpServletResponse',
    'ServerHttpRequest', 'ServerHttpResponse', 'ServerWebExchange',
    'Authentication', 'Principal',
}


def is_primitive_type(dtype: str) -> bool:
    """프리미티브/표준 라이브러리 타입 여부 판별"""
    base = dtype.rstrip('?').split('<')[0].split('.')[-1].rstrip('[]')
    return base in _PRIMITIVE_TYPES


def enrich_parameters_with_dto(endpoints: list, dto_catalog: dict) -> None:
    """엔드포인트 파라미터에 DTO 필드 정보를 추가

    각 파라미터의 data_type이 커스텀 타입이면 DTO 카탈로그에서 조회하여
    resolved_fields, resolved_from 필드를 추가합니다.
    """
    type_index = dto_catalog.get("type_index", {})
    types = dto_catalog.get("types", {})

    for ep in endpoints:
        for param in ep.parameters:
            dtype = param.get("data_type", "")
            if not dtype or is_primitive_type(dtype):
                continue

            # ? 제거, 제네릭 내부 타입도 시도
            clean_type = dtype.rstrip('?')

            # 1차: 전체 이름으로 조회
            qualified_names = type_index.get(clean_type, [])

            # 2차: 마지막 부분 (simple name)으로 조회
            if not qualified_names:
                simple = clean_type.split('.')[-1]
                qualified_names = type_index.get(simple, [])

            # 3차: 제네릭 파라미터 타입 시도 (List<UserDTO> → UserDTO)
            if not qualified_names and '<' in clean_type:
                inner = re.search(r'<(.+?)>', clean_type)
                if inner:
                    inner_type = inner.group(1).split(',')[0].strip()
                    if not is_primitive_type(inner_type):
                        qualified_names = type_index.get(inner_type, [])
                        if not qualified_names:
                            simple = inner_type.split('.')[-1]
                            qualified_names = type_index.get(simple, [])

            if qualified_names:
                type_info = types.get(qualified_names[0])
                if type_info and type_info.get("fields"):
                    param["resolved_fields"] = type_info["fields"]
                    param["resolved_from"] = qualified_names[0]


# ============================================================
#  디렉토리 스캔
# ============================================================

def scan_directory(source_dir: Path, dto_catalog: dict = None) -> dict:
    """디렉토리 전체를 스캔하여 API 엔드포인트 추출"""

    # 1. 보안 설정 먼저 탐색
    module_auth = find_security_configs(source_dir)

    # 2. 컨트롤러 파일 탐색
    controller_files = []
    for f in source_dir.rglob("*.kt"):
        if any(ex in f.parts for ex in {"node_modules", ".idea", "target", "build", ".git", "test"}):
            continue
        controller_files.append(f)

    # Java 파일도 포함
    for f in source_dir.rglob("*.java"):
        if any(ex in f.parts for ex in {"node_modules", ".idea", "target", "build", ".git", "test"}):
            continue
        controller_files.append(f)

    # 3. 각 파일에서 엔드포인트 추출
    all_endpoints = []
    all_commented_controllers = []
    scanned_files = 0
    controller_count = 0

    for f in controller_files:
        try:
            raw = f.read_text(encoding="utf-8", errors="replace")
        except (IOError, UnicodeDecodeError):
            continue

        scanned_files += 1

        # @Controller/@RestController 가 있는 파일만 파싱 (raw에서 체크)
        if not re.search(r'@(?:Rest)?Controller', raw):
            continue

        endpoints, commented = parse_controller_file(f, source_dir, module_auth)
        if endpoints:
            controller_count += 1
        all_endpoints.extend(endpoints)
        all_commented_controllers.extend(commented)

    # 3.5. DTO 카탈로그 연동 (파라미터 타입 해석)
    if dto_catalog:
        enrich_parameters_with_dto(all_endpoints, dto_catalog)

    # 4. 모듈별 통계
    module_stats = {}
    for ep in all_endpoints:
        mod = ep.module
        if mod not in module_stats:
            module_stats[mod] = {"total": 0, "auth_required": 0, "no_auth": 0}
        module_stats[mod]["total"] += 1
        if ep.auth_required:
            module_stats[mod]["auth_required"] += 1
        else:
            module_stats[mod]["no_auth"] += 1

    # 5. HTTP 메서드별 통계
    method_stats = {}
    for ep in all_endpoints:
        m = ep.method
        method_stats[m] = method_stats.get(m, 0) + 1

    # 6. 인증 통계 (이진 분류)
    auth_stats = {
        "auth_required": sum(1 for ep in all_endpoints if ep.auth_required),
        "auth_not_required": sum(1 for ep in all_endpoints if not ep.auth_required),
    }

    # 보안 등급별 통계 (4-Level 매트릭스)
    auth_detail_stats = {}
    for ep in all_endpoints:
        detail = ep.auth_detail or "(none)"
        if "PreAuthorize" in detail:
            cat = "preauthorize"
        elif detail.startswith("@Secured"):
            cat = "secured"
        elif "Security config" in detail:
            cat = "security_config"
        elif "required=true, permitted=true" in detail:
            cat = "L1_완전인증"
        elif "required=true" in detail:
            cat = "L2_기본인증"
        elif "required=false, permitted=true" in detail:
            cat = "L4_조건부인증"
        elif "required=false" in detail:
            cat = "L3_비인증"
        elif ep.auth_annotations:
            cat = "L2_기본인증"
        else:
            cat = "no_auth_annotation"
        auth_detail_stats[cat] = auth_detail_stats.get(cat, 0) + 1

    result = {
        "source_dir": str(source_dir),
        "total_files_scanned": scanned_files,
        "total_controllers": controller_count,
        "total_endpoints": len(all_endpoints),
        "security_configs": module_auth,
        "module_stats": module_stats,
        "method_stats": method_stats,
        "auth_stats": auth_stats,
        "auth_detail_stats": auth_detail_stats,
        "endpoints": [asdict(ep) for ep in all_endpoints],
    }

    if all_commented_controllers:
        result["commented_controllers"] = all_commented_controllers

    return result


# ============================================================
#  메인
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="API 엔드포인트 인벤토리 자동 추출 (Spring MVC/WebFlux 컨트롤러)"
    )
    parser.add_argument(
        "source_dir",
        help="스캔 대상 소스코드 디렉토리",
    )
    parser.add_argument(
        "--output", "-o",
        help="결과 출력 JSON 파일 경로",
        default=None,
    )
    parser.add_argument(
        "--quiet", "-q",
        help="요약만 출력",
        action="store_true",
    )
    parser.add_argument(
        "--auth-annotations",
        nargs="*",
        help="추가 커스텀 인증 어노테이션 이름 (예: Session LoginUser)",
        default=[],
    )
    parser.add_argument(
        "--dto-catalog", "-d",
        help="DTO 타입 카탈로그 JSON (scan_dto.py 출력) 경로",
        default=None,
    )
    args = parser.parse_args()

    source_dir = Path(args.source_dir)
    if not source_dir.exists():
        print(f"Error: 디렉토리를 찾을 수 없습니다: {source_dir}")
        sys.exit(1)

    # 커스텀 인증 어노테이션 추가
    if args.auth_annotations:
        AUTH_ANNOTATIONS.update(args.auth_annotations)
        print(f"인증 어노테이션: {sorted(AUTH_ANNOTATIONS)}")

    # DTO 카탈로그 로드
    dto_catalog = None
    if args.dto_catalog:
        dto_path = Path(args.dto_catalog)
        if dto_path.exists():
            with open(dto_path, encoding="utf-8") as f:
                dto_catalog = json.load(f)
            print(f"DTO 카탈로그 로드: {dto_catalog.get('total_types', 0)}개 타입")
        else:
            print(f"Warning: DTO 카탈로그를 찾을 수 없습니다: {dto_path}")

    print(f"스캔 대상: {source_dir}")
    result = scan_directory(source_dir, dto_catalog=dto_catalog)

    # 요약 출력
    print(f"\n스캔 완료: {result['total_files_scanned']}개 파일, "
          f"{result['total_controllers']}개 컨트롤러, "
          f"{result['total_endpoints']}개 엔드포인트")

    print(f"\n모듈별:")
    for mod, stats in result["module_stats"].items():
        print(f"  {mod}: {stats['total']}개 "
              f"(인증: {stats['auth_required']}, 비인증: {stats['no_auth']})")

    print(f"\nHTTP 메서드별:")
    for method, count in sorted(result["method_stats"].items()):
        print(f"  {method}: {count}개")

    auth_s = result.get("auth_stats", {})
    if auth_s:
        print(f"\n인증 분류:")
        print(f"  인증 필요 (auth_required=true): {auth_s.get('auth_required', 0)}개")
        print(f"  인증 불필요 (auth_required=false): {auth_s.get('auth_not_required', 0)}개")

    auth_ds = result.get("auth_detail_stats", {})
    if auth_ds:
        level_desc = {
            "L1_완전인증": "Level 1 - 완전 인증 (required=true, permitted=true)",
            "L2_기본인증": "Level 2 - 기본 인증 (required=true)",
            "L3_비인증": "Level 3 - 비인증 (required=false)",
            "L4_조건부인증": "Level 4 - 조건부 인증 (required=false, permitted=true)",
            "preauthorize": "@PreAuthorize",
            "secured": "@Secured",
            "security_config": "Security Config",
            "no_auth_annotation": "인증 어노테이션 없음",
        }
        print(f"\n보안 등급 상세:")
        for key, count in sorted(auth_ds.items(), key=lambda x: -x[1]):
            label = level_desc.get(key, key)
            print(f"  {label}: {count}개")

    if not args.quiet:
        # 보안 설정 요약
        if result["security_configs"]:
            print(f"\n보안 설정:")
            for mod, cfg in result["security_configs"].items():
                print(f"  {mod}:")
                print(f"    config: {cfg['config_file']}")
                print(f"    auth paths: {cfg['auth_paths']}")
                print(f"    permit paths: {cfg['permit_paths']}")
                print(f"    CSRF disabled: {cfg['csrf_disabled']}")
                print(f"    CORS open: {cfg['cors_open']}")

        # 엔드포인트 목록
        print(f"\n엔드포인트 목록:")
        for ep in result["endpoints"]:
            auth = "AUTH" if ep["auth_required"] else "OPEN"
            params = ", ".join(
                f"{p['name']}:{p['type']}" for p in ep["parameters"]
                if p["type"] not in ("request", "response", "exchange")
            )
            print(f"  [{ep['method']:6s}] {ep['api']:<40s} [{auth}] "
                  f"{ep['handler']:<40s} params=({params})")

    # 주석 처리된 컨트롤러 출력
    commented = result.get("commented_controllers", [])
    if commented:
        print(f"\n주석 처리된 컨트롤러 ({len(commented)}개, 분석 제외됨):")
        for cc in commented:
            print(f"  - {cc['class']}: 엔드포인트 {cc['endpoint_count']}개 ({cc['reason']})")

    # 파일 출력
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        print(f"\n결과 저장: {output_path}")
    elif not args.quiet:
        print("\n(--output 옵션으로 JSON 파일 저장 가능)")


if __name__ == "__main__":
    main()
