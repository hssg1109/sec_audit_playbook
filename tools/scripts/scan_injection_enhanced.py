#!/usr/bin/env python3
"""
인젝션 고도화 진단 스크립트 - endpoint별 양호/취약 판정

scan_api.py 결과를 기반으로 각 API endpoint에 대해
Controller → Service → Repository 호출 흐름을 추적하고,
endpoint별로 SQL Injection 양호/취약/정보를 판정합니다.

추가로 OS Command Injection, SSI Injection 키워드 전역 스캔을 수행합니다.

사용법:
    python scan_injection_enhanced.py <source_dir> --api-inventory <json>
    python scan_injection_enhanced.py testbed/3-pcona/.../pcona-console \
        --api-inventory state/pcona_api_scan.json \
        --modules pcona-console \
        -o state/pcona_task_22_enhanced.json
"""

import json
import re
import sys
import argparse
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional
from datetime import datetime

# scan_injection_patterns.py에서 패턴 가져오기
sys.path.insert(0, str(Path(__file__).parent))
from scan_injection_patterns import (
    OS_CMD_PATTERNS, OS_CMD_SAFE_PATTERNS, OS_CMD_FILTER_CHARS,
    SSI_PATTERNS, scan_file, matches_glob,
)


# ============================================================
#  0. JPA / Spring Data 상수
# ============================================================

# JPA Safe Methods - Spring Data JPA 내장 메서드 (PreparedStatement 자동 바인딩)
JPA_SAFE_METHODS = {
    # CrudRepository
    'count', 'delete', 'deleteAll', 'deleteAllById', 'deleteById',
    'existsById', 'findAll', 'findAllById', 'findById', 'save', 'saveAll',
    # JpaRepository
    'deleteAllInBatch', 'deleteInBatch', 'flush', 'getById', 'getOne',
    'getReferenceById', 'saveAllAndFlush', 'saveAndFlush',
}

# Spring Data JPA 메서드명 규칙 prefix (findBy*, countBy* 등 → 자동 생성, 안전)
JPA_CONVENTION_PREFIXES = (
    'findBy', 'countBy', 'existsBy', 'deleteBy', 'removeBy',
    'readBy', 'getBy', 'queryBy', 'searchBy', 'streamBy',
    'findFirst', 'findTop', 'findDistinct',
)

# [Phase 12] Controller→Service 위임 추적 대상 컴포넌트 접미사
_TRACEABLE_COMPONENT_SUFFIXES = (
    'Service', 'UseCase', 'Handler', 'Adapter', 'Facade',
    'Provider', 'Helper', 'Processor', 'Manager', 'Delegate',
    'Component', 'Coordinator',
)


# ============================================================
#  1. 데이터 구조
# ============================================================

@dataclass
class CallNode:
    """호출 그래프 노드"""
    class_name: str
    file_path: str
    method_name: str
    called_methods: list = field(default_factory=list)  # [(class, method)]


@dataclass
class DbOperation:
    """Repository의 DB 접근 정보"""
    method: str
    access_type: str        # bind, orm, criteria, criteria_tosql, raw_concat, mybatis_safe, mybatis_unsafe, ibatis_safe, ibatis_unsafe, jpa_builtin, none
    detail: str             # 상세 진단 내역
    line: int = 0
    code_snippet: str = ""
    is_vulnerable: bool = False


@dataclass
class EndpointDiagnosis:
    """Endpoint별 진단 결과"""
    no: str
    platform: str = "WEB"
    check_item: str = "SQL인젝션"
    result: str = "양호"         # 양호 / 취약 / 정보 / N/A
    severity: str = "Risk 2"
    threat: str = "DB정보 유출"

    # API 정보
    http_method: str = ""
    request_mapping: str = ""
    process_file: str = ""
    handler: str = ""
    method_name: str = ""
    parameters: str = ""

    # 흐름 추적
    service_calls: list = field(default_factory=list)
    repository_calls: list = field(default_factory=list)
    db_operations: list = field(default_factory=list)

    # 진단 상세
    filter_type: str = "N/A"
    filter_detail: str = "N/A"
    diagnosis_type: str = ""
    diagnosis_detail: str = ""
    diagnosis_method: str = "자동"
    needs_review: bool = False

    # 코드 증적
    evidence: list = field(default_factory=list)


# ============================================================
#  2. Kotlin/Java 파서 유틸리티
# ============================================================

def read_file_safe(filepath: Path) -> str:
    """파일 안전 읽기"""
    try:
        return filepath.read_text(encoding="utf-8", errors="replace")
    except (IOError, UnicodeDecodeError):
        return ""


def extract_class_name(content: str) -> Optional[str]:
    """클래스명 추출 (class / interface / object 대응)"""
    m = re.search(r'(?:class|interface|object)\s+(\w+)', content)
    return m.group(1) if m else None


def extract_constructor_deps(content: str) -> list:
    """생성자 주입 의존성 추출

    지원 패턴:
    1. Kotlin primary constructor: class Foo(private val x: FooService, ...)
    2. Java @Autowired field injection: @Autowired private FooService fooService;
    3. Java explicit constructor injection: public Foo(FooService svc, BarService bar) { ... }
    4. Java private final field: private final FooService fooService;
    5. Kotlin @Autowired lateinit var: @Autowired lateinit var svc: FooService
    6. Kotlin property bean injection: private val svc: FooService

    Returns: [('fieldName', 'TypeName'), ...]
    """
    deps = []

    # 1. Kotlin primary constructor: class Foo(private val x: Type, ...)
    class_match = re.search(r'class\s+\w+\s*\((.*?)\)\s*(?:\{|:)', content, re.DOTALL)
    if class_match:
        params_text = class_match.group(1)
        for m in re.finditer(r'(?:private\s+)?(?:val|var)\s+(\w+)\s*:\s*(\w+)', params_text):
            deps.append((m.group(1), m.group(2)))

    # 2. Java @Autowired field injection:
    #    @Autowired private FooService fooService;
    #    @Autowired FooService fooService;  (package-private, 접근제한자 없음)
    #    @Autowired protected FooService fooService;
    #    줄바꿈/불규칙 공백 대응
    for m in re.finditer(
        r'@(?:Autowired|Inject|Resource)[\s\n]+(?:(?:private|protected|public)[\s\n]+)?(\w+)[\s\n]+(\w+)\s*;',
        content
    ):
        if (m.group(2), m.group(1)) not in deps:
            deps.append((m.group(2), m.group(1)))

    # 3. Java explicit constructor injection: public ClassName(Type1 param1, Type2 param2, ...)
    #    Matches @Autowired constructor or any public constructor of the class
    class_name_match = re.search(r'class\s+(\w+)', content)
    if class_name_match:
        cls_name = class_name_match.group(1)
        # @Autowired 또는 @Inject가 붙은 생성자, 또는 public 생성자
        ctor_pattern = rf'(?:@(?:Autowired|Inject)\s+)?(?:public\s+)?{re.escape(cls_name)}\s*\((.*?)\)\s*\{{'
        ctor_match = re.search(ctor_pattern, content, re.DOTALL)
        if ctor_match:
            ctor_params = ctor_match.group(1)
            # Java constructor params: TypeName paramName (with optional annotations/generics)
            for m in re.finditer(
                r'(?:@\w+(?:\([^)]*\))?\s+)*(\w+)(?:<[^>]*>)?\s+(\w+)\s*(?:,|$)',
                ctor_params
            ):
                type_name, field_name = m.group(1), m.group(2)
                if (field_name, type_name) not in deps:
                    deps.append((field_name, type_name))

    # 4. Java private final field: private final FooService fooService;
    #    (constructor injection without @Autowired — Lombok @RequiredArgsConstructor or explicit)
    for m in re.finditer(r'private\s+final\s+(\w+)(?:<[^>]*>)?\s+(\w+)\s*;', content):
        type_name, field_name = m.group(1), m.group(2)
        if (field_name, type_name) not in deps:
            deps.append((field_name, type_name))

    # 5. Kotlin @Autowired lateinit var: @Autowired [private|protected] lateinit var fieldName: TypeName
    #    줄바꿈/불규칙 공백 대응 (re.DOTALL로 \s가 \n도 매칭)
    for m in re.finditer(
        r'@(?:Autowired|Inject|Resource)[\s\n]+(?:(?:private|protected)[\s\n]+)?lateinit[\s\n]+var[\s\n]+(\w+)[\s\n]*:[\s\n]*(\w+)',
        content
    ):
        if (m.group(1), m.group(2)) not in deps:
            deps.append((m.group(1), m.group(2)))

    # 6. Kotlin property injection (Spring bean by type suffix)
    bean_suffixes = ('Service', 'Repository', 'Mapper', 'Dao', 'DAO', 'Template',
                     'Client', 'SqlMapClient', 'DataSource',
                     'UseCase', 'Handler', 'Adapter', 'Facade',
                     'Provider', 'Helper', 'Processor', 'Manager', 'Delegate',
                     'Component', 'Coordinator')
    for m in re.finditer(
        r'(?:private|protected|internal)\s+(?:val|var)\s+(\w+)\s*:\s*(\w+)',
        content
    ):
        field_name, type_name = m.group(1), m.group(2)
        if any(type_name.endswith(s) for s in bean_suffixes):
            if (field_name, type_name) not in deps:
                deps.append((field_name, type_name))

    return deps


def extract_method_body(content: str, method_name: str) -> str:
    """메서드 본문 추출 (중괄호 매칭)"""
    # fun methodName( 또는 def methodName(
    pattern = rf'fun\s+{re.escape(method_name)}\s*\('
    match = re.search(pattern, content)
    if not match:
        # Java style: public ReturnType methodName(
        # ReturnType can be: simple (String), dotted (Protos.Type), generic (ResponseEntity<Foo>),
        # array (byte[]), or combinations (List<Map<String, Object>>)
        pattern = rf'(?:public|private|protected)\s+[\w.<>,\[\] ?]+\s+{re.escape(method_name)}\s*\('
        match = re.search(pattern, content)
    if not match:
        # Package-private Java method (no access modifier): ReturnType methodName(
        pattern = rf'(?:^|\n)\s+[\w.]+(?:<[^>]*>)?\s+{re.escape(method_name)}\s*\('
        match = re.search(pattern, content)
    if not match:
        return ""

    # 함수 시작부터 본문 추출
    start = match.start()
    # { 를 찾을 때까지
    brace_start = content.find('{', start)
    if brace_start == -1:
        # expression body (= ...) 처리
        eq_pos = content.find('=', start)
        if eq_pos != -1:
            # 다음 fun/class/} 까지
            end = len(content)
            for end_pat in [r'\n\s*fun\s', r'\n\s*class\s', r'\n\}']:
                m = re.search(end_pat, content[eq_pos:])
                if m and eq_pos + m.start() < end:
                    end = eq_pos + m.start()
            return content[start:end]
        return ""

    depth = 0
    i = brace_start
    while i < len(content):
        if content[i] == '{':
            depth += 1
        elif content[i] == '}':
            depth -= 1
            if depth == 0:
                return content[start:i + 1]
        i += 1

    return content[start:]


def extract_method_calls(method_body: str, field_names: list) -> list:
    """메서드 본문에서 특정 필드의 메서드 호출 추출
    예: service.findAll(x, y) → ('service', 'findAll')
        service::findAll → ('service', 'findAll')
    """
    calls = []
    skip_methods = frozenset({
        'toString', 'hashCode', 'equals', 'getClass',
        'get', 'set', 'let', 'also', 'apply', 'run',
    })
    for field_name in field_names:
        escaped = re.escape(field_name)
        # 1. 표준 메서드 호출: field.method( (줄바꿈/공백 내성)
        for m in re.finditer(rf'{escaped}[\s\n]*\.[\s\n]*(\w+)\s*\(', method_body):
            method = m.group(1)
            if method not in skip_methods:
                calls.append((field_name, method))
        # 2. 메서드 참조: field::method (Lambda/Stream에서 사용)
        for m in re.finditer(rf'{escaped}[\s\n]*::[\s\n]*(\w+)', method_body):
            method = m.group(1)
            if method not in skip_methods and (field_name, method) not in calls:
                calls.append((field_name, method))
    return calls


# ============================================================
#  3. Call Graph 구축
# ============================================================

def find_class_file(source_dir: Path, class_name: str,
                    suffixes: list = None) -> Optional[Path]:
    """클래스명으로 파일 찾기"""
    if suffixes is None:
        suffixes = ['.kt', '.java']

    for suffix in suffixes:
        candidates = list(source_dir.rglob(f"{class_name}{suffix}"))
        if candidates:
            return candidates[0]

    # 파일명과 클래스명이 다를 수 있으므로 내용 검색
    for suffix in suffixes:
        for f in source_dir.rglob(f"*{suffix}"):
            try:
                content = f.read_text(encoding="utf-8", errors="replace")
                if re.search(rf'class\s+{re.escape(class_name)}\b', content):
                    return f
            except (IOError, UnicodeDecodeError):
                continue
    return None


def build_class_index(source_dir: Path) -> dict:
    """소스 디렉토리의 클래스 인덱스 구축 (클래스명 → 파일 경로)"""
    index = {}
    exclude_dirs = {"node_modules", ".idea", "target", "build", ".git", "dist", "test"}

    for suffix in ('.kt', '.java'):
        for f in source_dir.rglob(f"*{suffix}"):
            if any(ex in f.parts for ex in exclude_dirs):
                continue
            try:
                content = f.read_text(encoding="utf-8", errors="replace")
                for m in re.finditer(r'(?:class|interface|object)\s+(\w+)', content):
                    index[m.group(1)] = f
            except (IOError, UnicodeDecodeError):
                continue
    return index


def _collect_element_text(elem) -> str:
    """XML Element의 순수 텍스트를 재귀적으로 수집 (주석/CDATA 안전 처리)

    ElementTree는 <!-- 주석 --> 을 자동으로 무시하므로,
    elem.text + 모든 자식의 tail 을 연결하면 SQL 본문만 추출됨.
    """
    parts = []
    if elem.text:
        parts.append(elem.text)
    for child in elem:
        # 자식 태그의 텍스트도 포함 (iBatis <isNotEmpty> 등 동적 태그 내부)
        parts.append(_collect_element_text(child))
        if child.tail:
            parts.append(child.tail)
    return "".join(parts)


def build_mybatis_index(source_dir: Path) -> dict:
    """MyBatis/iBatis XML mapper 파일을 ElementTree 기반으로 파싱하여 SQL ID 인덱스 구축

    주석(<!-- -->)은 자동 무시되어 오탐 방지.
    <include refid="...">는 해당 <sql id="..."> 를 인라인 병합.

    Returns:
        {
            "namespace.sqlId": {
                "file": "relative/path/to/mapper.xml",
                "sql_type": "select|insert|update|delete",
                "has_dollar": bool,         # ${} 사용 여부 (MyBatis 취약)
                "has_hash": bool,           # #{} 사용 여부 (MyBatis 안전)
                "has_ibatis_dollar": bool,   # $param$ 사용 여부 (iBatis 취약)
                "has_ibatis_hash": bool,     # #param# 사용 여부 (iBatis 안전)
                "dollar_vars": list,         # ${} 내 변수명 목록
                "has_dynamic_binding": bool, # ORDER BY/LIMIT 등 동적 바인딩 여부
            },
            ...
        }
    """
    import xml.etree.ElementTree as ET

    index = {}
    exclude_dirs = {"node_modules", ".idea", "target", "build", ".git", "dist", "test"}
    sql_tags = {"select", "insert", "update", "delete"}

    # 동적 바인딩 예외 변수명 (ORDER BY ${col} 등 기능상 불가피)
    dynamic_binding_vars = {"order", "sort", "column", "col", "table", "schema",
                            "tableName", "orderBy", "sortColumn", "sortField",
                            "direction", "limit", "offset"}

    for xml_file in source_dir.rglob("*.xml"):
        if any(ex in xml_file.parts for ex in exclude_dirs):
            continue

        content = read_file_safe(xml_file)
        if not content:
            continue

        # namespace 빠른 필터 (sqlMap 또는 mapper가 없으면 skip)
        if "<sqlMap " not in content and "<mapper " not in content:
            continue

        # ElementTree 파싱
        try:
            tree = ET.parse(xml_file)
        except ET.ParseError:
            continue
        root = tree.getroot()

        # namespace 추출
        namespace = root.get("namespace", "")
        if not namespace:
            continue

        rel_path = str(xml_file.relative_to(source_dir)) if xml_file.is_relative_to(source_dir) else str(xml_file)

        # <sql id="..."> 조각(fragment) 인덱스 구축 (include refid 병합용)
        sql_fragments = {}
        for sql_elem in root.iter("sql"):
            frag_id = sql_elem.get("id", "")
            if frag_id:
                sql_fragments[frag_id] = _collect_element_text(sql_elem)

        # SQL statement 태그 파싱
        for elem in root:
            tag = elem.tag.lower()
            if tag not in sql_tags:
                continue

            sql_id = elem.get("id", "")
            if not sql_id:
                continue

            # 순수 텍스트 수집 (XML 주석 <!-- --> 은 ElementTree가 자동 무시)
            sql_text = _collect_element_text(elem)

            # <include refid="..."> 병합
            for include_elem in elem.iter("include"):
                refid = include_elem.get("refid", "")
                if refid in sql_fragments:
                    sql_text += " " + sql_fragments[refid]

            # SQL 주석 제거 (/* ... */ 내의 ${}/$param$ 오탐 방지)
            sql_text = re.sub(r'/\*.*?\*/', '', sql_text, flags=re.DOTALL)
            # SQL 한 줄 주석 제거 (-- ... 이후)
            sql_text = re.sub(r'--[^\n]*', '', sql_text)

            # ${} / #{} 분석
            dollar_matches = re.findall(r'\$\{([^}]+)\}', sql_text)
            ibatis_dollar_matches = re.findall(r'\$(\w+)\$', sql_text)

            has_dollar = len(dollar_matches) > 0
            has_ibatis_dollar = len(ibatis_dollar_matches) > 0
            has_hash = bool(re.search(r'#\{[^}]+\}', sql_text))
            has_ibatis_hash = bool(re.search(r'#\w+#', sql_text))

            # 동적 바인딩 예외 판정: 변수명이 order/sort/table 계열이면 별도 태그
            all_dollar_vars = dollar_matches + ibatis_dollar_matches
            has_dynamic = any(
                v.lower() in dynamic_binding_vars or
                any(kw in v.lower() for kw in ("order", "sort", "table", "column", "limit"))
                for v in all_dollar_vars
            )

            entry = {
                "file": rel_path,
                "sql_type": tag,
                "has_dollar": has_dollar,
                "has_hash": has_hash,
                "has_ibatis_dollar": has_ibatis_dollar,
                "has_ibatis_hash": has_ibatis_hash,
                "dollar_vars": all_dollar_vars,
                "has_dynamic_binding": has_dynamic,
            }

            # Register with namespace.id (primary key)
            full_id = f"{namespace}.{sql_id}"
            index[full_id] = entry

            # Also register with className.sqlId for interface method matching
            # namespace: com.foo.bar.MyMapper → className: MyMapper
            class_name = namespace.rsplit(".", 1)[-1] if "." in namespace else namespace
            class_key = f"{class_name}.{sql_id}"
            if class_key not in index:
                index[class_key] = entry

            # Also register with just sql_id for loose matching
            if sql_id not in index:
                index[sql_id] = entry

    return index


def _is_jpa_repository(content: str) -> bool:
    """JPA Repository 인터페이스인지 확인 (Java extends / Kotlin : 구문 모두 지원)"""
    return bool(re.search(
        r'(?:extends|:)\s*(?:JpaRepository|CrudRepository|PagingAndSortingRepository|'
        r'JpaSpecificationExecutor|MongoRepository|'
        r'ReactiveCrudRepository|ReactiveSortingRepository)\s*[<,]',
        content
    ))


def _is_jpa_safe_method(method_name: str) -> bool:
    """JPA 내장/규칙 메서드인지 확인 (PreparedStatement 자동 바인딩으로 안전)"""
    if method_name in JPA_SAFE_METHODS:
        return True
    for prefix in JPA_CONVENTION_PREFIXES:
        if method_name.startswith(prefix):
            return True
    return False


def _analyze_jpa_query(content: str, method_name: str) -> list:
    """JPA @Query 어노테이션 분석"""
    ops = []
    # @Query("...") 또는 @Query(value="...") 바로 뒤에 메서드 선언
    pattern = (
        rf'@Query\s*\(\s*(?:value\s*=\s*)?'
        rf'("(?:[^"\\]|\\.)*")\s*'
        rf'(?:,\s*nativeQuery\s*=\s*(?:true|false)\s*)?'
        rf'\)\s*'
        rf'(?:@\w+(?:\([^)]*\))?\s*)*'
        rf'(?:fun|public|protected|private|\w+[\w.<>,\[\] ]*)\s+'
        rf'{re.escape(method_name)}\s*\('
    )
    match = re.search(pattern, content, re.DOTALL)
    if not match:
        return ops

    query_text = match.group(1)
    has_named_param = bool(re.search(r':\w+', query_text))
    has_positional = bool(re.search(r'\?\d*', query_text))
    has_concat = bool(re.search(r'"\s*\+\s*\w+', query_text))

    if has_concat:
        ops.append(DbOperation(
            method=method_name,
            access_type="raw_concat",
            detail="취약: @Query 어노테이션에서 문자열 결합 사용",
            is_vulnerable=True,
        ))
    elif has_named_param or has_positional:
        ops.append(DbOperation(
            method=method_name,
            access_type="jpa_builtin",
            detail=f"양호: @Query에서 {'named parameter' if has_named_param else 'positional'} 바인딩 사용",
            is_vulnerable=False,
        ))
    else:
        ops.append(DbOperation(
            method=method_name,
            access_type="jpa_builtin",
            detail="양호: @Query 어노테이션 - 정적 JPQL (바인딩 불필요)",
            is_vulnerable=False,
        ))
    return ops


def _resolve_impl_class(class_name: str, class_index: dict) -> Optional[Path]:
    """Interface → 구현체 클래스 파일 탐색

    탐색 순서:
    1. {ClassName}Impl (Spring 관례)
    2. I{Name} → {Name} (I-prefix 관례)
    3. class_index 전체에서 implements 검색
    """
    # 1. {ClassName}Impl
    for suffix in ('Impl', 'Implementation'):
        impl_name = class_name + suffix
        if impl_name in class_index:
            return class_index[impl_name]

    # 2. IFooService → FooService (I-prefix 관례)
    if class_name.startswith("I") and len(class_name) > 1 and class_name[1].isupper():
        bare_name = class_name[1:]
        if bare_name in class_index:
            return class_index[bare_name]

    # 3. implements 검색 (비용이 높으므로 최후 수단)
    for cls_name, file_path in class_index.items():
        if cls_name == class_name:
            continue
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
            if re.search(rf'\bimplements\s+[^{{]*\b{re.escape(class_name)}\b', content):
                return file_path
        except (IOError, UnicodeDecodeError):
            continue

    return None


def _trace_service_chain(svc_class: str, svc_method: str,
                          source_dir: Path, class_index: dict,
                          mybatis_index: dict,
                          depth: int = 1, max_depth: int = 3,
                          visited: set = None) -> dict:
    """Service→Service 위임 재귀 추적 (depth-limited)

    Service A → Service B → DB 패턴을 재귀적으로 추적하여
    최종 DB 접근 패턴을 찾아냄. 무한루프 방지를 위해 depth 제한 적용.
    """
    result = {"repository_calls": [], "db_operations": []}

    if depth > max_depth:
        return result
    if visited is None:
        visited = set()
    visit_key = f"{svc_class}.{svc_method}"
    if visit_key in visited:
        return result
    visited.add(visit_key)

    svc_file = class_index.get(svc_class)
    if not svc_file:
        return result

    svc_content = read_file_safe(svc_file)
    if not svc_content:
        return result

    # Interface → 구현체 탐색
    if re.search(r'\binterface\s+' + re.escape(svc_class) + r'\b', svc_content):
        impl_file = _resolve_impl_class(svc_class, class_index)
        if impl_file:
            svc_content = read_file_safe(impl_file)
            svc_file = impl_file
        else:
            return result

    svc_deps = extract_constructor_deps(svc_content)

    # Repository/Mapper/DAO 필드
    repo_fields = [(name, cls) for name, cls in svc_deps
                   if any(cls.endswith(s) for s in
                          ('Repository', 'Mapper', 'Dao', 'DAO'))]
    # DB 클라이언트 필드
    db_client_fields = [(name, cls) for name, cls in svc_deps
                        if any(kw in cls for kw in
                               ('Template', 'SqlMapClient', 'DataSource',
                                'JdbcOperations', 'SqlSession'))]

    svc_method_body = extract_method_body(svc_content, svc_method)
    if not svc_method_body:
        # 메서드 본문 추출 실패 시 fallback: JPA repository 분석
        if repo_fields:
            for _, repo_cls in repo_fields:
                repo_file = class_index.get(repo_cls)
                if repo_file:
                    repo_content = read_file_safe(repo_file)
                    if repo_content and _is_jpa_repository(repo_content):
                        result["repository_calls"].append(f"{repo_cls} [JPA Repository]")
                        result["db_operations"].append(DbOperation(
                            method=svc_method,
                            access_type="jpa_builtin",
                            detail=f"양호: {repo_cls}는 JPA Repository - 내장 메서드는 PreparedStatement 자동 바인딩",
                            is_vulnerable=False,
                        ))
                        return result
        return result

    # Repository 호출 추적
    repo_field_names = [name for name, _ in repo_fields]
    repo_calls = extract_method_calls(svc_method_body, repo_field_names)

    for repo_field, repo_method in repo_calls:
        repo_class = None
        for fname, cls in repo_fields:
            if fname == repo_field:
                repo_class = cls
                break
        if not repo_class:
            continue

        result["repository_calls"].append(f"{repo_class}.{repo_method}()")
        repo_file = class_index.get(repo_class)
        if not repo_file:
            continue
        repo_content = read_file_safe(repo_file)
        if not repo_content:
            continue
        db_ops = analyze_repository_method(repo_content, repo_method,
                                            repo_file, mybatis_index)
        result["db_operations"].extend(db_ops)

    # DB 클라이언트 직접 사용
    if db_client_fields and mybatis_index and not result["db_operations"]:
        db_client_names = [name for name, _ in db_client_fields]
        db_calls = extract_method_calls(svc_method_body, db_client_names)
        if db_calls:
            dao_ops = analyze_dao_method(svc_content, svc_method,
                                         mybatis_index, svc_file)
            if dao_ops:
                result["db_operations"].extend(dao_ops)

    # Fallback: repo_fields는 있으나 호출 추출 실패 → JPA repository 확인
    if not result["db_operations"] and repo_fields and not repo_calls:
        for _, repo_cls in repo_fields:
            repo_file = class_index.get(repo_cls)
            if repo_file:
                repo_content = read_file_safe(repo_file)
                if repo_content and _is_jpa_repository(repo_content):
                    result["repository_calls"].append(f"{repo_cls} [JPA Repository - fallback]")
                    result["db_operations"].append(DbOperation(
                        method=svc_method,
                        access_type="jpa_builtin",
                        detail=f"양호: {repo_cls}는 JPA Repository (메서드 호출 추출 실패하였으나 JPA 내장 메서드는 안전)",
                        is_vulnerable=False,
                    ))
                    return result

    # 아직 DB ops 없으면 → Service→Service 위임 재귀 추적
    if not result["db_operations"]:
        other_svc_fields = [(name, cls) for name, cls in svc_deps
                            if any(cls.endswith(s)
                                   for s in _TRACEABLE_COMPONENT_SUFFIXES)]
        del_calls = extract_method_calls(svc_method_body,
                                          [n for n, _ in other_svc_fields])
        for del_field, del_method in del_calls[:5]:  # 상위 5개만
            del_class = None
            for fname, cls in other_svc_fields:
                if fname == del_field:
                    del_class = cls
                    break
            if not del_class:
                continue

            sub = _trace_service_chain(del_class, del_method,
                                        source_dir, class_index, mybatis_index,
                                        depth + 1, max_depth, visited)
            if sub.get("db_operations"):
                result["repository_calls"].extend(sub["repository_calls"])
                result["db_operations"].extend(sub["db_operations"])
                break

    return result


# ============================================================
#  Phase 14: Service 내부 메서드 위임 재귀 추적
# ============================================================

# 내부 위임 추적 시 무시할 제어흐름/유틸리티 메서드
_SKIP_INTERNAL_METHODS = frozenset({
    'if', 'for', 'while', 'switch', 'catch',
    'return', 'throw', 'new', 'super', 'this',
    'log', 'debug', 'info', 'warn', 'error', 'trace',
    'println', 'print', 'format', 'valueOf', 'toString',
    'equals', 'hashCode', 'get', 'set', 'put', 'add',
    'remove', 'contains', 'isEmpty', 'size', 'stream',
    'map', 'filter', 'collect', 'forEach', 'of',
    'builder', 'build', 'toBuilder',
    # Kotlin 표준 함수
    'let', 'run', 'apply', 'also', 'with',
    'checkNotNull', 'require', 'requireNotNull',
    'check', 'takeIf', 'takeUnless',
})


def _trace_internal_methods(svc_content: str, method_name: str,
                            repo_fields: list, repo_field_names: list,
                            class_index: dict, mybatis_index: dict,
                            depth: int = 1, max_depth: int = 3,
                            visited: set = None) -> list:
    """Service 내부 private 메서드 위임 재귀 추적 (depth-limited).

    publicMethod() → helper1() → helper2() → repo.query() 패턴 추적.
    순환 참조 방지를 위해 visited set 사용.

    Returns:
        list of (repo_entries: list[str], db_ops: list[DbOperation]) tuples.
        빈 리스트이면 DB 접근을 찾지 못한 것.
    """
    if depth > max_depth:
        return []
    if visited is None:
        visited = set()
    if method_name in visited:
        return []
    visited.add(method_name)

    method_body = extract_method_body(svc_content, method_name)
    if not method_body:
        return []

    # 1. 이 메서드에서 직접 repo 호출 확인
    repo_calls = extract_method_calls(method_body, repo_field_names)
    db_operations = []
    repo_results = []

    for repo_field, repo_method in repo_calls:
        repo_class = None
        for fname, cls in repo_fields:
            if fname == repo_field:
                repo_class = cls
                break
        if not repo_class:
            continue
        repo_results.append(f"{repo_class}.{repo_method}() [via {method_name}()]")
        repo_file = class_index.get(repo_class)
        if repo_file:
            repo_content = read_file_safe(repo_file)
            if repo_content:
                db_ops = analyze_repository_method(
                    repo_content, repo_method, repo_file, mybatis_index)
                db_operations.extend(db_ops)

    if db_operations:
        return [(repo_results, db_operations)]

    # 2. repo 호출 없으면 → 내부 메서드로 재귀
    internal_calls = re.findall(r'(?:this\s*\.\s*)?(\w+)\s*\(', method_body)

    for ic in internal_calls:
        if ic in _SKIP_INTERNAL_METHODS or ic in visited:
            continue
        sub = _trace_internal_methods(
            svc_content, ic, repo_fields, repo_field_names,
            class_index, mybatis_index,
            depth + 1, max_depth, visited)
        if sub:
            return sub

    return []


def trace_endpoint(endpoint: dict, source_dir: Path,
                   class_index: dict, mybatis_index: dict = None) -> dict:
    """단일 endpoint에 대해 Controller → Service → Repository 추적"""
    result = {
        "service_calls": [],
        "repository_calls": [],
        "db_operations": [],
    }

    # 1. Controller 파일에서 handler 메서드 파싱
    handler = endpoint.get("handler", "")
    file_field = endpoint.get("file", "")

    # handler: "AdController.findAll()"
    handler_match = re.match(r'(\w+)\.(\w+)\s*\(', handler)
    if not handler_match:
        return result

    controller_class = handler_match.group(1)
    handler_method = handler_match.group(2)

    # Controller 파일 찾기
    ctrl_file = None
    if file_field:
        # file 필드에서 경로 추출 (상대경로:라인 형식)
        file_path_str = file_field.split(":")[0]
        candidate = source_dir / file_path_str
        if not candidate.exists():
            # source_dir 상위에서 시도
            candidate = source_dir.parent / file_path_str
        if not candidate.exists():
            # 전체 경로 검색
            for p in source_dir.rglob(Path(file_path_str).name):
                candidate = p
                break
        if candidate.exists():
            ctrl_file = candidate

    if not ctrl_file:
        ctrl_file = class_index.get(controller_class)
    if not ctrl_file:
        return result

    ctrl_content = read_file_safe(ctrl_file)
    if not ctrl_content:
        return result

    # 2. Controller의 의존성 추출
    ctrl_deps = extract_constructor_deps(ctrl_content)

    # [Phase 15] 부모 클래스 의존성 병합
    parent_match = re.search(
        r'class\s+\w+\s+(?:extends\s+|:\s*)(\w+)', ctrl_content)
    if parent_match:
        parent_class = parent_match.group(1)
        parent_file = class_index.get(parent_class)
        if parent_file:
            parent_content = read_file_safe(parent_file)
            if parent_content:
                parent_deps = extract_constructor_deps(parent_content)
                existing_names = {n for n, _ in ctrl_deps}
                for name, cls in parent_deps:
                    if name not in existing_names:
                        ctrl_deps.append((name, cls))

    service_fields = [(name, cls) for name, cls in ctrl_deps
                      if any(cls.endswith(s) for s in _TRACEABLE_COMPONENT_SUFFIXES)]

    # 3. Handler 메서드 본문에서 service 호출 추출
    method_body = extract_method_body(ctrl_content, handler_method)
    if not method_body:
        return result

    # [Phase 15] handler 메서드 본문을 결과에 포함 (stub 판정용)
    result["handler_method_body"] = method_body

    svc_field_names = [name for name, _ in service_fields]
    svc_calls = extract_method_calls(method_body, svc_field_names)

    for field_name, svc_method in svc_calls:
        # field → class 매핑
        svc_class = None
        for fname, cls in service_fields:
            if fname == field_name:
                svc_class = cls
                break
        if not svc_class:
            continue

        result["service_calls"].append(f"{svc_class}.{svc_method}()")

        # 4. Service 파일 찾기 → Repository 호출 추적
        svc_file = class_index.get(svc_class)
        if not svc_file:
            # [Phase 13] 외부 모듈 서비스 추정 판정
            result["service_calls"][-1] = f"{svc_class}.{svc_method}() [external]"
            result["db_operations"].append(DbOperation(
                method=svc_method,
                access_type="external_module",
                detail=f"양호(추정): {svc_class}는 외부 모듈 - "
                       f"cross-module injection 위험 낮음",
                is_vulnerable=False,
            ))
            continue

        svc_content = read_file_safe(svc_file)
        if not svc_content:
            continue

        # [Phase 3] Interface → 구현체 탐색
        if re.search(r'\binterface\s+' + re.escape(svc_class) + r'\b', svc_content):
            impl_file = _resolve_impl_class(svc_class, class_index)
            if impl_file:
                svc_content = read_file_safe(impl_file)
                svc_file = impl_file
            else:
                continue

        svc_deps = extract_constructor_deps(svc_content)

        # Repository/Mapper/Dao 필드 (비DB 클래스 제외)
        _non_db_classes = frozenset({
            'ObjectMapper', 'ModelMapper', 'RestTemplate',
            'WebClient', 'HttpClient', 'RedisTemplate',
            'StringRedisTemplate', 'ReactiveRedisTemplate',
            'KafkaTemplate', 'RabbitTemplate', 'JmsTemplate',
        })
        repo_fields = [(name, cls) for name, cls in svc_deps
                       if any(cls.endswith(s) for s in
                              ('Repository', 'Mapper', 'Dao', 'DAO'))
                       and cls not in _non_db_classes]

        # DB 클라이언트 직접 주입 필드 (SqlMapClientTemplate, JdbcTemplate 등)
        db_client_fields = [(name, cls) for name, cls in svc_deps
                            if any(kw in cls for kw in
                                   ('Template', 'SqlMapClient', 'DataSource',
                                    'JdbcOperations', 'SqlSession'))
                            and cls not in _non_db_classes]

        # [Phase 11] 비DB Service 필터: DB 의존성이 전혀 없는 서비스 → 스킵
        if not repo_fields and not db_client_fields:
            # DriverManager.getConnection() 직접 사용 안전장치
            if not re.search(r'DriverManager\s*\.\s*getConnection', svc_content):
                result["service_calls"][-1] = f"{svc_class}.{svc_method}() [non-DB]"
                continue

        svc_method_body = extract_method_body(svc_content, svc_method)
        if not svc_method_body:
            # [Phase 2 Fallback] 메서드 본문 추출 실패 → JPA repository 확인
            if repo_fields:
                for _, repo_cls in repo_fields:
                    repo_file = class_index.get(repo_cls)
                    if repo_file:
                        repo_content = read_file_safe(repo_file)
                        if repo_content and _is_jpa_repository(repo_content):
                            result["repository_calls"].append(
                                f"{repo_cls} [JPA Repository]")
                            result["db_operations"].append(DbOperation(
                                method=svc_method,
                                access_type="jpa_builtin",
                                detail=f"양호: {repo_cls}는 JPA Repository - "
                                       f"내장 메서드는 PreparedStatement 자동 바인딩",
                                is_vulnerable=False,
                            ))
                            break
            continue

        # Repository 호출 추적
        repo_field_names = [name for name, _ in repo_fields]
        repo_calls = extract_method_calls(svc_method_body, repo_field_names)

        for repo_field, repo_method in repo_calls:
            # field → class 매핑
            repo_class = None
            for fname, cls in repo_fields:
                if fname == repo_field:
                    repo_class = cls
                    break
            if not repo_class:
                continue

            result["repository_calls"].append(f"{repo_class}.{repo_method}()")

            # 5. Repository 메서드의 DB 접근 방식 분석
            repo_file = class_index.get(repo_class)
            if not repo_file:
                continue

            repo_content = read_file_safe(repo_file)
            if not repo_content:
                continue

            db_ops = analyze_repository_method(repo_content, repo_method,
                                                repo_file, mybatis_index)
            result["db_operations"].extend(db_ops)

        # DB 클라이언트 직접 사용 추적 (Service에서 직접 sqlMapClientTemplate 호출)
        if db_client_fields and mybatis_index:
            db_client_names = [name for name, _ in db_client_fields]
            db_calls = extract_method_calls(svc_method_body, db_client_names)
            if db_calls:
                # Service 자체가 DAO 역할 → analyze_dao_method로 분석
                dao_ops = analyze_dao_method(svc_content, svc_method,
                                             mybatis_index, svc_file)
                if dao_ops:
                    result["repository_calls"].append(
                        f"{svc_class}.{svc_method}() [direct DB]")
                    result["db_operations"].extend(dao_ops)

        # [Phase 2 Fallback] repo_fields 있으나 호출 추출 실패 → JPA 확인
        if not result["db_operations"] and repo_fields and not repo_calls:
            for _, repo_cls in repo_fields:
                repo_file = class_index.get(repo_cls)
                if repo_file:
                    repo_content = read_file_safe(repo_file)
                    if repo_content and _is_jpa_repository(repo_content):
                        result["repository_calls"].append(
                            f"{repo_cls} [JPA Repository - fallback]")
                        result["db_operations"].append(DbOperation(
                            method=svc_method,
                            access_type="jpa_builtin",
                            detail=f"양호: {repo_cls}는 JPA Repository "
                                   f"(메서드 호출 추출 실패하였으나 JPA 내장 메서드는 안전)",
                            is_vulnerable=False,
                        ))
                        break

        # [Phase 7/14] Service 내부 메서드 위임 추적 (depth=3 재귀)
        if not result["db_operations"] and repo_fields:
            internal_result = _trace_internal_methods(
                svc_content, svc_method, repo_fields, repo_field_names,
                class_index, mybatis_index,
                depth=1, max_depth=3, visited=None)
            if internal_result:
                for repo_entries, db_ops in internal_result:
                    result["repository_calls"].extend(repo_entries)
                    result["db_operations"].extend(db_ops)

        # [Phase 4] Service→Service 위임 재귀 추적
        if not result["db_operations"]:
            other_svc_fields = [(name, cls) for name, cls in svc_deps
                                if any(cls.endswith(s)
                                       for s in _TRACEABLE_COMPONENT_SUFFIXES)]
            del_calls = extract_method_calls(
                svc_method_body, [n for n, _ in other_svc_fields])
            for del_field, del_method in del_calls[:5]:
                del_class = None
                for fname, cls in other_svc_fields:
                    if fname == del_field:
                        del_class = cls
                        break
                if not del_class:
                    continue

                sub = _trace_service_chain(
                    del_class, del_method,
                    source_dir, class_index, mybatis_index,
                    depth=1, max_depth=3)
                if sub.get("db_operations"):
                    result["service_calls"].append(
                        f"{del_class}.{del_method}() [위임]")
                    result["repository_calls"].extend(
                        sub["repository_calls"])
                    result["db_operations"].extend(
                        sub["db_operations"])
                    break

    return result


# ============================================================
#  4. Repository DB 접근 분석
# ============================================================

def analyze_dao_method(content: str, method_name: str,
                       mybatis_index: dict, file_path: Path = None) -> list:
    """DAO 클래스의 sqlMapClientTemplate/SqlSessionTemplate 호출 분석

    iBatis 2.0 DAO 패턴:
        sqlMapClientTemplate.queryForObject("namespace.sqlId", param)
        sqlMapClientTemplate.queryForList("namespace.sqlId", param)
        sqlMapClientTemplate.update("namespace.sqlId", param)
    MyBatis 3.0 DAO 패턴:
        sqlSession.selectOne("namespace.sqlId", param)
        sqlSession.selectList("namespace.sqlId", param)
    """
    ops = []
    method_body = extract_method_body(content, method_name)
    if not method_body:
        # DAO의 경우 메서드 본문이 없으면 interface일 수 있음 → 클래스 전체 탐색
        method_body = content

    # iBatis sqlMapClientTemplate 패턴
    ibatis_pattern = (
        r'(?:sqlMapClientTemplate|sqlMapClient|getSqlMapClientTemplate\(\))'
        r'\s*\.\s*'
        r'(?:queryForObject|queryForList|queryForMap|insert|update|delete)'
        r'\s*\(\s*["\']([^"\']+)["\']'
    )
    # MyBatis SqlSession 패턴
    mybatis_session_pattern = (
        r'(?:sqlSession(?:Template)?|getSqlSession\(\))'
        r'\s*\.\s*'
        r'(?:selectOne|selectList|selectMap|insert|update|delete)'
        r'\s*\(\s*["\']([^"\']+)["\']'
    )

    found_any = False
    for pattern in [ibatis_pattern, mybatis_session_pattern]:
        for m in re.finditer(pattern, method_body):
            found_any = True
            sql_id = m.group(1)

            # mybatis_index에서 조회
            entry = mybatis_index.get(sql_id)
            if not entry:
                # namespace 없이 ID만으로도 시도
                short_id = sql_id.split(".")[-1] if "." in sql_id else sql_id
                entry = mybatis_index.get(short_id)

            if entry:
                if entry.get("has_dollar") or entry.get("has_ibatis_dollar"):
                    is_unsafe = "ibatis" in pattern.lower() or entry.get("has_ibatis_dollar")
                    access_type = "ibatis_unsafe" if is_unsafe and not entry.get("has_dollar") else "mybatis_unsafe"
                    dollar_vars = entry.get("dollar_vars", [])
                    is_dynamic = entry.get("has_dynamic_binding", False)
                    var_info = f" (변수: {', '.join(dollar_vars)})" if dollar_vars else ""
                    dynamic_note = " [동적 바인딩 - Review Needed]" if is_dynamic else ""
                    ops.append(DbOperation(
                        method=method_name,
                        access_type=access_type,
                        detail=f"취약: XML mapper에서 ${{}}/{('$param$' if is_unsafe and not entry.get('has_dollar') else '')} 직접 삽입 ({sql_id} in {entry['file']}){var_info}{dynamic_note}",
                        is_vulnerable=True,
                    ))
                else:
                    is_ibatis = entry.get("has_ibatis_hash")
                    access_type = "ibatis_safe" if is_ibatis and not entry.get("has_hash") else "mybatis_safe"
                    ops.append(DbOperation(
                        method=method_name,
                        access_type=access_type,
                        detail=f"양호: XML mapper에서 #{{}} 바인딩 사용 ({sql_id} in {entry['file']})",
                        is_vulnerable=False,
                    ))
            else:
                # XML에서 찾지 못함 → 정보
                ops.append(DbOperation(
                    method=method_name,
                    access_type="mybatis_safe",
                    detail=f"XML mapper에서 SQL ID '{sql_id}' 참조 (XML 매핑 확인 필요)",
                    is_vulnerable=False,
                ))

    return ops if found_any else ops


def _analyze_mybatis_annotations(content: str, method_name: str,
                                  mybatis_index: dict = None) -> list:
    """MyBatis @Select/@Insert/@Update/@Delete 어노테이션 분석

    Mapper interface 메서드에 붙은 SQL 어노테이션을 분석하여 양호/취약 판정.
    """
    ops = []
    # 메서드 앞에 위치한 어노테이션 찾기
    # @Select("SELECT ... #{param} ...") 또는 @Select({"SELECT ...", "WHERE ..."})
    annotation_pattern = (
        rf'@(Select|Insert|Update|Delete)\s*\(\s*'
        rf'((?:"[^"]*"|\{{[^}}]*\}}))\s*\)'
        rf'\s*(?:fun|public|protected|private|\w+)\s+'
        rf'{re.escape(method_name)}\s*\('
    )
    match = re.search(annotation_pattern, content, re.DOTALL)
    if not match:
        return ops

    sql_text = match.group(2)

    has_dollar = bool(re.search(r'\$\{[^}]+\}', sql_text))
    has_concat = bool(re.search(r'"\s*\+\s*\w+\s*\+\s*"', sql_text))
    has_hash = bool(re.search(r'#\{[^}]+\}', sql_text))

    if has_dollar or has_concat:
        ops.append(DbOperation(
            method=method_name,
            access_type="mybatis_unsafe",
            detail=f"취약: @{match.group(1)} 어노테이션에서 {'${} 직접 삽입' if has_dollar else '문자열 결합'} 사용",
            is_vulnerable=True,
        ))
    elif has_hash:
        ops.append(DbOperation(
            method=method_name,
            access_type="mybatis_safe",
            detail=f"양호: @{match.group(1)} 어노테이션에서 #{{}} 바인딩 사용",
            is_vulnerable=False,
        ))
    else:
        # 어노테이션은 있으나 바인딩 패턴 불분명
        ops.append(DbOperation(
            method=method_name,
            access_type="mybatis_safe",
            detail=f"양호: @{match.group(1)} 어노테이션 - 정적 SQL (바인딩 불필요)",
            is_vulnerable=False,
        ))

    return ops


def _lookup_mybatis_xml(content: str, method_name: str,
                         mybatis_index: dict) -> list:
    """Interface 메서드에 대해 MyBatis XML mapper에서 SQL ID 조회"""
    ops = []

    # 클래스/인터페이스의 FQN 또는 간단 이름으로 namespace 추출
    # interface AppManagerMapper → namespace가 "...AppManagerMapper"일 가능성
    class_name = extract_class_name(content)
    if not class_name:
        return ops

    # package 추출 시도
    pkg_match = re.search(r'package\s+([\w.]+)', content)
    fqn = f"{pkg_match.group(1)}.{class_name}" if pkg_match else class_name

    # 1) FQN.methodName 으로 조회
    full_key = f"{fqn}.{method_name}"
    entry = mybatis_index.get(full_key)

    # 2) className.methodName 으로 조회
    if not entry:
        entry = mybatis_index.get(f"{class_name}.{method_name}")

    # 3) methodName 단독 조회
    if not entry:
        entry = mybatis_index.get(method_name)

    if not entry:
        return ops

    if entry.get("has_dollar") or entry.get("has_ibatis_dollar"):
        is_ibatis = entry.get("has_ibatis_dollar") and not entry.get("has_dollar")
        dollar_vars = entry.get("dollar_vars", [])
        is_dynamic = entry.get("has_dynamic_binding", False)
        var_info = f" (변수: {', '.join(dollar_vars)})" if dollar_vars else ""
        dynamic_note = " [동적 바인딩 - Review Needed]" if is_dynamic else ""
        ops.append(DbOperation(
            method=method_name,
            access_type="ibatis_unsafe" if is_ibatis else "mybatis_unsafe",
            detail=f"취약: XML mapper에서 ${{}}/{('$param$' if is_ibatis else '')} 직접 삽입 ({entry['file']}){var_info}{dynamic_note}",
            is_vulnerable=True,
        ))
    else:
        is_ibatis = entry.get("has_ibatis_hash") and not entry.get("has_hash")
        ops.append(DbOperation(
            method=method_name,
            access_type="ibatis_safe" if is_ibatis else "mybatis_safe",
            detail=f"양호: XML mapper에서 #{{}} 바인딩 사용 ({entry['file']})",
            is_vulnerable=False,
        ))

    return ops


def analyze_repository_method(content: str, method_name: str,
                               file_path: Path = None,
                               mybatis_index: dict = None) -> list:
    """Repository 메서드의 DB 접근 패턴을 분석하여 진단 유형 결정

    우선순위:
      1. 메서드 본문에서 직접 사용하는 DB 접근 패턴 확인
      2. 양호/취약 패턴이 공존 시 메서드의 주된 작업 기준으로 판정
      3. ORM(.using(entity)) > bind > criteria > raw_concat 순으로 판정
    """
    if mybatis_index is None:
        mybatis_index = {}

    ops = []

    # --- 0단계: DAO/sqlMapClientTemplate 패턴 우선 확인 ---
    if mybatis_index and re.search(
        r'(?:sqlMapClientTemplate|sqlMapClient|getSqlMapClientTemplate|'
        r'sqlSession(?:Template)?|getSqlSession)',
        content
    ):
        dao_ops = analyze_dao_method(content, method_name, mybatis_index, file_path)
        if dao_ops:
            return dao_ops

    # --- 0-1단계: MyBatis Mapper Interface (어노테이션 기반) ---
    # @Select/@Insert/@Update/@Delete 어노테이션이 있는 interface 메서드
    annotation_ops = _analyze_mybatis_annotations(content, method_name, mybatis_index)
    if annotation_ops:
        return annotation_ops

    # --- 0-2단계: MyBatis Mapper Interface (XML 매핑) ---
    # 메서드 본문이 없는 interface → mybatis_index에서 매핑 확인
    method_body = extract_method_body(content, method_name)
    if not method_body:
        # interface일 가능성 → MyBatis XML 매핑 시도
        if mybatis_index:
            xml_ops = _lookup_mybatis_xml(content, method_name, mybatis_index)
            if xml_ops:
                return xml_ops

        # --- [Phase 10] Mapper interface fallback: XML 미발견 시 MyBatis 안전 추정 ---
        class_name = extract_class_name(content)
        if class_name and class_name.endswith(('Mapper', 'Dao', 'DAO')) \
                and not _is_jpa_repository(content):
            mybatis_crud_prefixes = ('select', 'insert', 'update', 'delete',
                                     'get', 'find', 'count', 'query', 'list',
                                     'set', 'del', 'remove', 'save', 'add',
                                     'merge', 'upsert', 'batch', 'bulk')
            if any(method_name.lower().startswith(p) for p in mybatis_crud_prefixes):
                return [DbOperation(
                    method=method_name,
                    access_type="mybatis_safe",
                    detail=f"양호(추정): {class_name} MyBatis Mapper - "
                           f"#{{}} 기본 바인딩 추정 (XML 미발견)",
                    is_vulnerable=False,
                )]

        # --- 0-3단계: JPA Repository 내장 메서드 확인 ---
        if _is_jpa_repository(content):
            if _is_jpa_safe_method(method_name):
                return [DbOperation(
                    method=method_name,
                    access_type="jpa_builtin",
                    detail=f"양호: JPA 내장 메서드 ({method_name}) - PreparedStatement 자동 바인딩",
                    is_vulnerable=False,
                )]
            # @Query 어노테이션 확인
            query_ops = _analyze_jpa_query(content, method_name)
            if query_ops:
                return query_ops
            # JPA 규칙 기반 메서드 (findBy* 등) 중 미매칭 → 안전으로 추정
            return [DbOperation(
                method=method_name,
                access_type="jpa_builtin",
                detail=f"양호: JPA Repository 인터페이스 메서드 ({method_name})",
                is_vulnerable=False,
            )]

        return ops

    lines = method_body.splitlines()

    # 메서드 시작 라인 번호 계산
    all_lines = content.splitlines()
    method_start_line = 0
    method_name_esc = re.escape(method_name)
    for i, line in enumerate(all_lines):
        if re.search(rf'(?:fun\s+|[\w.<>\[\]]+\s+){method_name_esc}\s*\(', line):
            method_start_line = i + 1
            break

    def find_line(match_obj):
        idx = method_body[:match_obj.start()].count('\n')
        code = lines[idx].strip() if idx < len(lines) else ""
        return method_start_line + idx, code

    # --- 1단계: 모든 패턴 수집 ---

    found_orm = False
    found_bind = False
    found_criteria_safe = False
    found_criteria_tosql = False
    found_raw_concat = False
    found_execute = bool(re.search(r'\.execute\s*\(', method_body))

    # ORM: .using(entity) - insert/update/delete
    if re.search(r'\.(?:insert|update|delete)\s*\(\s*\)\s*\.'
                 r'(?:into|table|from)',
                 method_body, re.DOTALL):
        found_orm = True
    if re.search(r'\.using\s*\(', method_body):
        found_orm = True

    # .bind() 파라미터 바인딩
    if re.search(r'\.bind\s*\(\s*["\']', method_body):
        found_bind = True

    # Criteria DSL (.matching)
    if re.search(r'\.matching\s*\(', method_body):
        if re.search(r'Utils\.toSql', method_body):
            found_criteria_tosql = True
        else:
            found_criteria_safe = True

    # Utils.toSql() (execute 컨텍스트)
    if re.search(r'Utils\.toSql\s*\(', method_body):
        found_criteria_tosql = True

    # Raw SQL concat
    concat_patterns = [
        (r'(?:\.execute|\.sql)\s*\([^)]*\+', "Raw SQL 문자열 결합 (+)"),
        (r'buildString\s*\{', "buildString으로 SQL 동적 생성"),
        (r'String\.format\s*\([^)]*(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)',
         "String.format()으로 SQL 생성"),
        (r'\.format\s*\([^)]*(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)',
         ".format()으로 SQL 생성"),
    ]
    raw_concat_desc = ""
    for pat, desc in concat_patterns:
        if re.search(pat, method_body, re.IGNORECASE | re.DOTALL):
            found_raw_concat = True
            raw_concat_desc = desc
            break

    # buildString 은 SQL 컨텍스트인지 확인
    if found_raw_concat and "buildString" in raw_concat_desc:
        # buildString 주변에 SQL 키워드가 있는지 확인
        if not re.search(r'(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM|_SQL|\.execute|\.sql)',
                         method_body, re.IGNORECASE):
            found_raw_concat = False

    # --- 2단계: 우선순위 기반 판정 ---

    # 메서드명에서 작업 유형 추론
    is_create = any(kw in method_name.lower()
                    for kw in ('create', 'insert', 'register', 'save', 'add'))
    is_update = any(kw in method_name.lower()
                    for kw in ('update', 'modify', 'set', 'reset', 'change'))
    is_delete = any(kw in method_name.lower()
                    for kw in ('delete', 'remove'))
    is_write_op = is_create or is_update or is_delete

    # 쓰기 작업이면서 ORM 사용 → ORM이 주된 패턴
    if is_write_op and found_orm:
        ops.append(DbOperation(
            method=method_name,
            access_type="orm",
            detail="유형2: ORM 방식으로 객체 바인딩하여 DB 처리",
            is_vulnerable=False,
        ))
        return ops

    # 쓰기 작업이면서 bind 사용 → bind가 주된 패턴
    if is_write_op and found_bind:
        bind_m = re.search(r'\.bind\s*\(\s*["\']', method_body)
        line_no, code = find_line(bind_m)
        ops.append(DbOperation(
            method=method_name,
            access_type="bind",
            detail="유형1: 파라미터에 대해 : 바인딩",
            line=line_no,
            code_snippet=code,
            is_vulnerable=False,
        ))
        return ops

    # Utils.toSql() 취약 패턴 (쓰기 작업이 아닌 경우)
    if found_criteria_tosql:
        tosql_m = re.search(r'Utils\.toSql\s*\(', method_body)
        line_no, code = find_line(tosql_m)
        ops.append(DbOperation(
            method=method_name,
            access_type="criteria_tosql",
            detail="취약: Utils.toSql()이 CriteriaDefinition.toString()을 SQL에 직접 삽입",
            line=line_no,
            code_snippet=code,
            is_vulnerable=True,
        ))
        return ops

    # Raw SQL concat (쓰기 작업이 아닌 경우)
    if found_raw_concat and not is_write_op:
        for pat, desc in concat_patterns:
            m = re.search(pat, method_body, re.IGNORECASE | re.DOTALL)
            if m:
                line_no, code = find_line(m)
                ops.append(DbOperation(
                    method=method_name,
                    access_type="raw_concat",
                    detail=f"취약: {desc}",
                    line=line_no,
                    code_snippet=code,
                    is_vulnerable=True,
                ))
                return ops

    # Raw SQL concat + 쓰기 작업 → bind/orm이 없는 경우만 취약
    if found_raw_concat and is_write_op and not found_bind and not found_orm:
        for pat, desc in concat_patterns:
            m = re.search(pat, method_body, re.IGNORECASE | re.DOTALL)
            if m:
                line_no, code = find_line(m)
                ops.append(DbOperation(
                    method=method_name,
                    access_type="raw_concat",
                    detail=f"취약: {desc}",
                    line=line_no,
                    code_snippet=code,
                    is_vulnerable=True,
                ))
                return ops

    # --- 양호 패턴 ---

    if found_bind:
        bind_m = re.search(r'\.bind\s*\(\s*["\']', method_body)
        line_no, code = find_line(bind_m)
        ops.append(DbOperation(
            method=method_name,
            access_type="bind",
            detail="유형1: 파라미터에 대해 : 바인딩",
            line=line_no,
            code_snippet=code,
            is_vulnerable=False,
        ))
        return ops

    if found_orm:
        ops.append(DbOperation(
            method=method_name,
            access_type="orm",
            detail="유형2: ORM 방식으로 객체 바인딩하여 DB 처리",
            is_vulnerable=False,
        ))
        return ops

    if found_criteria_safe:
        ops.append(DbOperation(
            method=method_name,
            access_type="criteria",
            detail="유형3: Criteria 기반 쿼리 방식으로 DB 처리",
            is_vulnerable=False,
        ))
        return ops

    # R2dbcEntityTemplate
    if re.search(r'R2dbcEntityTemplate|\.select\s*\(\s*\w+::class', method_body):
        ops.append(DbOperation(
            method=method_name,
            access_type="orm",
            detail="유형2: R2dbcEntityTemplate 사용",
            is_vulnerable=False,
        ))
        return ops

    # .execute + :param
    if found_execute:
        if re.search(r':\w+', method_body) and \
           not re.search(r'\.toString\s*\(\s*\)', method_body):
            ops.append(DbOperation(
                method=method_name,
                access_type="bind",
                detail="유형1: SQL에 :param 바인딩 사용",
                is_vulnerable=False,
            ))
            return ops

    # DB 접근 없음
    if not re.search(r'\.(?:execute|sql|select|insert|update|delete|query)\s*\(',
                     method_body, re.IGNORECASE):
        ops.append(DbOperation(
            method=method_name,
            access_type="none",
            detail="DB 접근 없음",
            is_vulnerable=False,
        ))
        return ops

    # 판정 불가
    ops.append(DbOperation(
        method=method_name,
        access_type="unknown",
        detail="자동 판정 불가 - 수동 검토 필요",
        is_vulnerable=False,
    ))
    return ops


# ============================================================
#  5. Endpoint별 판정
# ============================================================

def has_db_input_params(params: list) -> bool:
    """endpoint 파라미터 중 DB 쿼리에 영향을 줄 수 있는 사용자 입력이 있는지"""
    if not params:
        return False
    # 사용자가 직접 제어 가능한 파라미터 유형
    skip_types = {"User", "ServerWebExchange", "ServerHttpRequest",
                  "ServerHttpResponse", "WebSession", "Authentication",
                  "Principal", "Model", "BindingResult", "Errors"}
    for p in params:
        p_type = p.get("type", "")
        data_type = p.get("data_type", "")
        if p_type in ("query", "path", "body") and data_type not in skip_types:
            return True
        if p_type == "pageable":
            return True  # Pageable의 sort 파라미터 가능
    return False


def has_search_like_params(params: list) -> bool:
    """검색/필터 관련 파라미터가 있는지 (toSql 영향 가능)"""
    search_names = {"search", "keyword", "query", "q", "field", "value",
                    "filter", "term", "name", "title", "text"}
    for p in params:
        p_name = p.get("name", "").lower()
        if p_name in search_names:
            return True
        if p.get("type") == "query" and p.get("data_type", "") == "String":
            return True
    return False


def is_non_db_endpoint(endpoint: dict) -> bool:
    """DB 접근이 필요 없는 엔드포인트인지 판별"""
    mapping = endpoint.get("api", "")
    handler = endpoint.get("handler", "")

    non_db_patterns = [
        r'/health', r'/actuator', r'/diagnosis',
        r'/callback', r'/login', r'/logout',
        r'/static/', r'\.jsp$', r'/ws/',
    ]
    for pat in non_db_patterns:
        if re.search(pat, mapping, re.IGNORECASE):
            return True
    return False


def judge_endpoint(trace_result: dict, endpoint: dict) -> dict:
    """endpoint에 대한 최종 양호/취약/정보 판정"""

    # [Phase 16] 제거(deprecated) 엔드포인트 → 양호
    handler = endpoint.get("handler", "")
    if handler.startswith("제거") or handler == "":
        return {
            "result": "양호",
            "diagnosis_type": "비활성 엔드포인트 [deprecated]",
            "diagnosis_detail": "제거/비활성 엔드포인트 - 코드 미존재 또는 사용 중지",
            "filter_type": "N/A",
            "filter_detail": "N/A",
            "needs_review": False,
        }

    db_ops = trace_result.get("db_operations", [])
    params = endpoint.get("parameters", [])

    has_user_params = has_db_input_params(params)
    has_search_params = has_search_like_params(params)

    # 비DB 엔드포인트 (healthcheck, login 등) → 양호
    if is_non_db_endpoint(endpoint):
        if not trace_result.get("service_calls"):
            return {
                "result": "양호",
                "diagnosis_type": "비DB 엔드포인트",
                "diagnosis_detail": "DB 접근이 필요 없는 엔드포인트 (healthcheck/login/callback 등)",
                "filter_type": "N/A",
                "filter_detail": "N/A",
                "needs_review": False,
            }

    if not db_ops:
        # [Phase 11] 모든 Service가 비DB → 양호
        svc_calls = trace_result.get("service_calls", [])
        if svc_calls and all("[non-DB]" in s for s in svc_calls):
            return {
                "result": "양호",
                "diagnosis_type": "비DB Service",
                "diagnosis_detail": "모든 Service가 DB 의존성 없음 (Repository/Mapper/Template 미보유)",
                "filter_type": "N/A",
                "filter_detail": "N/A",
                "needs_review": False,
            }

        # Repository 추적 실패
        if not trace_result.get("service_calls"):
            # [Phase 9] 비DB 패턴 확장 판정
            handler = endpoint.get("handler", "")
            handler_class = handler.split(".")[0] if "." in handler else ""

            # 세션 전용 Controller → 양호 (DB 미접근)
            session_controllers = {
                'InternalSessionController', 'SessionController',
                'RedisApiController',
            }
            if handler_class in session_controllers:
                return {
                    "result": "양호",
                    "diagnosis_type": "비DB 엔드포인트 (세션)",
                    "diagnosis_detail": "세션/캐시 전용 Controller - DB 직접 접근 없음",
                    "filter_type": "N/A",
                    "filter_detail": "N/A",
                    "needs_review": False,
                }

            # Service 호출도 없으면 비DB 가능성 높음
            if not has_user_params:
                return {
                    "result": "양호",
                    "diagnosis_type": "Service 미호출",
                    "diagnosis_detail": "Controller에서 Service/Repository 호출 없음 - DB 접근 없는 엔드포인트",
                    "filter_type": "N/A",
                    "filter_detail": "N/A",
                    "needs_review": False,
                }

            # [Phase 15] Handler 본문에 DB 관련 호출 패턴 없으면 → 양호 (stub)
            handler_body = trace_result.get("handler_method_body", "")
            if handler_body and not re.search(
                    r'(?:Service|Repository|Mapper|Dao|DAO|Template)\s*[\.\(]',
                    handler_body, re.IGNORECASE):
                return {
                    "result": "양호",
                    "diagnosis_type": "비DB 핸들러 [stub]",
                    "diagnosis_detail": "Handler 메서드 내 DB 관련 호출 패턴 없음",
                    "filter_type": "N/A",
                    "filter_detail": "N/A",
                    "needs_review": False,
                }

            return {
                "result": "정보",
                "diagnosis_type": "추적 불가",
                "diagnosis_detail": "Controller→Service→Repository 자동 추적 실패 - 수동 검토 필요",
                "filter_type": "N/A",
                "filter_detail": "N/A",
                "needs_review": True,
            }
        return {
            "result": "정보",
            "diagnosis_type": "DB 접근 미확인",
            "diagnosis_detail": "Service 호출 확인되나 Repository DB 접근 추적 불가",
            "filter_type": "N/A",
            "filter_detail": "N/A",
            "needs_review": True,
        }

    # 취약 패턴 존재 여부
    vulnerable_ops = [op for op in db_ops if op.is_vulnerable]
    safe_ops = [op for op in db_ops if not op.is_vulnerable and
                op.access_type != "none"]

    if vulnerable_ops:
        op = vulnerable_ops[0]

        # 취약 판정 세분화:
        # - Utils.toSql() + 검색 파라미터 → 취약
        # - Utils.toSql() + Pageable만 → 정보 (sort 파라미터로 제한적)
        # - Utils.toSql() + 파라미터 없음 → 정보
        # - Raw concat + 사용자 입력 → 취약
        # - Raw concat + 내부 파라미터만 → 정보
        if op.access_type == "criteria_tosql":
            if has_search_params:
                result_str = "취약"
                detail = op.detail
            elif has_user_params:
                result_str = "정보"
                detail = op.detail + " (사용자 입력값이 Criteria에 간접 전달될 수 있음)"
            else:
                result_str = "정보"
                detail = op.detail + " (사용자 입력 파라미터 없어 직접 입력 불가)"
        elif op.access_type == "raw_concat":
            if has_search_params:
                result_str = "취약"
                detail = op.detail
            elif has_user_params:
                result_str = "정보"
                detail = op.detail + " (사용자 파라미터가 SQL 결합에 도달하는지 수동 확인 필요)"
            else:
                result_str = "정보"
                detail = op.detail + " (사용자 입력 파라미터 없음)"
        elif op.access_type in ("mybatis_unsafe", "ibatis_unsafe"):
            # MyBatis/iBatis ${} 사용 → 동적 바인딩 예외 + 검색 파라미터 기준 판정
            is_dynamic_binding = "동적 바인딩" in op.detail
            if is_dynamic_binding:
                # ORDER BY ${col} 등 기능상 불가피한 동적 바인딩
                if has_search_params:
                    result_str = "정보"
                    detail = op.detail + " (동적 바인딩 + 사용자 입력 존재 - 수동 검증 필요)"
                elif has_user_params:
                    result_str = "정보"
                    detail = op.detail + " (동적 바인딩 - 사용자 입력 도달 여부 수동 확인 필요)"
                else:
                    result_str = "정보"
                    detail = op.detail + " (동적 바인딩 - 사용자 입력 파라미터 없음)"
            elif has_search_params:
                result_str = "취약"
                detail = op.detail
            elif has_user_params:
                result_str = "취약"
                detail = op.detail + " (사용자 입력이 ${} 치환에 도달 가능)"
            else:
                result_str = "정보"
                detail = op.detail + " (사용자 입력 파라미터 없음)"
        else:
            result_str = "취약" if has_user_params else "정보"
            detail = op.detail

        filter_type = "N/A"
        filter_detail = "N/A"
        if op.access_type == "criteria_tosql":
            filter_type = "r2dbc"
            filter_detail = "toSql()"
        elif op.access_type in ("mybatis_unsafe", "ibatis_unsafe"):
            filter_type = "mybatis"
            filter_detail = "${}"

        return {
            "result": result_str,
            "diagnosis_type": op.detail.split(":")[0].strip() if ":" in op.detail else op.access_type,
            "diagnosis_detail": detail,
            "filter_type": filter_type,
            "filter_detail": filter_detail,
            "needs_review": result_str == "정보" and has_user_params,
            "evidence": [{
                "file": str(op.code_snippet),
                "line": op.line,
                "detail": op.detail,
            }] if op.code_snippet else [],
        }

    if safe_ops:
        op = safe_ops[0]
        filter_type = "r2dbc"
        filter_detail = ":"
        if op.access_type == "orm":
            filter_detail = "orm"
        elif op.access_type == "criteria":
            filter_detail = "criteria"
        elif op.access_type == "bind":
            filter_detail = ":"
        elif op.access_type == "jpa_builtin":
            filter_type = "jpa"
            filter_detail = "built-in"
        elif op.access_type in ("mybatis_safe", "ibatis_safe"):
            filter_type = "mybatis"
            filter_detail = "#{}"
        elif op.access_type == "external_module":
            filter_type = "N/A"
            filter_detail = "external"

        return {
            "result": "양호",
            "diagnosis_type": op.detail,
            "diagnosis_detail": op.detail,
            "filter_type": filter_type,
            "filter_detail": filter_detail,
            "needs_review": op.access_type == "external_module",
        }

    # DB 접근 없음
    no_db_ops = [op for op in db_ops if op.access_type == "none"]
    if no_db_ops:
        if not has_user_params:
            return {
                "result": "양호",
                "diagnosis_type": "유형4: DB처리에 사용되는 파라미터없음",
                "diagnosis_detail": "유형4: DB처리에 사용되는 파라미터없음",
                "filter_type": "r2dbc",
                "filter_detail": "N/A",
                "needs_review": False,
            }
        return {
            "result": "양호",
            "diagnosis_type": "DB 접근 없음",
            "diagnosis_detail": "이 endpoint의 Repository 메서드에서 직접 DB 접근 없음",
            "filter_type": "N/A",
            "filter_detail": "N/A",
            "needs_review": False,
        }

    # unknown
    return {
        "result": "정보",
        "diagnosis_type": "자동 판정 불가",
        "diagnosis_detail": "자동 판정 불가 - 수동 검토 필요",
        "filter_type": "N/A",
        "filter_detail": "N/A",
        "needs_review": True,
    }


# ============================================================
#  6. OS Command / SSI 전역 스캔
# ============================================================

def scan_global_patterns(source_dir: Path, context_lines: int = 3) -> dict:
    """OS Command Injection / SSI Injection 전역 스캔"""
    extensions = {".kt", ".java", ".xml", ".js", ".ts", ".jsx", ".tsx",
                  ".php", ".py", ".cs", ".vb", ".groovy",
                  ".html", ".shtml", ".stm", ".shtm", ".jsp", ".vue",
                  ".ejs", ".njk", ".hbs"}

    exclude_dirs = {"node_modules", ".idea", "target", "build", ".git", "dist"}

    all_files = []
    for ext in extensions:
        for f in source_dir.rglob(f"*{ext}"):
            if not any(ex in f.parts for ex in exclude_dirs):
                all_files.append(f)

    # OS Command Injection
    cmd_findings = []
    for f in all_files:
        cmd_findings.extend(scan_file(f, OS_CMD_PATTERNS,
                                       OS_CMD_SAFE_PATTERNS, context_lines))

    # SSI Injection
    ssi_findings = []
    for f in all_files:
        ssi_findings.extend(scan_file(f, SSI_PATTERNS, [], context_lines))

    # 상대 경로 변환
    for finding in cmd_findings + ssi_findings:
        try:
            finding.file = str(Path(finding.file).relative_to(source_dir))
        except ValueError:
            pass

    # 결정론적 정렬 (rglob filesystem order 비결정성 해소)
    cmd_findings.sort(key=lambda f: (f.file, f.line))
    ssi_findings.sort(key=lambda f: (f.file, f.line))

    return {
        "os_command_injection": {
            "total": len(cmd_findings),
            "findings": [asdict(f) for f in cmd_findings],
        },
        "ssi_injection": {
            "total": len(ssi_findings),
            "findings": [asdict(f) for f in ssi_findings],
        },
    }


# ============================================================
#  7. 메인 로직
# ============================================================

def load_api_inventory(inventory_path: Path, modules: list = None) -> list:
    """API 인벤토리 로드 (scan_api.py 출력 또는 task_21_result.json)"""
    with open(inventory_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # scan_api.py 출력 형식
    if "endpoints" in data:
        endpoints = data["endpoints"]
    # task_21_result.json 형식
    elif "findings" in data:
        endpoints = data["findings"]
    else:
        print(f"Error: 지원하지 않는 인벤토리 형식입니다: {inventory_path}")
        sys.exit(1)

    # 모듈 필터
    if modules:
        endpoints = [ep for ep in endpoints
                     if ep.get("module", "") in modules]

    return endpoints


def format_params(params: list) -> str:
    """파라미터 목록을 문자열로 포맷"""
    if not params:
        return "N/A"
    parts = []
    for p in params:
        name = p.get("name", "?")
        data_type = p.get("data_type", p.get("type", ""))
        if data_type:
            parts.append(f"{name}: {data_type}")
        else:
            parts.append(name)
    return ", ".join(parts)


def run_diagnosis(source_dir: Path, inventory_path: Path,
                  modules: list = None,
                  context_lines: int = 3) -> dict:
    """전체 진단 실행"""

    # 1. API 인벤토리 로드
    endpoints = load_api_inventory(inventory_path, modules)
    print(f"API 인벤토리 로드: {len(endpoints)}개 endpoint")

    # 2. 클래스 인덱스 구축
    print("클래스 인덱스 구축 중...")
    class_index = build_class_index(source_dir)
    print(f"  → {len(class_index)}개 클래스 인덱싱 완료")

    # 2-1. MyBatis/iBatis XML mapper 인덱스 구축
    print("MyBatis/iBatis XML mapper 인덱스 구축 중...")
    mybatis_index = build_mybatis_index(source_dir)
    print(f"  → {len(mybatis_index)}개 SQL 매핑 인덱싱 완료")

    # 3. Endpoint별 진단
    print("Endpoint별 진단 수행 중...")
    diagnoses = []
    counter = 0

    for ep in endpoints:
        counter += 1
        no = f"1-{counter}"

        # 호출 흐름 추적
        trace = trace_endpoint(ep, source_dir, class_index, mybatis_index)

        # 판정
        judgment = judge_endpoint(trace, ep)

        diag = EndpointDiagnosis(
            no=no,
            http_method=ep.get("method", ""),
            request_mapping=ep.get("api", ""),
            process_file=ep.get("file", ""),
            handler=ep.get("handler", ""),
            method_name=ep.get("handler", "").split(".")[-1].rstrip("()") if ep.get("handler") else "",
            parameters=format_params(ep.get("parameters", [])),
            service_calls=trace.get("service_calls", []),
            repository_calls=trace.get("repository_calls", []),
            db_operations=[asdict(op) for op in trace.get("db_operations", [])],
            result=judgment["result"],
            filter_type=judgment.get("filter_type", "N/A"),
            filter_detail=judgment.get("filter_detail", "N/A"),
            diagnosis_type=judgment.get("diagnosis_type", ""),
            diagnosis_detail=judgment.get("diagnosis_detail", ""),
            needs_review=judgment.get("needs_review", False),
            evidence=judgment.get("evidence", []),
        )
        diagnoses.append(diag)

    # 통계
    sqli_stats = {"양호": 0, "취약": 0, "정보": 0, "N/A": 0}
    for d in diagnoses:
        sqli_stats[d.result] = sqli_stats.get(d.result, 0) + 1

    print(f"\nSQLi 진단 완료: {len(diagnoses)}개 endpoint")
    for k, v in sqli_stats.items():
        if v > 0:
            print(f"  {k}: {v}건")

    review_count = sum(1 for d in diagnoses if d.needs_review)
    if review_count > 0:
        print(f"  수동 검토 필요: {review_count}건")

    # 4. OS Command / SSI 전역 스캔
    print("\nOS Command / SSI Injection 전역 스캔 중...")
    global_findings = scan_global_patterns(source_dir, context_lines)
    print(f"  OS Command Injection: {global_findings['os_command_injection']['total']}건")
    print(f"  SSI Injection: {global_findings['ssi_injection']['total']}건")

    return {
        "task_id": "2-2",
        "status": "completed",
        "scan_metadata": {
            "source_dir": str(source_dir),
            "api_inventory": str(inventory_path),
            "modules_filtered": modules or [],
            "total_endpoints": len(endpoints),
            "total_classes_indexed": len(class_index),
            "total_mybatis_mappings": len(mybatis_index),
            "scanned_at": datetime.now().isoformat(),
            "script_version": "3.4.0",
        },
        "endpoint_diagnoses": [asdict(d) for d in diagnoses],
        "global_findings": global_findings,
        "summary": {
            "total_endpoints": len(diagnoses),
            "sqli": sqli_stats,
            "os_command": {
                "total": global_findings["os_command_injection"]["total"]
            },
            "ssi": {
                "total": global_findings["ssi_injection"]["total"]
            },
            "needs_review": review_count,
        },
        "executed_at": datetime.now().isoformat(),
    }


def main():
    parser = argparse.ArgumentParser(
        description="인젝션 고도화 진단 - endpoint별 양호/취약 판정"
    )
    parser.add_argument(
        "source_dir",
        help="스캔 대상 소스코드 디렉토리",
    )
    parser.add_argument(
        "--api-inventory", "-a",
        required=True,
        help="API 인벤토리 JSON 파일 (scan_api.py 출력 또는 task_21_result.json)",
    )
    parser.add_argument(
        "--modules", "-m",
        nargs="*",
        help="진단 대상 모듈 필터 (예: pcona-console)",
    )
    parser.add_argument(
        "--output", "-o",
        help="결과 출력 JSON 파일 경로",
        default=None,
    )
    parser.add_argument(
        "--context-lines", "-c",
        help="매칭 줄 전후 컨텍스트 줄 수 (기본: 3)",
        type=int,
        default=3,
    )
    args = parser.parse_args()

    source_dir = Path(args.source_dir)
    if not source_dir.exists():
        print(f"Error: 디렉토리를 찾을 수 없습니다: {source_dir}")
        sys.exit(1)

    inventory_path = Path(args.api_inventory)
    if not inventory_path.exists():
        print(f"Error: 인벤토리 파일을 찾을 수 없습니다: {inventory_path}")
        sys.exit(1)

    result = run_diagnosis(source_dir, inventory_path,
                           args.modules, args.context_lines)

    # 파일 출력
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        print(f"\n결과 저장: {output_path}")
    else:
        # stdout 요약
        print("\n(--output 옵션으로 JSON 파일 저장 가능)")


if __name__ == "__main__":
    main()
