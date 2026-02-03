#!/usr/bin/env python3
"""
인젝션 패턴 사전 스캔 스크립트
소스코드에서 SQL Injection, OS Command Injection, SSI Injection 패턴을 검출합니다.

LLM 에이전트가 소스코드를 직접 읽지 않고, 이 스크립트의 출력만으로
severity 판정 및 설명 작성을 수행할 수 있도록 합니다.

사용법:
    python scan_injection_patterns.py <source_dir> [--output <file>] [--context-lines 3]
    python scan_injection_patterns.py testbed/3-pcona/pcona-env-dev@afd19907e2c/
    python scan_injection_patterns.py testbed/3-pcona/pcona-env-dev@afd19907e2c/ --output state/pcona_injection_scan.json

패턴 출처:
    - old_진단가이드문서/22_인젝션 진단가이드.docx
    - prompts/static/task_22_injection_review.md
"""

import json
import re
import sys
import argparse
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional


# ============================================================
#  1. SQL Injection 검출 패턴
#     출처: 22_인젝션 진단가이드.docx §1, task_22_injection_review.md
# ============================================================

# 1-1. DB API 식별 키워드 (언어별)
DB_API_IDENTIFY = {
    "java_jdbc": [
        r"NamedParameterJdbcTemplate",
        r"JdbcTemplate",
        r"PreparedStatement",
        r"Statement\.executeQuery",
        r"Statement\.execute\b",
    ],
    "java_jpa": [
        r"JpaRepository",
        r"@Query\s*\(",
        r"EntityManager",
        r"createQuery\s*\(",
        r"createNativeQuery\s*\(",
    ],
    "java_mybatis": [
        r"@Mapper\b",
        r"SqlSession",
        r"mybatis",
        r"ibatis",
        r"@Insert\s*\(",
        r"@Select\s*\(",
        r"@Update\s*\(",
        r"@Delete\s*\(",
    ],
    "java_r2dbc": [
        r"DatabaseClient",
        r"R2dbcEntityTemplate",
        r"Criteria\.where\s*\(",
        r"\.execute\s*\(",
        r"\.sql\s*\(",
        r"r2dbc",
    ],
    "nodejs": [
        r"Sequelize\s*\(",
        r"db\.query\s*\(",
        r"client\.query\s*\(",
        r"connect\.query\s*\(",
        r"queryQueue\.push",
        r"sendQueryPrepared",
    ],
}

# 1-2. SQL Injection 취약 패턴
SQLI_VULNERABLE_PATTERNS = [
    {
        "id": "SQLI_MYBATIS_DOLLAR_XML",
        "name": "MyBatis XML ${} 문자열 보간",
        "desc": "MyBatis XML mapper에서 ${} 사용은 PreparedStatement 바인딩 없이 직접 문자열 치환하여 SQL Injection 취약",
        "pattern": r'\$\{[^}]+\}',
        "file_glob": ["*.xml"],
        # MyBatis mapper XML 파일만 스캔 (pom.xml, logback.xml 등 제외)
        # <mapper namespace= 또는 <!DOCTYPE mapper 태그가 있는 파일만
        "file_content_check": r'(?:<mapper\s+namespace\s*=|<!DOCTYPE\s+mapper|<resultMap\s)',
        "category": "SQL Injection / MyBatis",
        "safe_counterpart": "#{} 파라미터 바인딩 사용",
    },
    {
        "id": "SQLI_MYBATIS_DOLLAR_ANNOTATION",
        "name": "MyBatis 어노테이션 ${} 문자열 보간",
        "desc": "MyBatis @Select/@Insert/@Update/@Delete 어노테이션에서 ${} 사용 시 SQL Injection 취약",
        # 같은 줄에 @Annotation 또는 SQL 키워드가 있어야 매칭
        "pattern": r'(?:@(?:Select|Insert|Update|Delete)\s*\(.*?\$\{|(?:SELECT|INSERT|UPDATE|DELETE|ALTER|WHERE|FROM|JOIN|SET|INTERVAL|INTO)\s.*?\$\{)',
        "file_glob": ["*.kt", "*.java"],
        "category": "SQL Injection / MyBatis",
        "safe_counterpart": "#{} 파라미터 바인딩 사용",
    },
    {
        "id": "SQLI_R2DBC_CRITERIA_TOSTRING",
        "name": "R2DBC Criteria.toString() SQL 직접 삽입",
        "desc": "Criteria 객체를 .toString()하여 SQL WHERE절에 직접 삽입 (진단가이드 §1 참조)",
        "pattern": r'(?:Criteria\.where|criteria|definition).*?\.toString\s*\(\)',
        "file_glob": ["*.kt", "*.java"],
        "category": "SQL Injection / R2DBC",
        "safe_counterpart": ".bind() 파라미터 바인딩 또는 R2dbcEntityTemplate Query DSL 사용",
    },
    {
        "id": "SQLI_R2DBC_STRING_CONCAT",
        "name": "R2DBC SQL 문자열 결합",
        "desc": "DatabaseClient.execute()에 문자열 결합(+, append, format, buildString)으로 사용자 입력을 SQL에 삽입",
        "pattern": r'(?:\.execute|\.sql)\s*\(\s*(?:"""[^"]*"""|"[^"]*")\s*(?:\+|\.format\s*\()',
        "file_glob": ["*.kt", "*.java"],
        "category": "SQL Injection / R2DBC",
        "safe_counterpart": ":param 파라미터 + .bind() 사용",
    },
    {
        "id": "SQLI_R2DBC_APPEND_SQL",
        "name": "R2DBC StringBuilder SQL 동적 생성",
        "desc": "StringBuilder/buildString으로 SQL을 동적 구성하여 사용자 입력값을 직접 삽입",
        "pattern": r'(?:buildString|StringBuilder|StringBuffer)\s*(?:\{|\()',
        "file_glob": ["*.kt", "*.java"],
        "category": "SQL Injection / R2DBC",
        "context_check": r'(?:SELECT\s+.*FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|WHERE\s+|ORDER\s+BY|GROUP\s+BY|\.execute\s*\(|\.sql\s*\(|_SQL\b)',
        "context_window": 8,
        "safe_counterpart": "파라미터 바인딩 사용",
    },
    {
        "id": "SQLI_STRING_FORMAT_SQL",
        "name": "String.format()으로 SQL 생성",
        "desc": "String.format() 또는 Kotlin 문자열 템플릿으로 SQL에 변수를 직접 삽입",
        "pattern": r'(?:\.format\s*\(|String\.format\s*\()',
        "file_glob": ["*.kt", "*.java"],
        "context_check": r'(?:SELECT\s+.*FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|\.execute\s*\(|\.sql\s*\(|client\.execute)',
        "context_window": 3,
        # 날짜/URL/파일경로 포맷은 제외
        "line_exclude": r'(?:DateTimeFormatter|\.format\s*\(\s*DateTimeFormatter|trackingUrl|FILE_NAME_FORMAT|ARCHIVE_FILE|\.format\s*\(\s*"%[tTdD])',
        "category": "SQL Injection",
        "safe_counterpart": "PreparedStatement 또는 :param 바인딩 사용",
    },
    {
        "id": "SQLI_JPA_CONCAT",
        "name": "JPA @Query 문자열 결합",
        "desc": "JPA @Query 어노테이션 내에서 문자열 결합으로 파라미터를 SQL에 직접 삽입",
        "pattern": r'@Query\s*\(\s*(?:value\s*=\s*)?["\'].*?\+',
        "file_glob": ["*.kt", "*.java"],
        "category": "SQL Injection / JPA",
        "safe_counterpart": ":param 또는 ?N 파라미터 바인딩 사용",
    },
    {
        "id": "SQLI_JDBC_STATEMENT",
        "name": "JDBC Statement 직접 실행",
        "desc": "Statement.executeQuery()에 문자열 결합으로 SQL 생성",
        "pattern": r'(?:Statement|stmt)\.execute(?:Query|Update)?\s*\(\s*(?:sql|query|[a-zA-Z_]+\s*\+)',
        "file_glob": ["*.kt", "*.java"],
        "category": "SQL Injection / JDBC",
        "safe_counterpart": "PreparedStatement + setString() 사용",
    },
    {
        "id": "SQLI_NODEJS_CONCAT",
        "name": "Node.js SQL 문자열 결합",
        "desc": "Node.js에서 db.query()에 문자열 결합 또는 템플릿 리터럴로 SQL 생성",
        "pattern": r'(?:db|client|connect|pool)\.query\s*\(\s*(?:`[^`]*\$\{|["\'][^"\']*\"\s*\+)',
        "file_glob": ["*.js", "*.ts"],
        "category": "SQL Injection / Node.js",
        "safe_counterpart": "Parameterized query ($1, $2) 사용",
    },
    {
        "id": "SQLI_ES_QUERY_INTERPOLATION",
        "name": "Elasticsearch @Query 파라미터 보간",
        "desc": "Spring Data Elasticsearch @Query의 ?N 플레이스홀더는 내부적으로 문자열 치환 방식 - 입력값의 JSON 특수문자 이스케이프 검증 필요",
        "pattern": r'@Query\s*\(\s*["\'].*?\?[0-9]',
        "file_glob": ["*.kt", "*.java"],
        "category": "NoSQL Injection / Elasticsearch",
        "safe_counterpart": "NativeSearchQueryBuilder 또는 Criteria API 사용, 입력값 이스케이프 처리",
    },
    {
        "id": "SQLI_DYNAMIC_TABLE_COLUMN",
        "name": "동적 테이블명/컬럼명 SQL 삽입",
        "desc": "사용자 입력을 테이블명이나 컬럼명으로 SQL에 직접 삽입 (파라미터 바인딩 불가 영역)",
        "pattern": r'(?:FROM|JOIN|INTO|TABLE|UPDATE)\s+["\']?\s*(?:\%s|\+\s*(?:table|column|field))',
        "file_glob": ["*.kt", "*.java"],
        "category": "SQL Injection / Dynamic Identifier",
        "safe_counterpart": "화이트리스트 검증으로 허용된 식별자만 사용",
    },
    {
        "id": "SQLI_DYNAMIC_TABLE_COLUMN_XML",
        "name": "동적 테이블명/컬럼명 SQL 삽입 (XML)",
        "desc": "MyBatis XML mapper에서 ${} 로 테이블명/컬럼명을 동적 삽입",
        "pattern": r'(?:FROM|JOIN|INTO|TABLE|UPDATE)\s+["\']?\s*\$\{',
        "file_glob": ["*.xml"],
        "file_content_check": r'(?:<mapper\s|<select\s|<insert\s|<update\s|<delete\s|mybatis|ibatis)',
        "category": "SQL Injection / Dynamic Identifier",
        "safe_counterpart": "화이트리스트 검증으로 허용된 식별자만 사용",
    },
]

# 1-3. SQL Injection 양호 패턴 (safe indicators)
SQLI_SAFE_PATTERNS = [
    {
        "id": "SQLI_SAFE_MYBATIS_HASH",
        "name": "MyBatis #{} 파라미터 바인딩",
        "pattern": r'#\{[^}]+\}',
        "file_glob": ["*.xml", "*.kt", "*.java"],
    },
    {
        "id": "SQLI_SAFE_R2DBC_BIND",
        "name": "R2DBC .bind() 파라미터 바인딩",
        "pattern": r'\.bind\s*\(\s*["\']',
        "file_glob": ["*.kt", "*.java"],
    },
    {
        "id": "SQLI_SAFE_PREPARED_STATEMENT",
        "name": "PreparedStatement 사용",
        "pattern": r'PreparedStatement|prepareStatement|setString|setInt|setLong',
        "file_glob": ["*.kt", "*.java"],
    },
    {
        "id": "SQLI_SAFE_JPA_PARAM_BINDING",
        "name": "JPA 파라미터 바인딩 (:param)",
        "pattern": r'@Query\s*\(.*?:[a-zA-Z_]+',
        "file_glob": ["*.kt", "*.java"],
    },
    {
        "id": "SQLI_SAFE_WHITELIST",
        "name": "화이트리스트 검증",
        "pattern": r'(?:allowedFields|whitelist|allowed_columns|setOf|listOf).*?\.contains\s*\(',
        "file_glob": ["*.kt", "*.java"],
    },
]


# ============================================================
#  2. OS Command Injection 검출 패턴
#     출처: 22_인젝션 진단가이드.docx §2
# ============================================================

OS_CMD_PATTERNS = [
    # 2.1.1 Java OS 명령실행 (진단가이드 §2.1.1)
    {
        "id": "CMD_RUNTIME_EXEC",
        "name": "Runtime.exec() 명령 실행",
        "desc": "Runtime.exec()로 외부 OS 명령 실행 (진단가이드 §2.1.1)",
        "pattern": r'Runtime\.(?:getRuntime\s*\(\s*\)\s*\.)?exec\s*\(',
        "file_glob": ["*.kt", "*.java"],
        "category": "OS Command Injection / Java",
    },
    {
        "id": "CMD_PROCESS_BUILDER",
        "name": "ProcessBuilder 명령 실행",
        "desc": "ProcessBuilder로 외부 OS 명령 실행 (진단가이드 §2.1.1, §2.4)",
        "pattern": r'ProcessBuilder\s*\(',
        "file_glob": ["*.kt", "*.java"],
        "category": "OS Command Injection / Java",
    },
    {
        "id": "CMD_DEFAULT_EXECUTOR",
        "name": "DefaultExecutor 명령 실행",
        "desc": "Apache Commons Exec DefaultExecutor로 명령 실행 (진단가이드 §2.1.1)",
        "pattern": r'DefaultExecutor|Execute\.Command',
        "file_glob": ["*.kt", "*.java"],
        "category": "OS Command Injection / Java",
    },
    {
        "id": "CMD_GETRUNTIME",
        "name": "Runtime.getRuntime() 사용",
        "desc": "Runtime.getRuntime() 호출 (진단가이드 §2.1.1) - exec() 동반 여부 확인 필요",
        "pattern": r'(?:Runtime\.getRuntime|getRuntime\s*\(\s*\))',
        "file_glob": ["*.kt", "*.java"],
        "category": "OS Command Injection / Java",
    },
    # 2.1.2 Node.js 명령실행 (진단가이드 §2.1.2)
    {
        "id": "CMD_NODEJS_EVAL",
        "name": "Node.js eval() 사용",
        "desc": "eval()은 문자열을 코드로 실행 - 사용자 입력 시 명령 실행 취약 (진단가이드 §2.1.2)",
        "pattern": r'\beval\s*\(',
        "file_glob": ["*.js", "*.ts"],
        "category": "OS Command Injection / Node.js",
    },
    {
        "id": "CMD_NODEJS_SETTIMEOUT_STRING",
        "name": "Node.js setTimeout/setInterval 문자열 인자",
        "desc": "setTimeout/setInterval에 문자열 인자 전달 시 eval과 동일 효과 (진단가이드 §2.1.2, §2.3)",
        "pattern": r'(?:setTimeout|setInterval)\s*\(\s*["\']',
        "file_glob": ["*.js", "*.ts"],
        "category": "OS Command Injection / Node.js",
    },
    {
        "id": "CMD_NODEJS_CHILD_PROCESS",
        "name": "Node.js child_process 사용",
        "desc": "child_process 모듈의 exec/execSync/spawn 사용 (진단가이드 §2.1.2)",
        "pattern": r'(?:child_process|require\s*\(\s*["\']child_process)',
        "file_glob": ["*.js", "*.ts"],
        "category": "OS Command Injection / Node.js",
    },
    {
        "id": "CMD_NODEJS_EXEC",
        "name": "Node.js exec()/execSync()/spawn()",
        "desc": "외부 명령 직접 실행 함수 (진단가이드 §2.1.2)",
        "pattern": r'(?:exec|execSync|spawn|execFile|execFileSync|spawnSync)\s*\(',
        "file_glob": ["*.js", "*.ts"],
        "category": "OS Command Injection / Node.js",
        # RegExp.exec(), Array.find() 등 일반 JS 메서드 제외
        "line_exclude": r'(?:\.exec\s*\(|RegExp|/[^/]+/[gimsuy]*\.exec|\.(?:find|map|filter|forEach|reduce)\s*\()',
    },
    # 2.1.3 PHP OS 명령실행 (진단가이드 §2.1.3)
    {
        "id": "CMD_PHP_EXEC",
        "name": "PHP 명령 실행 함수",
        "desc": "PHP 내장 명령 실행 함수 (진단가이드 §2.1.3, php.net/ref.exec 참조)",
        "pattern": r'\b(?:exec|passthru|system|shell_exec|proc_open|popen)\s*\(',
        "file_glob": ["*.php"],
        "category": "OS Command Injection / PHP",
    },
]

# 2-2. OS Command Injection 필터 검증 (진단가이드 §2.2.2)
# 양호: 6개 문자 모두 필터 - &, |, ;, >, `(backQuote), $
OS_CMD_FILTER_CHARS = ['&', '|', ';', '>', '`', '$']

OS_CMD_SAFE_PATTERNS = [
    {
        "id": "CMD_SAFE_SHUTDOWN_HOOK",
        "name": "Runtime.getRuntime() shutdown hook 전용",
        "pattern": r'(?:addShutdownHook|Runtime\.getRuntime\s*\(\s*\)\s*\.addShutdownHook)',
        "file_glob": ["*.kt", "*.java"],
    },
    {
        "id": "CMD_SAFE_HARDCODED",
        "name": "ProcessBuilder 하드코딩 명령어 (진단가이드 §2.4)",
        "pattern": r'ProcessBuilder\s*\(\s*(?:listOf|Arrays\.asList|List\.of)\s*\(\s*["\']',
        "file_glob": ["*.kt", "*.java"],
    },
    {
        "id": "CMD_SAFE_SETTIMEOUT_FUNC",
        "name": "setTimeout/setInterval function 객체 전달 (진단가이드 §2.3)",
        "pattern": r'(?:setTimeout|setInterval)\s*\(\s*(?:function|\(\)|[a-zA-Z_]+\s*(?:,|\)))',
        "file_glob": ["*.js", "*.ts"],
    },
    {
        "id": "CMD_SAFE_CSP_HEADER",
        "name": "CSP 헤더 설정 (진단가이드 §2.3)",
        "pattern": r'Content-Security-Policy',
        "file_glob": ["*.js", "*.ts", "*.html", "*.vue"],
    },
]


# ============================================================
#  3. SSI (Server-Side Include) Injection 검출 패턴
# ============================================================

SSI_PATTERNS = [
    {
        "id": "SSI_INCLUDE_DIRECTIVE",
        "name": "SSI include 디렉티브",
        "desc": "서버 사이드 인클루드 디렉티브가 사용자 입력과 함께 사용될 수 있는 패턴",
        "pattern": r'<!--\s*#\s*(?:include|exec|echo|config|flastmod|fsize)',
        "file_glob": ["*.html", "*.shtml", "*.stm", "*.shtm"],
        "category": "SSI Injection",
    },
    {
        "id": "SSI_EXEC_CMD",
        "name": "SSI exec cmd 디렉티브",
        "desc": "SSI exec cmd로 OS 명령 실행 가능",
        "pattern": r'<!--\s*#\s*exec\s+cmd\s*=',
        "file_glob": ["*.html", "*.shtml", "*.stm", "*.shtm"],
        "category": "SSI Injection",
    },
    {
        "id": "SSI_THYMELEAF_SSTI",
        "name": "Thymeleaf SSTI (Server-Side Template Injection)",
        "desc": "사용자 입력을 Thymeleaf templateEngine.process()에 직접 전달 시 SpEL 표현식 주입으로 RCE 가능",
        "pattern": r'templateEngine\.process\s*\(',
        "file_glob": ["*.kt", "*.java"],
        "category": "SSI Injection / Template Injection",
    },
    {
        "id": "SSI_FREEMARKER_TEMPLATE",
        "name": "FreeMarker 템플릿 인젝션",
        "desc": "FreeMarker 템플릿에서 사용자 입력을 직접 처리 시 SSTI 취약",
        "pattern": r'(?:freemarker|FreeMarker|Configuration\s*\(\s*\)|ftl)\S*\.process\s*\(',
        "file_glob": ["*.kt", "*.java"],
        "category": "SSI Injection / Template Injection",
    },
    {
        "id": "SSI_VELOCITY_TEMPLATE",
        "name": "Velocity 템플릿 인젝션",
        "desc": "Velocity 템플릿 엔진에서 사용자 입력을 직접 처리",
        "pattern": r'(?:VelocityEngine|Velocity).*?\.(?:evaluate|mergeTemplate)\s*\(',
        "file_glob": ["*.kt", "*.java"],
        "category": "SSI Injection / Template Injection",
    },
    {
        "id": "SSI_SPEL_EXPRESSION",
        "name": "SpEL 표현식 동적 평가",
        "desc": "Spring Expression Language를 사용자 입력으로 동적 평가 시 RCE 가능",
        "pattern": r'(?:ExpressionParser|SpelExpressionParser).*?\.parseExpression\s*\(',
        "file_glob": ["*.kt", "*.java"],
        "category": "SSI Injection / SpEL Injection",
    },
    {
        "id": "SSI_JSP_INCLUDE",
        "name": "JSP 동적 include",
        "desc": "JSP에서 사용자 입력을 include 경로로 사용",
        "pattern": r'<jsp:include\s+page\s*=\s*["\']?\s*<%=',
        "file_glob": ["*.jsp"],
        "category": "SSI Injection / JSP",
    },
    {
        "id": "SSI_EL_INJECTION",
        "name": "EL (Expression Language) Injection",
        "desc": "Java EE Expression Language에서 사용자 입력이 ${} 표현식으로 평가",
        "pattern": r'(?:ELProcessor|ExpressionFactory).*?\.eval\s*\(',
        "file_glob": ["*.kt", "*.java"],
        "category": "SSI Injection / EL Injection",
    },
]


# ============================================================
#  스캐너 로직
# ============================================================

@dataclass
class Finding:
    pattern_id: str
    pattern_name: str
    category: str
    description: str
    file: str
    line: int
    code_snippet: str
    context_before: list = field(default_factory=list)
    context_after: list = field(default_factory=list)
    safe_indicators: list = field(default_factory=list)
    safe_counterpart: str = ""


def matches_glob(filename: str, globs: list[str]) -> bool:
    """파일명이 glob 패턴 중 하나와 매칭되는지 확인"""
    for g in globs:
        ext = g.replace("*", "")
        if filename.endswith(ext):
            return True
    return False


def scan_file(filepath: Path, patterns: list[dict], safe_patterns: list[dict],
              context_lines: int = 3) -> list[Finding]:
    """파일에서 패턴을 검색하고 결과를 반환"""
    findings = []
    filename = filepath.name

    try:
        content = filepath.read_text(encoding="utf-8", errors="replace")
        lines = content.splitlines()
    except (IOError, UnicodeDecodeError):
        return findings

    for pat in patterns:
        if not matches_glob(filename, pat.get("file_glob", [])):
            continue

        # file_content_check: 파일 전체에 특정 패턴이 있어야 스캔 진행
        if "file_content_check" in pat:
            if not re.search(pat["file_content_check"], content, re.IGNORECASE):
                continue

        regex = re.compile(pat["pattern"], re.IGNORECASE)
        context_regex = None
        if "context_check" in pat:
            context_regex = re.compile(pat["context_check"], re.IGNORECASE)

        line_exclude_regex = None
        if "line_exclude" in pat:
            line_exclude_regex = re.compile(pat["line_exclude"], re.IGNORECASE)

        ctx_window = pat.get("context_window", 5)

        for i, line in enumerate(lines):
            match = regex.search(line)
            if not match:
                continue

            # line_exclude: 매칭된 줄이 제외 패턴에 해당하면 스킵
            if line_exclude_regex and line_exclude_regex.search(line):
                continue

            # context_check: 주변 줄에서 키워드 확인
            if context_regex:
                window = lines[max(0, i - ctx_window):min(len(lines), i + ctx_window + 1)]
                window_text = "\n".join(window)
                if not context_regex.search(window_text):
                    continue

            # 전후 context 추출
            ctx_before = lines[max(0, i - context_lines):i]
            ctx_after = lines[i + 1:min(len(lines), i + 1 + context_lines)]

            # safe indicator 확인
            safe_found = []
            window_text = "\n".join(lines[max(0, i - 10):min(len(lines), i + 11)])
            for sp in safe_patterns:
                if not matches_glob(filename, sp.get("file_glob", [])):
                    continue
                if re.search(sp["pattern"], window_text, re.IGNORECASE):
                    safe_found.append(sp["id"])

            rel_path = str(filepath)

            findings.append(Finding(
                pattern_id=pat["id"],
                pattern_name=pat["name"],
                category=pat.get("category", "Unknown"),
                description=pat.get("desc", ""),
                file=rel_path,
                line=i + 1,
                code_snippet=line.strip(),
                context_before=[l.strip() for l in ctx_before],
                context_after=[l.strip() for l in ctx_after],
                safe_indicators=safe_found,
                safe_counterpart=pat.get("safe_counterpart", ""),
            ))

    return findings


def scan_directory(source_dir: Path, context_lines: int = 3) -> dict:
    """디렉토리 전체를 스캔하여 인젝션 패턴을 검출"""

    extensions = {".kt", ".java", ".xml", ".js", ".ts", ".php",
                  ".html", ".shtml", ".stm", ".shtm", ".jsp", ".vue"}

    all_files = []
    for ext in extensions:
        all_files.extend(source_dir.rglob(f"*{ext}"))

    # test, node_modules, .idea, target, build 디렉토리 제외
    exclude_dirs = {"node_modules", ".idea", "target", "build", ".git", "dist"}
    all_files = [f for f in all_files
                 if not any(ex in f.parts for ex in exclude_dirs)]

    # DB API 식별 결과
    db_api_detections = {}
    for f in all_files:
        try:
            content = f.read_text(encoding="utf-8", errors="replace")
        except (IOError, UnicodeDecodeError):
            continue
        for api_type, keywords in DB_API_IDENTIFY.items():
            for kw in keywords:
                if re.search(kw, content, re.IGNORECASE):
                    if api_type not in db_api_detections:
                        db_api_detections[api_type] = []
                    rel = str(f.relative_to(source_dir))
                    if rel not in db_api_detections[api_type]:
                        db_api_detections[api_type].append(rel)

    # 1. SQL Injection 스캔
    sqli_findings = []
    for f in all_files:
        sqli_findings.extend(scan_file(f, SQLI_VULNERABLE_PATTERNS,
                                       SQLI_SAFE_PATTERNS, context_lines))

    # 2. OS Command Injection 스캔
    cmd_findings = []
    for f in all_files:
        cmd_findings.extend(scan_file(f, OS_CMD_PATTERNS,
                                      OS_CMD_SAFE_PATTERNS, context_lines))

    # OS Command Filter 검증 (§2.2.2)
    cmd_filter_analysis = []
    filter_patterns = [r'filter', r'sanitize', r'escape', r'replace\s*\(']
    for f in all_files:
        if not matches_glob(f.name, ["*.kt", "*.java", "*.js", "*.ts"]):
            continue
        try:
            content = f.read_text(encoding="utf-8", errors="replace")
        except (IOError, UnicodeDecodeError):
            continue
        for fp in filter_patterns:
            if re.search(fp, content, re.IGNORECASE):
                # 6개 필터 문자 확인
                chars_found = []
                chars_missing = []
                for c in OS_CMD_FILTER_CHARS:
                    escaped = re.escape(c)
                    if re.search(escaped, content):
                        chars_found.append(c)
                    else:
                        chars_missing.append(c)
                if chars_found:
                    cmd_filter_analysis.append({
                        "file": str(f.relative_to(source_dir)),
                        "chars_filtered": chars_found,
                        "chars_missing": chars_missing,
                        "sufficient": len(chars_missing) == 0,
                    })
                break

    # 3. SSI Injection 스캔
    ssi_findings = []
    for f in all_files:
        ssi_findings.extend(scan_file(f, SSI_PATTERNS, [], context_lines))

    # 상대 경로 변환
    for finding in sqli_findings + cmd_findings + ssi_findings:
        try:
            finding.file = str(Path(finding.file).relative_to(source_dir))
        except ValueError:
            pass

    # 결과 통계
    def count_by_pattern(findings):
        counts = {}
        for f in findings:
            pid = f.pattern_id
            counts[pid] = counts.get(pid, 0) + 1
        return counts

    return {
        "source_dir": str(source_dir),
        "total_files_scanned": len(all_files),
        "db_api_detected": db_api_detections,
        "sql_injection": {
            "total_findings": len(sqli_findings),
            "by_pattern": count_by_pattern(sqli_findings),
            "findings": [asdict(f) for f in sqli_findings],
        },
        "os_command_injection": {
            "total_findings": len(cmd_findings),
            "by_pattern": count_by_pattern(cmd_findings),
            "findings": [asdict(f) for f in cmd_findings],
            "filter_analysis": cmd_filter_analysis,
        },
        "ssi_injection": {
            "total_findings": len(ssi_findings),
            "by_pattern": count_by_pattern(ssi_findings),
            "findings": [asdict(f) for f in ssi_findings],
        },
        "summary": {
            "sql_injection_count": len(sqli_findings),
            "os_command_injection_count": len(cmd_findings),
            "ssi_injection_count": len(ssi_findings),
            "total_suspicious": len(sqli_findings) + len(cmd_findings) + len(ssi_findings),
        },
    }


def main():
    parser = argparse.ArgumentParser(
        description="인젝션 패턴 사전 스캔 (SQL Injection, OS Command Injection, SSI Injection)"
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
        "--context-lines", "-c",
        help="매칭 줄 전후 컨텍스트 줄 수 (기본: 3)",
        type=int,
        default=3,
    )
    parser.add_argument(
        "--quiet", "-q",
        help="요약만 출력",
        action="store_true",
    )
    args = parser.parse_args()

    source_dir = Path(args.source_dir)
    if not source_dir.exists():
        print(f"Error: 디렉토리를 찾을 수 없습니다: {source_dir}")
        sys.exit(1)

    print(f"스캔 대상: {source_dir}")
    result = scan_directory(source_dir, args.context_lines)

    # 요약 출력
    s = result["summary"]
    print(f"\n스캔 완료: {result['total_files_scanned']}개 파일 분석")
    print(f"  SQL Injection 의심:        {s['sql_injection_count']}건")
    print(f"  OS Command Injection 의심: {s['os_command_injection_count']}건")
    print(f"  SSI Injection 의심:        {s['ssi_injection_count']}건")
    print(f"  전체 의심 건수:            {s['total_suspicious']}건")

    if not args.quiet:
        # DB API 식별 결과
        print(f"\nDB API 식별:")
        for api_type, files in result["db_api_detected"].items():
            print(f"  {api_type}: {len(files)}개 파일")

        # 패턴별 통계
        if result["sql_injection"]["by_pattern"]:
            print(f"\nSQL Injection 패턴별:")
            for pid, count in result["sql_injection"]["by_pattern"].items():
                print(f"  {pid}: {count}건")
        if result["os_command_injection"]["by_pattern"]:
            print(f"\nOS Command Injection 패턴별:")
            for pid, count in result["os_command_injection"]["by_pattern"].items():
                print(f"  {pid}: {count}건")
        if result["ssi_injection"]["by_pattern"]:
            print(f"\nSSI Injection 패턴별:")
            for pid, count in result["ssi_injection"]["by_pattern"].items():
                print(f"  {pid}: {count}건")

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
