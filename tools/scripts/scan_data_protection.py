#!/usr/bin/env python3
"""
scan_data_protection.py v1.0.0
================================================================================
Spring Boot (Java/Kotlin) 데이터 보호 및 정보 노출 취약점 자동 진단.
Task 2-5 전용 정적 분석 스크립트.

진단 항목:
  [S] 하드코딩 시크릿    : AWS/GCP 키, DB 비밀번호, JWT Secret 평문 리터럴
  [L] 민감정보 로깅      : log.*/logger.* 구문 내 PII 변수 직접 출력
  [C] 취약 암호화        : MD5/SHA-1/DES/RC4/ECB 모드 사용
  [J] JWT 검증 불완전    : parseUnsecuredClaims, alg=none, setAllowedClockSkewSeconds 과도
  [D] DTO 민감정보 노출  : Response DTO 내 PII 필드에 @JsonIgnore/@JsonProperty 미적용
  [R] CORS 오설정        : allowedOrigins("*"), allowCredentials(true) 동시 설정
  [H] 보안 헤더 미설정   : .headers().disable(), frameOptions().disable() 등

사용법:
  python scan_data_protection.py <source_dir> [-o output.json]
  python scan_data_protection.py testbed/myapp/ \\
      --api-inventory state/api_inventory.json \\
      -o state/task25_result.json
"""

import argparse
import json
import re
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional

VERSION = "1.0.0"

# ============================================================
#  0. 공통 유틸
# ============================================================

_EXCLUDE_DIRS = frozenset({
    "test", "Test", "target", "build", "node_modules",
    ".git", "__pycache__", "generated", "resources/static",
})

_TEST_PATH_RE = re.compile(r'[\\/](?:test|Test|spec|mock|stub|fixture)[\\/]')


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def _line_of(content: str, pos: int) -> int:
    return content[:pos].count("\n") + 1


def _rel(path: Path, base: Path) -> str:
    try:
        return str(path.relative_to(base))
    except ValueError:
        return str(path)


def _is_excluded(fp: Path) -> bool:
    return any(ex in fp.parts for ex in _EXCLUDE_DIRS)


def _is_test_file(fp: Path) -> bool:
    """테스트 경로 또는 테스트 클래스 패턴 확인"""
    return bool(_TEST_PATH_RE.search(str(fp)))


# ============================================================
#  1. 정규식 상수 (지시사항 1: 목적별 분리 및 정교화)
# ============================================================

# ── [S] 하드코딩 시크릿 탐지 ────────────────────────────────────────────────

# AWS Access Key ID (AKIA로 시작하는 20자 영숫자)
_S_AWS_AKID_RE = re.compile(
    r'(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}',
)

# AWS Secret Access Key (40자 Base64 유사 패턴, 할당 문맥 필요)
_S_AWS_SECRET_RE = re.compile(
    r'(?i)(?:aws[_\-.]?secret|aws[_\-.]?access[_\-.]?key|secretAccessKey)\s*'
    r'[=:]\s*["\']([A-Za-z0-9/+=]{40})["\']',
)

# GCP Service Account Key JSON 내 private_key 필드
_S_GCP_KEY_RE = re.compile(
    r'"private_key"\s*:\s*"-----BEGIN (?:RSA )?PRIVATE KEY',
    re.IGNORECASE,
)

# JWT Secret 하드코딩: jwt.secret = "...", secretKey = "...", jwtKey = "..."
# @Value("${...}") 또는 System.getenv(...) 참조는 제외
_S_JWT_SECRET_RE = re.compile(
    r'(?i)(?:jwt[_\-.]?secret|secret[_\-.]?key|signing[_\-.]?key|jwtKey)\s*'
    r'[=:]\s*["\']([A-Za-z0-9+/=_\-!@#$%^&*]{8,})["\']',
)

# DB 비밀번호 하드코딩: password = "...", passwd = "...", pwd = "..."
# @Value / ${} / System.getenv 참조 제외용 네거티브 룩어헤드 포함
_S_DB_PASS_RE = re.compile(
    r'(?i)(?:^|[;\s])(?:password|passwd|pwd|db[_\-.]?pass(?:word)?)\s*'
    r'[=:]\s*(?!.*\$\{)(?!\s*System\.getenv)(?!\s*@Value)'
    r'"([^"]{3,})"',
    re.MULTILINE,
)

# 프로퍼티 파일 내 평문 비밀번호 (application.properties/yml)
_S_PROP_PASS_RE = re.compile(
    r'(?i)(?:password|passwd|secret)\s*[=:]\s*(?!\$\{)(?!ENC\()(\S{4,})',
    re.MULTILINE,
)

# 일반 시크릿 패턴: api.key, access.key 등 리터럴 할당
_S_GENERIC_SECRET_RE = re.compile(
    r'(?i)(?:api[_\-.]?key|access[_\-.]?key|client[_\-.]?secret|app[_\-.]?secret)\s*'
    r'[=:]\s*["\']([A-Za-z0-9+/=_\-]{16,})["\']',
)

# @Value("${...}") — 안전 참조 패턴 (탐지 결과 필터링용)
_S_VALUE_ANNOTATION_RE = re.compile(r'@Value\s*\(\s*["\$]\{[^}]+\}["\)]')
# System.getenv — 환경변수 참조 (안전)
_S_GETENV_RE = re.compile(r'System\.getenv\s*\(')


# ── [L] 민감정보 로깅 탐지 ──────────────────────────────────────────────────

# PII 변수명 키워드 (필드명 / 변수명 패턴)
_PII_VAR_NAMES = (
    r'ci|di|mdn|ssn|mbrid|mbr_?id|memberid|memno|mbrno'
    r'|residentNo|jumin|rrn|birth|birthDate'
    r'|pwd|password|passwd'
    r'|cardNo|card_?no|creditCard|cvc|cvv|pan'
    r'|tel|phone|mobile|cellphone'
    r'|email'
    r'|addr|address'
    r'|auth|token|jwt|accessToken|refreshToken'
    r'|pin|pinCode'
    r'|rsaKey|privateKey|secretKey'
    r'|accountNo|account_?no|bankAccount'
)

# 로그 구문 내 PII 변수 직접 삽입 탐지
# log.info("...", ssn) / log.debug("pwd={}", pwd) / log.info("ci=" + ci)
_L_LOG_PII_RE = re.compile(
    rf'(?i)(?:log(?:ger)?|LOG)\s*\.\s*(?:trace|debug|info|warn|error|fatal)\s*\('
    rf'[^;]*?(?:{_PII_VAR_NAMES})\b',
    re.MULTILINE,
)

# SLF4J / Logback 파라미터 바인딩: log.info("val={}", piiVar)
_L_LOG_PARAM_BIND_RE = re.compile(
    rf'(?i)(?:log(?:ger)?|LOG)\s*\.\s*(?:trace|debug|info|warn|error)\s*\('
    rf'[^,)]*["\'][^"\']*\{{\}}'   # "...{}" 포맷 문자열
    rf'[^)]*(?:{_PII_VAR_NAMES})\b',
    re.MULTILINE,
)

# 마스킹 유틸 안전 패턴 (로깅 전 마스킹 처리)
_L_MASKING_SAFE_RE = re.compile(
    r'(?i)(?:mask(?:ing)?|Mask(?:ing)?(?:Util)?|redact|anonymize|encrypt)\s*\(',
)

# System.out.println PII 출력 (비운영 코드지만 경고)
_L_SYSOUT_PII_RE = re.compile(
    rf'(?i)System\.out\.(?:print(?:ln)?|printf)\s*\([^;]*?(?:{_PII_VAR_NAMES})\b',
    re.MULTILINE,
)


# ── [C] 취약 암호화 알고리즘 탐지 ───────────────────────────────────────────

# MessageDigest: MD5, SHA-1 (SHA-256/384/512는 안전)
_C_WEAK_DIGEST_RE = re.compile(
    r'MessageDigest\.getInstance\s*\(\s*"(MD5|SHA-?1|SHA1)"\s*\)',
    re.IGNORECASE,
)

# Cipher: DES, 3DES, RC4, ARCFOUR, ECB 모드
_C_WEAK_CIPHER_RE = re.compile(
    r'Cipher\.getInstance\s*\(\s*"('
    r'DES(?:/[^"]*)?'
    r'|DESede(?:/[^"]*)?'
    r'|RC4|ARCFOUR'
    r'|[A-Za-z]+/ECB/[^"]*'          # ECB 모드 (AES/ECB 포함)
    r')"\s*\)',
    re.IGNORECASE,
)

# KeyGenerator: DES, RC4
_C_WEAK_KEYGEN_RE = re.compile(
    r'KeyGenerator\.getInstance\s*\(\s*"(DES|DESede|RC4|ARCFOUR)"\s*\)',
    re.IGNORECASE,
)

# BouncyCastle / Apache Commons Codec MD5 직접 호출
_C_DIGEST_UTILS_MD5_RE = re.compile(
    r'(?:DigestUtils\.md5|DigestUtils\.md5Hex'
    r'|MD5\.digestAsHex'
    r'|Hashing\.md5\s*\('
    r'|MessageDigestPasswordEncoder.*MD5'
    r')',
    re.IGNORECASE,
)

# Spring Security 취약 PasswordEncoder
_C_WEAK_ENCODER_RE = re.compile(
    r'(?:new\s+(?:Md5PasswordEncoder|ShaPasswordEncoder|MessageDigestPasswordEncoder)'
    r'|NoOpPasswordEncoder\.getInstance)',
    re.IGNORECASE,
)


# ── [J] JWT 검증 불완전 탐지 ────────────────────────────────────────────────

# parseUnsecuredClaims / parseClaimsJwt (서명 없는 파싱 — jjwt)
_J_PARSE_UNSIGNED_RE = re.compile(
    r'\.parseUnsecuredClaims\s*\(|\.parseClaimsJwt\s*\(',
    re.IGNORECASE,
)

# alg=none 허용: setAllowedAlgorithms, NONE 상수 사용
_J_ALG_NONE_RE = re.compile(
    r'(?:SignatureAlgorithm\.NONE'
    r'|"none"\s*(?:,|\))'          # algorithm("none")
    r'|setAllowedAlgorithms.*NONE'
    r')',
    re.IGNORECASE,
)

# 서명 검증 없이 decode 만 사용 (jjwt setSigningKey 없는 parser)
_J_PARSER_NO_VERIFY_RE = re.compile(
    r'Jwts\.parser\s*\(\s*\)(?![\s\S]{0,200}\.setSigningKey)',
    re.DOTALL,
)

# jose4j / nimbus: 알고리즘 강제 없이 deserialize
_J_JOSE_NO_ALG_RE = re.compile(
    r'(?:new\s+JwtConsumerBuilder|JwtConsumer\.process)'
    r'(?![\s\S]{0,400}\.setRequireSignature|\.setExpectedSignatureAlgorithm)',
    re.DOTALL,
)

# 과도한 클럭 스큐 (600초 이상 → 만료 토큰 재사용 가능)
_J_CLOCK_SKEW_RE = re.compile(
    r'setAllowedClockSkewSeconds\s*\(\s*(\d+)\s*\)',
    re.IGNORECASE,
)
_J_CLOCK_SKEW_THRESHOLD = 600  # seconds


# ── [D] DTO 민감정보 노출 탐지 ──────────────────────────────────────────────

# 민감 필드명 패턴 (PII 필드명과 동일 + 추가)
_D_SENSITIVE_FIELD_NAMES_RE = re.compile(
    rf'(?i)(?:private|protected|public|var|val)\s+'
    rf'(?:String|Object|CharSequence|char\[\])?\s*'
    rf'(?:{_PII_VAR_NAMES})\b',
    re.MULTILINE,
)

# @JsonIgnore / @JsonProperty(access=READ_ONLY) — 안전 처리
_D_JSON_IGNORE_RE = re.compile(
    r'@JsonIgnore\b|@JsonProperty\s*\([^)]*(?:access\s*=\s*JsonProperty\.Access\.'
    r'(?:WRITE_ONLY|READ_ONLY)|["\']WRITE_ONLY["\'])[^)]*\)',
    re.IGNORECASE,
)

# @JsonView — 뷰 기반 필터링
_D_JSON_VIEW_RE = re.compile(r'@JsonView\s*\(', re.IGNORECASE)

# Getter 메서드가 없는 경우에도 노출 가능 — Lombok @Getter 탐지
_D_LOMBOK_GETTER_RE = re.compile(r'@(?:Getter|Data|Value)\b')

# 마스킹 직렬화 어노테이션
_D_MASKING_ANNOT_RE = re.compile(
    r'@(?:JsonSerialize|MaskingField|Masked|Sensitive|SensitiveData)\b',
    re.IGNORECASE,
)


# ── [R] CORS 오설정 탐지 ────────────────────────────────────────────────────

# allowedOrigins("*") 와일드카드
_R_ALLOWED_ORIGINS_WILDCARD_RE = re.compile(
    r'allowedOrigins\s*\(\s*["\']?\*["\']?\s*\)',
    re.IGNORECASE,
)

# allowedOriginPatterns("*")  — Spring 5.3+에서 credentials와 함께 사용
_R_ORIGIN_PATTERNS_WILDCARD_RE = re.compile(
    r'allowedOriginPatterns\s*\(\s*["\']?\*["\']?\s*\)',
    re.IGNORECASE,
)

# allowCredentials(true)
_R_ALLOW_CREDENTIALS_RE = re.compile(
    r'allowCredentials\s*\(\s*true\s*\)',
    re.IGNORECASE,
)

# @CrossOrigin 어노테이션 (클래스/메서드 레벨)
_R_CROSS_ORIGIN_RE = re.compile(
    r'@CrossOrigin\s*(?:\([^)]*\))?',
    re.IGNORECASE,
)

# Origin 헤더 그대로 반영: response.setHeader("Access-Control-Allow-Origin", originVar)
_R_ORIGIN_REFLECT_RE = re.compile(
    r'(?:setHeader|addHeader)\s*\(\s*["\']Access-Control-Allow-Origin["\']\s*,'
    r'\s*(?!"\*")(\w+)',
    re.IGNORECASE,
)


# ── [H] 보안 헤더 미설정 탐지 ───────────────────────────────────────────────

# .headers().disable() — 모든 보안 헤더 비활성화
_H_HEADERS_DISABLE_RE = re.compile(
    r'\.headers\s*\(\s*\)\s*\.disable\s*\(\s*\)',
    re.IGNORECASE,
)

# 람다 기반 headers(h -> h.disable())
_H_HEADERS_LAMBDA_DISABLE_RE = re.compile(
    r'\.headers\s*\(\s*\w+\s*->\s*\w+\.disable\s*\(\s*\)\s*\)',
    re.IGNORECASE,
)

# frameOptions().disable() — Clickjacking 방어 비활성화
_H_FRAME_DISABLE_RE = re.compile(
    r'\.frameOptions\s*\(\s*\)\s*\.disable\s*\(\s*\)'
    r'|frameOptions\s*\(\s*\w+\s*->\s*\w+\.disable\s*\(\s*\)\s*\)',
    re.IGNORECASE,
)

# Content Security Policy 미설정 탐지 (Security Config 내 CSP 설정 부재)
_H_CSP_SET_RE = re.compile(
    r'\.contentSecurityPolicy\s*\('
    r'|Content-Security-Policy'
    r'|\.addHeaderWriter\s*\(.*ContentSecurityPolicy',
    re.IGNORECASE,
)

# HSTS 설정 여부
_H_HSTS_RE = re.compile(
    r'\.httpStrictTransportSecurity\s*\('
    r'|\.hsts\s*\(',
    re.IGNORECASE,
)


# ============================================================
#  2. 데이터 구조
# ============================================================

@dataclass
class DPFinding:
    """데이터 보호 취약점 개별 발견 항목"""
    finding_id: str
    category: str           # HARDCODED_SECRET / SENSITIVE_LOGGING / WEAK_CRYPTO /
                            # JWT_INCOMPLETE / DTO_EXPOSURE / CORS_MISCONFIG / SECURITY_HEADER
    severity: str           # Critical / High / Medium / Low / Info
    title: str
    description: str
    file: str
    line: int
    code_snippet: str
    cwe_id: str
    owasp_category: str
    recommendation: str
    result: str             # 취약 / 정보 / 양호
    needs_review: bool = False
    evidence: dict = field(default_factory=dict)


@dataclass
class DPScanResult:
    """전체 스캔 결과"""
    version: str = VERSION
    task_id: str = "2-5"
    status: str = "completed"
    source_dir: str = ""
    scanned_at: str = ""
    summary: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)
    global_status: dict = field(default_factory=dict)


# ============================================================
#  3. 공통 헬퍼
# ============================================================

def _iter_sources(source_dir: Path, exts=(".java", ".kt", ".groovy")):
    """소스 파일 이터레이터 (빌드/테스트 디렉터리 제외)"""
    for ext in exts:
        for fp in source_dir.rglob(f"*{ext}"):
            if _is_excluded(fp):
                continue
            yield fp


def _iter_props(source_dir: Path):
    """프로퍼티/YAML 파일 이터레이터"""
    for pat in ("application*.properties", "application*.yml", "application*.yaml",
                "bootstrap*.properties", "bootstrap*.yml"):
        for fp in source_dir.rglob(pat):
            if _is_excluded(fp):
                continue
            yield fp


def _snippet(content: str, pos: int, window: int = 120) -> str:
    """pos 기준 앞뒤 window 범위 한 줄 스니펫"""
    line_start = content.rfind("\n", 0, pos) + 1
    line_end   = content.find("\n", pos)
    if line_end == -1:
        line_end = len(content)
    return content[line_start:line_end].strip()[:window]


def _make_id(category: str, n: int) -> str:
    abbr = {
        "HARDCODED_SECRET": "SEC",
        "SENSITIVE_LOGGING": "LOG",
        "WEAK_CRYPTO": "CRY",
        "JWT_INCOMPLETE": "JWT",
        "DTO_EXPOSURE": "DTO",
        "CORS_MISCONFIG": "COR",
        "SECURITY_HEADER": "HDR",
    }
    return f"DATA-{abbr.get(category, 'XXX')}-{n:03d}"


# ============================================================
#  4. [S] 하드코딩 시크릿 스캔
# ============================================================

def scan_hardcoded_secrets(source_dir: Path) -> list[DPFinding]:
    """소스 및 프로퍼티 파일에서 하드코딩된 시크릿 탐지"""
    findings: list[DPFinding] = []
    counter = [0]

    def _add(category, severity, title, desc, file, line, snippet, cwe, owasp, rec,
             result="취약", needs_review=False):
        counter[0] += 1
        findings.append(DPFinding(
            finding_id=_make_id("HARDCODED_SECRET", counter[0]),
            category="HARDCODED_SECRET",
            severity=severity,
            title=title,
            description=desc,
            file=file,
            line=line,
            code_snippet=snippet,
            cwe_id=cwe,
            owasp_category=owasp,
            recommendation=rec,
            result=result,
            needs_review=needs_review,
        ))

    # ── Java/Kotlin 소스 파일 스캔 ──────────────────────────────
    for fp in _iter_sources(source_dir):
        content = _read(fp)
        if not content:
            continue
        rel = _rel(fp, source_dir)
        is_test = _is_test_file(fp)

        # @Value / getenv 참조가 있는 줄은 안전 — 줄 단위 필터링
        safe_lines: set[int] = set()
        for m in _S_VALUE_ANNOTATION_RE.finditer(content):
            safe_lines.add(_line_of(content, m.start()))
        for m in _S_GETENV_RE.finditer(content):
            safe_lines.add(_line_of(content, m.start()))

        # AWS AKIA
        for m in _S_AWS_AKID_RE.finditer(content):
            ln = _line_of(content, m.start())
            if ln in safe_lines:
                continue
            _add("HARDCODED_SECRET",
                 "Info" if is_test else "Critical",
                 "AWS Access Key ID 하드코딩",
                 f"AWS Access Key ID 패턴({m.group()[:8]}...)이 소스코드에 평문 존재.",
                 rel, ln, _snippet(content, m.start()),
                 "CWE-798", "A02:2021 Cryptographic Failures",
                 "AWS Secrets Manager 또는 환경변수로 이관. 즉시 키 로테이션.",
                 result="정보" if is_test else "취약",
                 needs_review=is_test)

        # AWS Secret Key
        for m in _S_AWS_SECRET_RE.finditer(content):
            ln = _line_of(content, m.start())
            if ln in safe_lines:
                continue
            _add("HARDCODED_SECRET",
                 "Info" if is_test else "Critical",
                 "AWS Secret Access Key 하드코딩",
                 "AWS Secret Access Key가 코드에 평문 리터럴로 존재.",
                 rel, ln, _snippet(content, m.start()),
                 "CWE-798", "A02:2021 Cryptographic Failures",
                 "AWS Secrets Manager / Parameter Store로 이관.",
                 result="정보" if is_test else "취약",
                 needs_review=is_test)

        # GCP Private Key
        for m in _S_GCP_KEY_RE.finditer(content):
            ln = _line_of(content, m.start())
            _add("HARDCODED_SECRET",
                 "Info" if is_test else "Critical",
                 "GCP Service Account Private Key 하드코딩",
                 "GCP 서비스 계정 private_key가 소스코드에 포함.",
                 rel, ln, "-----BEGIN PRIVATE KEY (마스킹)",
                 "CWE-798", "A02:2021 Cryptographic Failures",
                 "GCP Secret Manager로 이관. 서비스 계정 키 즉시 폐기 후 재발급.",
                 result="정보" if is_test else "취약",
                 needs_review=is_test)

        # JWT Secret
        for m in _S_JWT_SECRET_RE.finditer(content):
            ln = _line_of(content, m.start())
            if ln in safe_lines:
                continue
            val = m.group(1)
            severity = "High"
            needs = False
            if len(val) < 32:
                desc = f"JWT 서명 키가 짧거나({len(val)}자) 추측 가능한 리터럴로 하드코딩."
            else:
                desc = "JWT 서명 키가 소스코드에 평문 리터럴로 하드코딩."
                needs = True  # 길이는 충분 — Prod 키 여부 수동 확인
            _add("HARDCODED_SECRET", severity,
                 "JWT Secret Key 하드코딩",
                 desc, rel, ln, _snippet(content, m.start()),
                 "CWE-798", "A02:2021 Cryptographic Failures",
                 "application.yml의 @Value(\"${jwt.secret}\") 참조 또는 Vault/KMS 사용.",
                 needs_review=needs)

        # DB Password
        for m in _S_DB_PASS_RE.finditer(content):
            ln = _line_of(content, m.start())
            if ln in safe_lines:
                continue
            _add("HARDCODED_SECRET",
                 "Info" if is_test else "High",
                 "DB 비밀번호 하드코딩",
                 "데이터베이스 비밀번호가 소스코드에 평문 리터럴로 존재.",
                 rel, ln, "password = \"****\" (마스킹)",
                 "CWE-798", "A02:2021 Cryptographic Failures",
                 "Spring Vault / AWS Secrets Manager / 환경변수로 이관.",
                 result="정보" if is_test else "취약",
                 needs_review=is_test)

        # 일반 API Key
        for m in _S_GENERIC_SECRET_RE.finditer(content):
            ln = _line_of(content, m.start())
            if ln in safe_lines:
                continue
            _add("HARDCODED_SECRET",
                 "Medium",
                 "API Key / Client Secret 하드코딩",
                 f"API Key 또는 Client Secret 패턴이 소스코드에 평문 리터럴로 존재.",
                 rel, ln, _snippet(content, m.start()),
                 "CWE-798", "A02:2021 Cryptographic Failures",
                 "환경변수 또는 외부 시크릿 관리 시스템으로 이관.",
                 needs_review=True)

    # ── 프로퍼티/YAML 파일 스캔 ─────────────────────────────────
    for fp in _iter_props(source_dir):
        content = _read(fp)
        if not content:
            continue
        rel = _rel(fp, source_dir)

        for m in _S_PROP_PASS_RE.finditer(content):
            ln = _line_of(content, m.start())
            val = m.group(1)
            # 플레이스홀더 / ENC() / 환경변수 참조 제외
            if val.startswith(("${", "ENC(", "#{", "@{")):
                continue
            if re.match(r'^[<>\$\#@\{\[]', val):
                continue
            _add("HARDCODED_SECRET",
                 "High",
                 "프로퍼티 파일 내 비밀번호/시크릿 평문",
                 f"application 설정 파일에 비밀번호/시크릿이 평문으로 저장.",
                 rel, ln, "****" + " (마스킹)",
                 "CWE-312", "A02:2021 Cryptographic Failures",
                 "Spring Cloud Config Vault 또는 Jasypt 암호화(@Value ENC(...)) 적용.",
                 needs_review=True)

    return findings


# ============================================================
#  5. [L] 민감정보 로깅 스캔
# ============================================================

def scan_sensitive_logging(source_dir: Path) -> list[DPFinding]:
    findings: list[DPFinding] = []
    counter = [0]

    for fp in _iter_sources(source_dir):
        content = _read(fp)
        if not content:
            continue
        rel = _rel(fp, source_dir)
        lines_list = content.splitlines()

        for i, line in enumerate(lines_list, 1):
            stripped = line.strip()
            # 주석 줄 제외
            if stripped.startswith(("//", "*", "/*", "#")):
                continue

            matched_pattern = None
            if _L_LOG_PII_RE.search(line):
                matched_pattern = "log_pii"
            elif _L_LOG_PARAM_BIND_RE.search(line):
                matched_pattern = "log_bind"
            elif _L_SYSOUT_PII_RE.search(line):
                matched_pattern = "sysout"

            if not matched_pattern:
                continue

            # 마스킹 유틸 사용 시 안전 — 같은 줄에 mask 함수 호출 확인
            if _L_MASKING_SAFE_RE.search(line):
                continue

            # 앞뒤 2줄 컨텍스트에서 마스킹 사용 여부 추가 확인
            ctx_start = max(0, i - 3)
            ctx_end   = min(len(lines_list), i + 2)
            ctx = "\n".join(lines_list[ctx_start:ctx_end])
            if _L_MASKING_SAFE_RE.search(ctx):
                # 가까운 마스킹 처리 존재 → 정보로 하향
                counter[0] += 1
                findings.append(DPFinding(
                    finding_id=_make_id("SENSITIVE_LOGGING", counter[0]),
                    category="SENSITIVE_LOGGING",
                    severity="Info",
                    title="민감정보 로깅 (마스킹 유틸 근접 사용 확인)",
                    description="로그 구문에 PII 변수가 포함되나 근접 컨텍스트에서 마스킹 유틸 호출 확인. 실제 마스킹 적용 여부 수동 확인 필요.",
                    file=rel, line=i,
                    code_snippet=stripped[:120],
                    cwe_id="CWE-532",
                    owasp_category="A09:2021 Security Logging and Monitoring Failures",
                    recommendation="마스킹 유틸이 해당 변수에 적용되었는지 확인. log.info(\"val={}\", MaskingUtils.mask(pii)) 형태 권장.",
                    result="정보",
                    needs_review=True,
                ))
                continue

            sev = "Info" if matched_pattern == "sysout" else "High"
            title = ("System.out PII 직접 출력" if matched_pattern == "sysout"
                     else "민감정보(PII) 평문 로깅")
            desc = ("System.out.println으로 PII 변수가 직접 출력됨."
                    if matched_pattern == "sysout"
                    else "로그 구문에 PII 변수(주민번호, 비밀번호, CI/DI 등)가 "
                         "마스킹 없이 직접 출력됨. 로그 파일 접근자에게 개인정보 노출 가능.")
            counter[0] += 1
            findings.append(DPFinding(
                finding_id=_make_id("SENSITIVE_LOGGING", counter[0]),
                category="SENSITIVE_LOGGING",
                severity=sev,
                title=title,
                description=desc,
                file=rel, line=i,
                code_snippet=stripped[:120],
                cwe_id="CWE-532",
                owasp_category="A09:2021 Security Logging and Monitoring Failures",
                recommendation=(
                    "1. 민감 필드를 로그에서 제외하거나 MaskingUtils.mask() 적용.\n"
                    "2. 운영 환경 로그 레벨을 INFO 이상으로 설정하고 DEBUG 로그 비활성화.\n"
                    "3. 로그 집계 시스템(ELK 등)의 접근 제어 강화."
                ),
                result="취약" if matched_pattern != "sysout" else "정보",
                needs_review=False,
            ))

    return findings


# ============================================================
#  6. [C] 취약 암호화 알고리즘 스캔
# ============================================================

def scan_weak_crypto(source_dir: Path) -> list[DPFinding]:
    findings: list[DPFinding] = []
    counter = [0]

    CRYPTO_CHECKS = [
        (_C_WEAK_DIGEST_RE,      "High",   "취약한 해시 알고리즘 사용",
         "MD5/SHA-1은 충돌 공격에 취약한 알고리즘입니다. 패스워드 해시나 무결성 검증에 사용 시 즉시 취약.",
         "CWE-327", "A02:2021 Cryptographic Failures",
         "SHA-256 이상(SHA-256/384/512) 또는 bcrypt/Argon2(패스워드용)로 교체."),
        (_C_WEAK_CIPHER_RE,      "High",   "취약한 대칭 암호화 알고리즘/모드 사용",
         "DES/3DES/RC4는 알려진 취약점이 있으며, ECB 모드는 패턴 노출 취약점이 있습니다.",
         "CWE-327", "A02:2021 Cryptographic Failures",
         "AES-256-GCM 또는 AES-256-CBC(PKCS5Padding)로 교체. ECB 모드는 GCM으로 대체."),
        (_C_WEAK_KEYGEN_RE,      "High",   "취약한 KeyGenerator 알고리즘",
         "DES/RC4 KeyGenerator 사용. 생성된 키는 취약한 암호화에만 사용 가능.",
         "CWE-327", "A02:2021 Cryptographic Failures",
         "AES KeyGenerator(256비트)로 교체."),
        (_C_DIGEST_UTILS_MD5_RE, "High",   "DigestUtils/Hashing MD5 직접 사용",
         "Apache Commons / Guava의 MD5 유틸 직접 호출. 동일한 취약점.",
         "CWE-327", "A02:2021 Cryptographic Failures",
         "SHA-256 유틸 또는 HMAC-SHA256으로 교체."),
        (_C_WEAK_ENCODER_RE,     "Critical", "취약한 Spring Security PasswordEncoder",
         "Md5PasswordEncoder / NoOpPasswordEncoder 사용. 패스워드가 평문 또는 MD5로 저장됨.",
         "CWE-916", "A02:2021 Cryptographic Failures",
         "BCryptPasswordEncoder(strength=12) 또는 Argon2PasswordEncoder로 교체."),
    ]

    for fp in _iter_sources(source_dir):
        content = _read(fp)
        if not content:
            continue
        rel = _rel(fp, source_dir)

        for pattern, sev, title, desc, cwe, owasp, rec in CRYPTO_CHECKS:
            for m in pattern.finditer(content):
                ln = _line_of(content, m.start())
                snip = _snippet(content, m.start())
                # 주석 내 언급 제외
                line_text = snip.lstrip()
                if line_text.startswith(("//", "*", "/*", "#")):
                    continue
                counter[0] += 1
                findings.append(DPFinding(
                    finding_id=_make_id("WEAK_CRYPTO", counter[0]),
                    category="WEAK_CRYPTO",
                    severity=sev,
                    title=title,
                    description=desc,
                    file=rel, line=ln,
                    code_snippet=snip,
                    cwe_id=cwe,
                    owasp_category=owasp,
                    recommendation=rec,
                    result="취약",
                    needs_review=False,
                ))

    return findings


# ============================================================
#  7. [J] JWT 검증 불완전 스캔
# ============================================================

def scan_jwt_issues(source_dir: Path) -> list[DPFinding]:
    findings: list[DPFinding] = []
    counter = [0]

    for fp in _iter_sources(source_dir):
        content = _read(fp)
        if not content:
            continue
        rel = _rel(fp, source_dir)

        # parseUnsecuredClaims
        for m in _J_PARSE_UNSIGNED_RE.finditer(content):
            ln = _line_of(content, m.start())
            counter[0] += 1
            findings.append(DPFinding(
                finding_id=_make_id("JWT_INCOMPLETE", counter[0]),
                category="JWT_INCOMPLETE",
                severity="High",
                title="JWT 서명 검증 없는 파싱 (parseUnsecuredClaims)",
                description=(
                    "parseUnsecuredClaims() 또는 parseClaimsJwt()는 서명 검증을 수행하지 않습니다. "
                    "공격자가 서명 없는 JWT를 위조하여 인증 우회 가능."
                ),
                file=rel, line=ln,
                code_snippet=_snippet(content, m.start()),
                cwe_id="CWE-347",
                owasp_category="A02:2021 Cryptographic Failures",
                recommendation="parseClaimsJws()와 .setSigningKey(secret) 조합 사용. jjwt 0.12+는 verifyWith() 사용.",
                result="취약",
            ))

        # alg=none 허용
        for m in _J_ALG_NONE_RE.finditer(content):
            ln = _line_of(content, m.start())
            counter[0] += 1
            findings.append(DPFinding(
                finding_id=_make_id("JWT_INCOMPLETE", counter[0]),
                category="JWT_INCOMPLETE",
                severity="Critical",
                title="JWT Algorithm NONE 허용",
                description=(
                    "SignatureAlgorithm.NONE 또는 algorithm(\"none\") 설정 탐지. "
                    "서명 없는 JWT를 유효한 토큰으로 수락 — 인증 완전 우회 가능."
                ),
                file=rel, line=ln,
                code_snippet=_snippet(content, m.start()),
                cwe_id="CWE-347",
                owasp_category="A02:2021 Cryptographic Failures",
                recommendation="허용 알고리즘을 HS256/RS256 등 명시적으로 지정. NONE 알고리즘 허용 로직 즉시 제거.",
                result="취약",
            ))

        # Jwts.parser() setSigningKey 없음
        for m in _J_PARSER_NO_VERIFY_RE.finditer(content):
            ln = _line_of(content, m.start())
            counter[0] += 1
            findings.append(DPFinding(
                finding_id=_make_id("JWT_INCOMPLETE", counter[0]),
                category="JWT_INCOMPLETE",
                severity="High",
                title="JWT Parser 서명 키 미설정",
                description=(
                    "Jwts.parser() 생성 후 setSigningKey() 없이 파싱 시도. "
                    "서명 검증이 실질적으로 수행되지 않을 수 있음."
                ),
                file=rel, line=ln,
                code_snippet=_snippet(content, m.start()),
                cwe_id="CWE-347",
                owasp_category="A02:2021 Cryptographic Failures",
                recommendation="Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token) 사용.",
                result="정보",
                needs_review=True,
            ))

        # 과도한 clock skew
        for m in _J_CLOCK_SKEW_RE.finditer(content):
            try:
                skew_val = int(m.group(1))
            except ValueError:
                continue
            if skew_val < _J_CLOCK_SKEW_THRESHOLD:
                continue
            ln = _line_of(content, m.start())
            counter[0] += 1
            findings.append(DPFinding(
                finding_id=_make_id("JWT_INCOMPLETE", counter[0]),
                category="JWT_INCOMPLETE",
                severity="Medium",
                title=f"JWT 클럭 스큐 과도 설정 ({skew_val}초)",
                description=(
                    f"setAllowedClockSkewSeconds({skew_val})는 {skew_val}초 동안 "
                    "만료된 토큰을 유효하게 수락합니다. 토큰 재사용 공격 가능성 증가."
                ),
                file=rel, line=ln,
                code_snippet=_snippet(content, m.start()),
                cwe_id="CWE-613",
                owasp_category="A02:2021 Cryptographic Failures",
                recommendation="클럭 스큐는 최대 60초 이하로 설정. 시스템 NTP 동기화로 대체.",
                result="정보",
                needs_review=True,
            ))

    return findings


# ============================================================
#  8. [D] DTO 민감정보 노출 스캔 (지시사항 2-1)
# ============================================================

def scan_dto_exposure(source_dir: Path, api_inventory: Optional[dict] = None) -> list[DPFinding]:
    """Response DTO 내 PII 필드에 @JsonIgnore / 마스킹 어노테이션 누락 여부 탐지.

    api_inventory가 있으면 실제 응답에 사용되는 DTO만 필터링하여 정확도 향상.
    """
    findings: list[DPFinding] = []
    counter = [0]

    # API 인벤토리에서 Response DTO 클래스명 수집
    response_dto_names: set[str] = set()
    if api_inventory:
        for ep in api_inventory.get("endpoints", []):
            rt = ep.get("return_type", "")
            # ResponseEntity<XxxResponse>, XxxDto, XxxResponse 등 추출
            for name in re.findall(r'\b([A-Z]\w+(?:Dto|Response|Result|Vo|VO|View|Info))\b', rt):
                response_dto_names.add(name)

    # DTO/Response 클래스 파일 스캔
    dto_pattern = re.compile(
        r'(?i)(?:Dto|Response|Result|VO|View|Info|Payload)\.(java|kt)$'
    )

    for fp in _iter_sources(source_dir):
        if not dto_pattern.search(fp.name):
            continue

        content = _read(fp)
        if not content:
            continue

        class_name_m = re.search(r'(?:class|data class|object)\s+(\w+)', content)
        if not class_name_m:
            continue
        class_name = class_name_m.group(1)

        # API 인벤토리가 있으면 응답 DTO만 분석
        if response_dto_names and class_name not in response_dto_names:
            continue

        rel = _rel(fp, source_dir)

        # Lombok @Getter / @Data 여부 (필드가 자동 직렬화됨)
        has_lombok = bool(_D_LOMBOK_GETTER_RE.search(content))

        lines_list = content.splitlines()
        for i, line in enumerate(lines_list, 1):
            if not _D_SENSITIVE_FIELD_NAMES_RE.search(line):
                continue

            # 바로 앞 줄(어노테이션)에서 보호 어노테이션 확인
            prev_ctx = "\n".join(lines_list[max(0, i - 4):i])
            has_ignore  = bool(_D_JSON_IGNORE_RE.search(prev_ctx))
            has_view    = bool(_D_JSON_VIEW_RE.search(prev_ctx))
            has_masking = bool(_D_MASKING_ANNOT_RE.search(prev_ctx))

            if has_ignore or has_masking:
                continue  # 보호 어노테이션 존재 → 양호

            stripped = line.strip()[:120]
            if has_view:
                # @JsonView는 있으나 실제 적용 범위 수동 확인 필요
                counter[0] += 1
                findings.append(DPFinding(
                    finding_id=_make_id("DTO_EXPOSURE", counter[0]),
                    category="DTO_EXPOSURE",
                    severity="Info",
                    title="DTO 민감 필드 — @JsonView 적용 (수동 확인 필요)",
                    description=(
                        f"{class_name}.{stripped.split()[-1] if stripped else '?'} 필드에 "
                        "@JsonView 탐지. 해당 뷰가 모든 응답에 적용되는지 수동 확인 필요."
                    ),
                    file=rel, line=i, code_snippet=stripped,
                    cwe_id="CWE-200",
                    owasp_category="A04:2021 Insecure Design",
                    recommendation="@JsonView가 실제 응답 엔드포인트에 일관되게 적용되는지 확인.",
                    result="정보",
                    needs_review=True,
                ))
                continue

            # 보호 어노테이션 없음
            sev = "High" if has_lombok else "Medium"
            desc = (
                f"{class_name} DTO에 민감 필드({stripped.split()[-1] if stripped else '?'})가 존재하며 "
                f"{'Lombok @Getter/@Data로 자동 직렬화되어 ' if has_lombok else ''}"
                "@JsonIgnore / 마스킹 어노테이션이 없어 API 응답에 평문 노출될 수 있음."
            )
            counter[0] += 1
            findings.append(DPFinding(
                finding_id=_make_id("DTO_EXPOSURE", counter[0]),
                category="DTO_EXPOSURE",
                severity=sev,
                title="DTO 민감 필드 @JsonIgnore 미적용",
                description=desc,
                file=rel, line=i, code_snippet=stripped,
                cwe_id="CWE-200",
                owasp_category="A04:2021 Insecure Design",
                recommendation=(
                    "1. 응답에 불필요한 PII 필드는 @JsonIgnore 적용.\n"
                    "2. 마스킹이 필요한 경우 커스텀 @JsonSerialize(using = MaskingSerializer.class) 적용.\n"
                    "3. 필드 자체를 응답 DTO에서 제거하고 별도 내부 Entity 사용 권장."
                ),
                result="취약",
                needs_review=False,
            ))

    return findings


# ============================================================
#  9. [R] CORS 오설정 스캔 (지시사항 2-2)
# ============================================================

def scan_cors_config(source_dir: Path) -> tuple[list[DPFinding], dict]:
    """전역 Security Config 및 Controller에서 CORS 오설정 탐지"""
    findings: list[DPFinding] = []
    counter = [0]
    global_cors: dict = {
        "has_cors_config":         False,
        "wildcard_found":          False,
        "credentials_with_wildcard": False,
        "origin_reflect_found":    False,
        "cross_origin_count":      0,
        "config_files":            [],
    }

    # 전역 Security / Web Config 파일 우선 스캔
    config_patterns = [
        "*SecurityConfig*.java", "*SecurityConfig*.kt",
        "*WebConfig*.java",      "*WebConfig*.kt",
        "*CorsConfig*.java",     "*CorsConfig*.kt",
        "*WebMvc*.java",         "*WebMvc*.kt",
        "web.xml",
    ]
    scanned: set[Path] = set()

    for pat in config_patterns:
        for fp in source_dir.rglob(pat):
            if _is_excluded(fp) or fp in scanned:
                continue
            scanned.add(fp)
            content = _read(fp)
            if not content:
                continue
            rel = _rel(fp, source_dir)

            has_wildcard     = bool(_R_ALLOWED_ORIGINS_WILDCARD_RE.search(content)
                                    or _R_ORIGIN_PATTERNS_WILDCARD_RE.search(content))
            has_credentials  = bool(_R_ALLOW_CREDENTIALS_RE.search(content))
            has_reflect      = bool(_R_ORIGIN_REFLECT_RE.search(content))

            if has_wildcard or has_credentials or has_reflect:
                global_cors["has_cors_config"] = True
                global_cors["config_files"].append(rel)

            if has_wildcard:
                global_cors["wildcard_found"] = True
                ln_m = (_R_ALLOWED_ORIGINS_WILDCARD_RE.search(content)
                        or _R_ORIGIN_PATTERNS_WILDCARD_RE.search(content))
                ln = _line_of(content, ln_m.start()) if ln_m else 0

                if has_credentials:
                    global_cors["credentials_with_wildcard"] = True
                    counter[0] += 1
                    findings.append(DPFinding(
                        finding_id=_make_id("CORS_MISCONFIG", counter[0]),
                        category="CORS_MISCONFIG",
                        severity="High",
                        title="CORS allowedOrigins(*) + allowCredentials(true) 동시 설정",
                        description=(
                            "allowedOrigins(\"*\")와 allowCredentials(true)를 동시에 설정하면 "
                            "모든 Origin의 인증 쿠키/헤더가 허용됩니다. "
                            "CSRF + XSS 공격 조합 시 세션 탈취 가능. "
                            "Spring 5.3+ 에서는 allowCredentials(true) + allowedOrigins(\"*\") 조합이 예외를 발생시키나, "
                            "allowedOriginPatterns(\"*\")와 조합하면 여전히 동작."
                        ),
                        file=rel, line=ln,
                        code_snippet=_snippet(content, ln_m.start()) if ln_m else "",
                        cwe_id="CWE-942",
                        owasp_category="A05:2021 Security Misconfiguration",
                        recommendation=(
                            "허용 Origin을 구체적인 도메인으로 제한: "
                            ".allowedOrigins(\"https://app.example.com\"). "
                            "와일드카드 사용 시 allowCredentials(false) 유지."
                        ),
                        result="취약",
                    ))
                else:
                    counter[0] += 1
                    findings.append(DPFinding(
                        finding_id=_make_id("CORS_MISCONFIG", counter[0]),
                        category="CORS_MISCONFIG",
                        severity="Medium",
                        title="CORS allowedOrigins(*) 와일드카드 설정",
                        description=(
                            "allowedOrigins(\"*\") 설정으로 모든 출처에서 Cross-Origin 요청 허용. "
                            "credentials 없이도 API 응답 데이터가 외부 Origin에 노출."
                        ),
                        file=rel, line=ln,
                        code_snippet=_snippet(content, ln_m.start()) if ln_m else "",
                        cwe_id="CWE-942",
                        owasp_category="A05:2021 Security Misconfiguration",
                        recommendation="허용 Origin을 배포 도메인 목록으로 제한.",
                        result="취약",
                    ))

            if has_reflect:
                global_cors["origin_reflect_found"] = True
                m = _R_ORIGIN_REFLECT_RE.search(content)
                ln = _line_of(content, m.start()) if m else 0
                counter[0] += 1
                findings.append(DPFinding(
                    finding_id=_make_id("CORS_MISCONFIG", counter[0]),
                    category="CORS_MISCONFIG",
                    severity="High",
                    title="Origin 헤더 그대로 반영 (CORS Origin 우회)",
                    description=(
                        "request.getHeader(\"Origin\") 값을 "
                        "Access-Control-Allow-Origin 응답 헤더에 그대로 반영. "
                        "공격자의 임의 Origin 요청 허용 — allowedOrigins(\"*\")와 동일한 위험."
                    ),
                    file=rel, line=ln,
                    code_snippet=_snippet(content, m.start()) if m else "",
                    cwe_id="CWE-942",
                    owasp_category="A05:2021 Security Misconfiguration",
                    recommendation="허용 Origin 화이트리스트를 서버 측에서 관리하고 요청 Origin과 대조 후 허용 여부 결정.",
                    result="취약",
                ))

    # Controller 레벨 @CrossOrigin 스캔
    for fp in _iter_sources(source_dir):
        if fp in scanned:
            continue
        content = _read(fp)
        if not content or not _R_CROSS_ORIGIN_RE.search(content):
            continue
        rel = _rel(fp, source_dir)

        for m in _R_CROSS_ORIGIN_RE.finditer(content):
            global_cors["cross_origin_count"] += 1
            ann_text = m.group()
            ln = _line_of(content, m.start())

            # @CrossOrigin(origins = "*") 또는 기본값(origins = "*") 탐지
            if re.search(r'origins\s*=\s*["\']?\*', ann_text) or "origins" not in ann_text:
                counter[0] += 1
                findings.append(DPFinding(
                    finding_id=_make_id("CORS_MISCONFIG", counter[0]),
                    category="CORS_MISCONFIG",
                    severity="Medium",
                    title="@CrossOrigin 기본값(와일드카드) 사용",
                    description=(
                        f"@CrossOrigin 어노테이션이 origins 미지정(기본값 *) 또는 "
                        f"origins=\"*\"으로 설정. 해당 Controller 전체 또는 메서드에 적용."
                    ),
                    file=rel, line=ln,
                    code_snippet=_snippet(content, m.start()),
                    cwe_id="CWE-942",
                    owasp_category="A05:2021 Security Misconfiguration",
                    recommendation="@CrossOrigin(origins = \"https://app.example.com\") 로 특정 도메인 명시.",
                    result="정보",
                    needs_review=True,
                ))

    return findings, global_cors


# ============================================================
#  10. [H] 보안 헤더 미설정 스캔 (지시사항 2-2)
# ============================================================

def scan_security_headers(source_dir: Path) -> tuple[list[DPFinding], dict]:
    """Spring Security Config에서 보안 헤더 설정 상태 탐지"""
    findings: list[DPFinding] = []
    counter = [0]
    header_status: dict = {
        "headers_disabled":   False,
        "frame_disabled":     False,
        "csp_configured":     False,
        "hsts_configured":    False,
        "config_files":       [],
    }

    config_patterns = [
        "*SecurityConfig*.java", "*SecurityConfig*.kt",
        "*SecurityFilterChain*.java",
        "*WebSecurityConfigurerAdapter*.java",
    ]

    for pat in config_patterns:
        for fp in source_dir.rglob(pat):
            if _is_excluded(fp):
                continue
            content = _read(fp)
            if not content:
                continue
            rel = _rel(fp, source_dir)

            # .headers().disable() 탐지
            if (_H_HEADERS_DISABLE_RE.search(content)
                    or _H_HEADERS_LAMBDA_DISABLE_RE.search(content)):
                header_status["headers_disabled"] = True
                header_status["config_files"].append(rel)
                m = (_H_HEADERS_DISABLE_RE.search(content)
                     or _H_HEADERS_LAMBDA_DISABLE_RE.search(content))
                ln = _line_of(content, m.start())
                counter[0] += 1
                findings.append(DPFinding(
                    finding_id=_make_id("SECURITY_HEADER", counter[0]),
                    category="SECURITY_HEADER",
                    severity="High",
                    title="전체 보안 헤더 비활성화 (.headers().disable())",
                    description=(
                        ".headers().disable() 설정으로 Spring Security의 모든 보안 응답 헤더가 제거됨. "
                        "X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, "
                        "HSTS, Content-Security-Policy 등 모두 미적용."
                    ),
                    file=rel, line=ln,
                    code_snippet=_snippet(content, m.start()),
                    cwe_id="CWE-693",
                    owasp_category="A05:2021 Security Misconfiguration",
                    recommendation=(
                        ".headers().disable() 제거 후 필요한 헤더만 선택적 비활성화. "
                        "최소한 frameOptions().deny(), contentTypeOptions() 는 활성화 유지."
                    ),
                    result="취약",
                ))

            # frameOptions().disable() 탐지
            if _H_FRAME_DISABLE_RE.search(content):
                header_status["frame_disabled"] = True
                if rel not in header_status["config_files"]:
                    header_status["config_files"].append(rel)
                m = _H_FRAME_DISABLE_RE.search(content)
                ln = _line_of(content, m.start())
                counter[0] += 1
                findings.append(DPFinding(
                    finding_id=_make_id("SECURITY_HEADER", counter[0]),
                    category="SECURITY_HEADER",
                    severity="Medium",
                    title="X-Frame-Options 비활성화 (Clickjacking 취약)",
                    description=(
                        "frameOptions().disable()로 X-Frame-Options 헤더가 제거됨. "
                        "<iframe>을 통한 Clickjacking 공격에 노출 가능."
                    ),
                    file=rel, line=ln,
                    code_snippet=_snippet(content, m.start()),
                    cwe_id="CWE-1021",
                    owasp_category="A05:2021 Security Misconfiguration",
                    recommendation=(
                        "frameOptions().deny() 또는 frameOptions().sameOrigin() 으로 변경. "
                        "임베딩이 필요한 경우 CSP frame-ancestors 지시자로 대체."
                    ),
                    result="취약",
                ))

            # CSP 설정 여부 확인 (미설정 시 정보로 리포트)
            if _H_CSP_SET_RE.search(content):
                header_status["csp_configured"] = True
            if _H_HSTS_RE.search(content):
                header_status["hsts_configured"] = True

    # CSP 미설정 정보 리포트 (Security Config 파일이 존재하는 경우에만)
    if header_status["config_files"] and not header_status["csp_configured"]:
        counter[0] += 1
        findings.append(DPFinding(
            finding_id=_make_id("SECURITY_HEADER", counter[0]),
            category="SECURITY_HEADER",
            severity="Info",
            title="Content-Security-Policy (CSP) 헤더 미설정",
            description=(
                "Spring Security Config에서 CSP 헤더 설정을 찾을 수 없음. "
                "CSP는 XSS 완화의 핵심 방어층입니다."
            ),
            file=header_status["config_files"][0] if header_status["config_files"] else "N/A",
            line=0, code_snippet="",
            cwe_id="CWE-693",
            owasp_category="A05:2021 Security Misconfiguration",
            recommendation=(
                ".headers().contentSecurityPolicy(\"default-src 'self'; ...\") 설정 추가. "
                "Report-Only 모드로 먼저 배포 후 정책 강화 권장."
            ),
            result="정보",
            needs_review=True,
        ))

    if header_status["config_files"] and not header_status["hsts_configured"]:
        counter[0] += 1
        findings.append(DPFinding(
            finding_id=_make_id("SECURITY_HEADER", counter[0]),
            category="SECURITY_HEADER",
            severity="Info",
            title="HSTS (HTTP Strict-Transport-Security) 미설정",
            description=(
                "HSTS 헤더 미설정. HTTPS 강제 없이 HTTP 다운그레이드 공격 가능."
            ),
            file=header_status["config_files"][0] if header_status["config_files"] else "N/A",
            line=0, code_snippet="",
            cwe_id="CWE-319",
            owasp_category="A05:2021 Security Misconfiguration",
            recommendation=(
                ".headers().httpStrictTransportSecurity()"
                ".maxAgeInSeconds(31536000).includeSubDomains(true) 설정."
            ),
            result="정보",
            needs_review=True,
        ))

    return findings, header_status


# ============================================================
#  11. 통계 요약 생성
# ============================================================

def _build_summary(all_findings: list[DPFinding]) -> dict:
    sev_order  = ["Critical", "High", "Medium", "Low", "Info"]
    cat_labels = {
        "HARDCODED_SECRET": "하드코딩 시크릿",
        "SENSITIVE_LOGGING": "민감정보 로깅",
        "WEAK_CRYPTO":       "취약 암호화",
        "JWT_INCOMPLETE":    "JWT 검증 불완전",
        "DTO_EXPOSURE":      "DTO 민감정보 노출",
        "CORS_MISCONFIG":    "CORS 오설정",
        "SECURITY_HEADER":   "보안 헤더 미설정",
    }

    by_sev = {s: 0 for s in sev_order}
    by_cat = {k: 0 for k in cat_labels}
    by_result = {"취약": 0, "정보": 0, "양호": 0}

    for f in all_findings:
        if f.severity in by_sev:
            by_sev[f.severity] += 1
        if f.category in by_cat:
            by_cat[f.category] += 1
        if f.result in by_result:
            by_result[f.result] += 1

    return {
        "total":      len(all_findings),
        "by_severity": by_sev,
        "by_category": {cat_labels.get(k, k): v for k, v in by_cat.items() if v > 0},
        "by_result":   by_result,
        "needs_review_count": sum(1 for f in all_findings if f.needs_review),
    }


# ============================================================
#  12. Main
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description=f"scan_data_protection.py v{VERSION} — 데이터 보호 취약점 자동 진단"
    )
    parser.add_argument("source_dir", help="진단 대상 소스 루트 디렉터리")
    parser.add_argument("--api-inventory", dest="api_inventory",
                        help="scan_api.py 결과 JSON (DTO 노출 정확도 향상용)")
    parser.add_argument("-o", "--output", default="state/task25_result.json",
                        help="결과 출력 경로 (기본: state/task25_result.json)")
    parser.add_argument("--skip", nargs="*", default=[],
                        choices=["secret", "logging", "crypto", "jwt", "dto", "cors", "header"],
                        help="특정 진단 항목 건너뛰기")
    args = parser.parse_args()

    source_dir = Path(args.source_dir).resolve()
    if not source_dir.exists():
        print(f"[ERROR] source_dir 미존재: {source_dir}", file=sys.stderr)
        sys.exit(1)

    # API 인벤토리 로드
    api_inventory = None
    if args.api_inventory:
        try:
            with open(args.api_inventory, encoding="utf-8") as f:
                api_inventory = json.load(f)
        except Exception as e:
            print(f"[WARN] API 인벤토리 로드 실패: {e}", file=sys.stderr)

    skip = set(args.skip)
    all_findings: list[DPFinding] = []
    global_status: dict = {}

    print(f"[scan_data_protection v{VERSION}] 진단 시작: {source_dir}")

    if "secret" not in skip:
        print("  [S] 하드코딩 시크릿 스캔...")
        all_findings.extend(scan_hardcoded_secrets(source_dir))

    if "logging" not in skip:
        print("  [L] 민감정보 로깅 스캔...")
        all_findings.extend(scan_sensitive_logging(source_dir))

    if "crypto" not in skip:
        print("  [C] 취약 암호화 알고리즘 스캔...")
        all_findings.extend(scan_weak_crypto(source_dir))

    if "jwt" not in skip:
        print("  [J] JWT 검증 불완전 스캔...")
        all_findings.extend(scan_jwt_issues(source_dir))

    if "dto" not in skip:
        print("  [D] DTO 민감정보 노출 스캔...")
        all_findings.extend(scan_dto_exposure(source_dir, api_inventory))

    cors_findings, cors_status = [], {}
    if "cors" not in skip:
        print("  [R] CORS 오설정 스캔...")
        cors_findings, cors_status = scan_cors_config(source_dir)
        all_findings.extend(cors_findings)
        global_status["cors"] = cors_status

    header_findings, header_status = [], {}
    if "header" not in skip:
        print("  [H] 보안 헤더 미설정 스캔...")
        header_findings, header_status = scan_security_headers(source_dir)
        all_findings.extend(header_findings)
        global_status["security_headers"] = header_status

    summary = _build_summary(all_findings)

    result = DPScanResult(
        source_dir=str(source_dir),
        scanned_at=datetime.now().isoformat(),
        summary=summary,
        findings=[asdict(f) for f in all_findings],
        global_status=global_status,
    )

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(asdict(result), f, ensure_ascii=False, indent=2)

    print(f"\n[완료] 총 {summary['total']}건 발견 "
          f"(취약 {summary['by_result']['취약']} / "
          f"정보 {summary['by_result']['정보']}) → {out_path}")
    crit = summary["by_severity"].get("Critical", 0)
    high = summary["by_severity"].get("High", 0)
    if crit or high:
        print(f"  Critical: {crit}건  High: {high}건 — 즉시 조치 필요")


if __name__ == "__main__":
    main()
