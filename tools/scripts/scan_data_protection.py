#!/usr/bin/env python3
"""
scan_data_protection.py v1.3.0
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
import bisect
import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional

VERSION = "1.3.0"

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

# 프로퍼티/YAML 파일 내 평문 시크릿
# password / passwd / secret / token 키워드 포함
# 값이 환경변수 참조(${...}), Jasypt 암호화(ENC(...)), YAML 앵커(&/*), 빈 값이 아닌 경우에만 탐지
_S_PROP_PASS_RE = re.compile(
    r'(?i)(?:^|[\s.])(?:password|passwd|secret|token)\s*[=:]\s*'
    r'(?!\s*$)'           # 빈 값 제외
    r'(?!\$\{)'           # 환경변수 참조 ${...} 제외
    r'(?!ENC\()'          # Jasypt ENC(...) 제외
    r'(?![#!])'           # 주석 문자로 시작하는 값 제외
    r'(?![&*])'           # YAML 앵커/별칭 제외
    r'([^\s\$\#\{\[\'\"]{4,}|["\'][^"\']{4,}["\'])',  # 순수 평문 리터럴
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

# ── [보완 1] Base64 인코딩 시크릿 탐지 ──────────────────────────────────────
# 기존 _S_GENERIC_SECRET_RE / _S_JWT_SECRET_RE 미커버 변수명에 집중
# 조건: 시크릿 컨텍스트 변수명 + 24자 이상 순수 Base64 + (+,/,= 중 1 이상 포함)
_S_BASE64_SECRET_NAMES_RE = re.compile(
    r'(?i)(?:hmac[_\-.]?(?:key|secret)'
    r'|auth[_\-.]?key'
    r'|signing[_\-.]?key'
    r'|encode[d]?[_\-.]?(?:key|secret)'
    r'|base64[_\-.]?(?:key|secret|token)'
    r'|client[_\-.]?key'
    r'|encrypt[_\-.]?key'
    r'|decode[d]?[_\-.]?key'
    r')\s*[=:]\s*["\']([A-Za-z0-9+/]{24,}={0,2})["\']',
)
# Base64 특성 문자 포함 여부 필터 — 단순 alphanumeric 제외
_S_BASE64_CHARS_RE = re.compile(r'[+/=]')


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

# ── [L] 로그 허용 목록 / 보호 필수 목록 (FP 필터링) ─────────────────────────
# 허용 목록: 단독 출력 시 FP — 내부 추적용 식별자·비즈니스 상수
_LOG_FP_ALLOWLIST_VARS = (
    r'userId|feedId|feedSeq|asumUid|pushType|redirectUri'
)
_LOG_FP_ALLOWLIST_RE = re.compile(
    rf'(?i)\b(?:{_LOG_FP_ALLOWLIST_VARS})\b'
)

# 보호 필수 목록: 반드시 마스킹 — 고객 식별자·인증 토큰·개인정보 포함 객체
_LOG_PROTECTED_PARAM_NAMES = (
    r'mbrId|mbrno|mbr_?id|memberid|memno'
    r'|authToken|accessToken|refreshToken|webTokenInfo|kmcResult'
    r'|encryptData|plainText|plain_?text'
    r'|sessionId|httpSession'
    r'|password|passwd|pwd|secretKey|privateKey|rsaKey'
    r'|cardNo|card_?no|creditCard|pan|cvc|cvv'
    r'|email|phone|mobile|tel|mdn'
    r'|response\b'  # 회원 정보 API 응답 전체 객체
)
_LOG_PROTECTED_PARAM_RE = re.compile(
    rf'(?i)(?<!\w)(?:{_LOG_PROTECTED_PARAM_NAMES})'
)
# Kotlin 문자열 템플릿 내 보호 필수 변수: "...: mbrId=${it}..."
_LOG_KOTLIN_PROTECTED_TEMPLATE_RE = re.compile(
    rf'(?i)\$\{{?(?:{_LOG_PROTECTED_PARAM_NAMES})'
)


def _has_protected_log_param(line: str) -> bool:
    """로그 라인에 보호 필수 변수가 문자열 리터럴 외부(파라미터 위치)에 존재하는지 확인.

    규칙:
    - 문자열 리터럴("...") 내 키워드만 있는 경우 → FP (e.g. logger.warn("Invalid JWT: ..."))
    - 파라미터 위치에 보호 필수 변수가 있는 경우 → TP (e.g. log.info("...", mbrId))
    - Kotlin 문자열 템플릿에 보호 필수 변수가 있는 경우 → TP (e.g. "...: mbrId=${it}")
    """
    # Kotlin 문자열 템플릿 체크 (보호 필수 변수가 ${...} 내 있으면 TP)
    if _LOG_KOTLIN_PROTECTED_TEMPLATE_RE.search(line):
        return True
    # 문자열 리터럴 제거 후 보호 필수 변수 체크
    stripped_of_strings = re.sub(r'"[^"]*"', '', line)
    return bool(_LOG_PROTECTED_PARAM_RE.search(stripped_of_strings))

# 로그 구문 내 PII 변수 직접 삽입 탐지 — 레벨별 분리
# ★ info/warn/error/fatal: 상용 환경 출력 → High/취약
# ★ debug/trace          : 개발/검증계 출력 → Low/정보
_L_LOG_PII_HIGH_RE = re.compile(
    rf'(?i)(?:log(?:ger)?|LOG)\s*\.\s*(?:info|warn|error|fatal)\s*\('
    rf'[^;]*?(?<!\w)(?:{_PII_VAR_NAMES})\b',
    re.MULTILINE,
)
_L_LOG_PII_LOW_RE = re.compile(
    rf'(?i)(?:log(?:ger)?|LOG)\s*\.\s*(?:debug|trace)\s*\('
    rf'[^;]*?(?<!\w)(?:{_PII_VAR_NAMES})\b',
    re.MULTILINE,
)
# 하위 호환용 통합 패턴 (DTO 스캔 등 컨텍스트 체크용)
_L_LOG_PII_RE = re.compile(
    rf'(?i)(?:log(?:ger)?|LOG)\s*\.\s*(?:trace|debug|info|warn|error|fatal)\s*\('
    rf'[^;]*?(?<!\w)(?:{_PII_VAR_NAMES})\b',
    re.MULTILINE,
)

# SLF4J / Logback 파라미터 바인딩: log.info("val={}", piiVar) — 레벨별 분리
_L_LOG_PARAM_BIND_HIGH_RE = re.compile(
    rf'(?i)(?:log(?:ger)?|LOG)\s*\.\s*(?:info|warn|error|fatal)\s*\('
    rf'[^,)]*["\'][^"\']*\{{\}}'
    rf'[^)]*(?<!\w)(?:{_PII_VAR_NAMES})\b',
    re.MULTILINE,
)
_L_LOG_PARAM_BIND_LOW_RE = re.compile(
    rf'(?i)(?:log(?:ger)?|LOG)\s*\.\s*(?:debug|trace)\s*\('
    rf'[^,)]*["\'][^"\']*\{{\}}'
    rf'[^)]*(?<!\w)(?:{_PII_VAR_NAMES})\b',
    re.MULTILINE,
)
# 하위 호환용
_L_LOG_PARAM_BIND_RE = re.compile(
    rf'(?i)(?:log(?:ger)?|LOG)\s*\.\s*(?:trace|debug|info|warn|error)\s*\('
    rf'[^,)]*["\'][^"\']*\{{\}}'
    rf'[^)]*(?<!\w)(?:{_PII_VAR_NAMES})\b',
    re.MULTILINE,
)

# 마스킹 유틸 안전 패턴 (로깅 전 마스킹 처리)
_L_MASKING_SAFE_RE = re.compile(
    r'(?i)(?:mask(?:ing)?|Mask(?:ing)?(?:Util)?|redact|anonymize|encrypt)\s*\(',
)

# System.out.println PII 출력 (비운영 코드지만 경고)
_L_SYSOUT_PII_RE = re.compile(
    rf'(?i)System\.out\.(?:print(?:ln)?|printf)\s*\([^;]*?(?<!\w)(?:{_PII_VAR_NAMES})\b',
    re.MULTILINE,
)


# ── [C] 취약 암호화 알고리즘 탐지 ───────────────────────────────────────────

# MessageDigest: MD5, SHA-1 (SHA-256/384/512는 안전)
_C_WEAK_DIGEST_RE = re.compile(
    r'MessageDigest\.getInstance\s*\(\s*"(MD5|SHA-?1|SHA1)"\s*\)',
    re.IGNORECASE,
)

# Cipher: DES, 3DES, RC4, ARCFOUR, ECB 모드, SEED/ECB
# ★ RSA/ECB/OAEPPadding 및 RSA/ECB/OAEPWith... — OAEP 패딩은 안전 → 제외 (FP 방지)
# ★ SEED/ECB — 국산 SEED 알고리즘도 ECB 모드 사용 시 패턴 노출 취약점
_C_WEAK_CIPHER_RE = re.compile(
    r'Cipher\.getInstance\s*\(\s*"('
    r'DES(?:/[^"]*)?'
    r'|DESede(?:/[^"]*)?'
    r'|RC4|ARCFOUR'
    r'|SEED/ECB(?:/[^"]*)?'           # 국산 SEED + ECB 모드
    r'|[A-Za-z]+/ECB/(?!OAEP)[^"]*'  # ECB 모드 (OAEP 계열 패딩 전체 제외)
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

# ── [보완 2] 하드코딩 IV(초기화 벡터) 탐지 ──────────────────────────────────
# Pattern A: new IvParameterSpec("literal".getBytes())
_C_IV_STRING_RE = re.compile(
    r'new\s+IvParameterSpec\s*\(\s*"([^"]{8,})"\s*\.getBytes\s*\(',
    re.IGNORECASE,
)
# Pattern B: new IvParameterSpec(new byte[]{...}) 인라인 배열
_C_IV_BYTES_INLINE_RE = re.compile(
    r'new\s+IvParameterSpec\s*\(\s*new\s+byte\s*\[\s*\]\s*\{[^}]{4,}\}',
    re.IGNORECASE,
)
# Pattern C Step1: static final byte[] 상수 선언 (변수명 캡처)
_C_STATIC_IV_DECL_RE = re.compile(
    r'(?:static\s+final\s+|final\s+static\s+)(?:byte\s*\[\s*\]|byte\[\])\s+'
    r'(\w+)\s*=\s*\{([^}]{4,})\}',
    re.IGNORECASE,
)
# Pattern C Step2: IvParameterSpec(varName) 변수 참조
_C_IV_VAR_REF_RE = re.compile(
    r'new\s+IvParameterSpec\s*\(\s*([A-Za-z_]\w*)\s*\)',
    re.IGNORECASE,
)
# 안전 제외 — SecureRandom 기반 IV 생성
_C_SECURE_RANDOM_IV_RE = re.compile(
    r'SecureRandom[^;]{0,200}IvParameterSpec'
    r'|IvParameterSpec[^;]{0,200}SecureRandom'
    r'|\.nextBytes\s*\([^;]{0,100}IvParameterSpec',
    re.IGNORECASE | re.DOTALL,
)
# 배열 내용에 숫자 리터럴이 존재하는지 확인 (FP 방지: 메서드 호출 결과 등 제외)
_C_IV_NUMERIC_VALS_RE = re.compile(r'(?:0x[0-9A-Fa-f]{1,2}|\b\d{1,3}\b)')


# ── [J] JWT 검증 불완전 탐지 ────────────────────────────────────────────────

# parseUnsecuredClaims / parseClaimsJwt (서명 없는 파싱 — jjwt)
_J_PARSE_UNSIGNED_RE = re.compile(
    r'\.parseUnsecuredClaims\s*\(|\.parseClaimsJwt\s*\(',
    re.IGNORECASE,
)

# alg=none 허용: setAllowedAlgorithms, NONE 상수 사용
# ★ "none"\s*(?:,|\)) 패턴은 .orElse("none") 등에서 FP 발생 → 앞에 알고리즘 함수 컨텍스트 요구
_J_ALG_NONE_RE = re.compile(
    r'(?:SignatureAlgorithm\.NONE'
    r'|\.algorithm\s*\(\s*"none"\s*\)'   # algorithm("none") — 메서드 체인 한정
    r'|setAllowedAlgorithms.*NONE'
    r')',
    re.IGNORECASE,
)

# JWT 라이브러리 import 확인 (파일 수준 필터 — FP 방지)
_J_JWT_IMPORT_RE = re.compile(
    r'import\s+(?:io\.jsonwebtoken|com\.auth0\.jwt|org\.jose4j|'
    r'com\.nimbusds\.jwt|io\.fusionauth\.jwt)',
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

# ── [보완 3] Lombok @ToString PII 노출 탐지 ──────────────────────────────────
# 파일 내 @ToString 또는 @Data 존재 여부 확인 (클래스 레벨 toString() 생성 트리거)
# ★ @Value 제외: Spring @Value("${...}")는 필드/메서드 레벨 어노테이션으로 toString() 생성 안 함.
#   Lombok @Value(클래스 레벨)는 @Value 단독 또는 @Value(staticConstructor=...) 형태이나,
#   실무에서 Spring @Value와 혼재 시 오탐 유발 → @ToString/@Data 로만 감지.
_D_TOSTRING_ANNOT_RE = re.compile(r'@(?:ToString|Data)\b')
# 안전 처리: @ToString(exclude=...) 또는 onlyExplicitlyIncluded=true
_D_TOSTRING_SAFE_RE = re.compile(
    r'@ToString\s*\([^)]*(?:exclude\s*=|onlyExplicitlyIncluded\s*=\s*true)[^)]*\)',
    re.IGNORECASE,
)
# @ToString(exclude={"field1","field2"}) 에서 필드명 추출
_D_TOSTRING_EXCLUDE_LIST_RE = re.compile(
    r'@ToString\s*\([^)]*exclude\s*=\s*\{([^}]+)\}',
    re.IGNORECASE,
)
# 필드 레벨 @ToString.Exclude
_D_TOSTRING_FIELD_EXCL_RE = re.compile(r'@ToString\.Exclude\b')
# 클래스 선언 전 N줄 내에 @ToString/@Data가 있는지 확인용 (per-class context)
_D_CLASS_DECL_RE = re.compile(
    r'(?:@ToString\b|@Data\b)[^\n]*(?:\n[^\n]*){0,8}(?:public|protected|private|abstract|final|\s)+class\s+',
    re.MULTILINE,
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
    """프로퍼티/YAML 파일 이터레이터 (모든 *.properties / *.yml / *.yaml 포함)"""
    for pat in ("*.properties", "*.yml", "*.yaml"):
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

        # [보완 1] Base64 인코딩 시크릿
        # - 변수명 컨텍스트(hmacKey, authKey, signingKey 등) + Base64 특성 문자(+,/,=) 필수
        # - 기존 JWT/AWS/GENERIC 패턴과 중복 방지: 동일 줄에서 이미 탐지됐으면 skip
        already_flagged_lines: set[int] = set()
        for m in _S_JWT_SECRET_RE.finditer(content):
            already_flagged_lines.add(_line_of(content, m.start()))
        for m in _S_AWS_SECRET_RE.finditer(content):
            already_flagged_lines.add(_line_of(content, m.start()))

        for m in _S_BASE64_SECRET_NAMES_RE.finditer(content):
            ln = _line_of(content, m.start())
            if ln in safe_lines or ln in already_flagged_lines:
                continue
            val = m.group(1)
            # Base64 특성 문자(+, /, 패딩=) 없으면 일반 alphanumeric — 기존 패턴에서 처리
            if not _S_BASE64_CHARS_RE.search(val):
                continue
            _add("HARDCODED_SECRET",
                 "Info" if is_test else "High",
                 "Base64 인코딩 시크릿 하드코딩",
                 (f"Base64 인코딩된 시크릿이 소스코드에 하드코딩됨 ({len(val)}자). "
                  f"디코딩 시 원본 키 복원 가능. 운영 키 여부 추가 확인 필요."),
                 rel, ln, _snippet(content, m.start()),
                 "CWE-798", "A02:2021 Cryptographic Failures",
                 "@Value(\"${key.property}\") 참조 + Jasypt ENC(...) 암호화 또는 Vault/KMS 이관.",
                 result="정보" if is_test else "취약",
                 needs_review=True)

    # ── 프로퍼티/YAML 파일 스캔 ─────────────────────────────────
    # i18n / 예외 메시지 파일 판별: 파일명에 message/error/exception/locale 포함 시 FP 제외 대상
    _I18N_NAME_RE = re.compile(
        r'(?i)(message|error|exception|locale|label|text|notice|alert|mail_template)',
    )

    def _is_i18n_props_value(val: str) -> bool:
        """프로퍼티 값이 i18n 안내 문구(FP)인지 판별.

        다음 조건 중 하나라도 해당하면 오탐(FP)으로 처리:
        1. 한글 유니코드 이스케이프 패턴(\\uXXXX) 포함 — 단순 UI 메시지
        2. 공백 2개 이상인 문장형 문자열 — 설명 문구
        3. 한글 문자(가-힣) 직접 포함 — 사용자 안내 메시지
        4. 마침표/물음표/느낌표로 끝나는 자연어 문장
        """
        # 1) 유니코드 이스케이프 (\uXXXX) 포함
        if re.search(r'\\u[0-9A-Fa-f]{4}', val):
            return True
        # 2) 공백 2개 이상 (문장형)
        if val.count(' ') >= 2:
            return True
        # 3) 한글 직접 포함
        if re.search(r'[\uAC00-\uD7A3]', val):
            return True
        # 4) 자연어 문장 종결 (마침표/느낌표/물음표로 끝남)
        if re.search(r'[.!?]$', val.strip()):
            return True
        return False

    for fp in _iter_props(source_dir):
        content = _read(fp)
        if not content:
            continue
        rel = _rel(fp, source_dir)

        # i18n / 메시지 파일 전체 스킵 (파일명 기반)
        if _I18N_NAME_RE.search(fp.stem):
            continue

        for m in _S_PROP_PASS_RE.finditer(content):
            ln = _line_of(content, m.start())
            val = m.group(1).strip('\'"')
            # 정규식 룩어헤드로 이미 대부분 걸러지지만 방어적 이중 체크
            if val.startswith(("${", "ENC(", "#{", "@{", "&", "*")):
                continue
            if re.match(r'^[<>\$\#@\{\[&\*]', val):
                continue
            # 너무 짧거나 변수명/키워드처럼 보이는 값은 제외 (false positive 방지)
            if len(val) < 4 or val.lower() in ("true", "false", "null", "none", ""):
                continue
            # i18n 안내 문구 FP 제거 (유니코드 이스케이프, 문장형, 한글, 자연어 종결)
            if _is_i18n_props_value(val):
                continue
            _add("HARDCODED_SECRET",
                 "High",
                 "설정 파일 내 비밀번호/시크릿/토큰 평문",
                 (f"설정 파일({fp.name})에 password/secret/token 값이 환경변수 참조나 "
                  f"암호화(ENC(...)) 없이 평문으로 저장됨."),
                 rel, ln, "****" + " (마스킹)",
                 "CWE-312", "A02:2021 Cryptographic Failures",
                 "Spring Cloud Config Vault 또는 Jasypt 암호화(ENC(...)) 적용. "
                 "또는 ${ENV_VAR} 환경변수 참조로 교체.",
                 needs_review=True)

    return findings


# ============================================================
#  5. [L] 민감정보 로깅 스캔
# ============================================================

def scan_sensitive_logging(source_dir: Path) -> list[DPFinding]:
    """민감정보 로깅 탐지.

    [그룹화] 동일 파일 내 복수 로그 취약점은 파일당 1개 Finding으로 묶음.
    vulnerable_lines 배열에 해당 라인 번호 전체를 기록하여 리포트 도배 방지.
    [레벨 차등화]
      info/warn/error/fatal → result="취약", severity="High"  (상용 환경 노출 위험)
      debug/trace           → result="정보", severity="Low"   (개발/검증계 노출 위험)
      System.out            → result="정보", severity="Info"
    """
    findings: list[DPFinding] = []
    counter = [0]

    # file_rel → bucket("high"/"low"/"sysout"/"masked") → [(line_no, snippet), ...]
    file_hits: dict[str, dict[str, list]] = defaultdict(lambda: defaultdict(list))

    for fp in _iter_sources(source_dir):
        content = _read(fp)
        if not content:
            continue
        rel = _rel(fp, source_dir)
        lines_list = content.splitlines()

        for i, line in enumerate(lines_list, 1):
            stripped = line.strip()
            if stripped.startswith(("//", "*", "/*", "#")):
                continue

            # 패턴 매칭 — 레벨 구분
            if _L_SYSOUT_PII_RE.search(line):
                bucket = "sysout"
            elif _L_LOG_PII_HIGH_RE.search(line) or _L_LOG_PARAM_BIND_HIGH_RE.search(line):
                bucket = "high"
            elif _L_LOG_PII_LOW_RE.search(line) or _L_LOG_PARAM_BIND_LOW_RE.search(line):
                bucket = "low"
            else:
                continue

            # 같은 줄에 마스킹 유틸 → masked 버킷으로
            if _L_MASKING_SAFE_RE.search(line):
                file_hits[rel]["masked"].append((i, stripped[:120]))
                continue

            # 앞뒤 2줄 컨텍스트 마스킹 → 버킷 강등
            ctx_start = max(0, i - 3)
            ctx_end   = min(len(lines_list), i + 2)
            ctx = "\n".join(lines_list[ctx_start:ctx_end])
            if _L_MASKING_SAFE_RE.search(ctx):
                file_hits[rel]["masked"].append((i, stripped[:120]))
                continue

            # FP 필터: 보호 필수 변수 없이 허용 목록 변수만 있는 라인 → masked(FP) 처리
            if bucket in ("high", "low") and not _has_protected_log_param(line):
                file_hits[rel]["masked"].append((i, stripped[:120]))
                continue

            file_hits[rel][bucket].append((i, stripped[:120]))

    # ── 파일 단위 Finding 생성 ────────────────────────────────────
    _REC = (
        "1. [필수 마스킹 대상] mbrId, authToken, kmcResult, webTokenInfo, encryptData 등 핵심 식별자·인증 토큰·개인정보 포함 객체는 "
        "로그 레벨에 관계없이 반드시 MaskingUtils.mask() 또는 동등한 유틸로 마스킹 처리 필수.\n"
        "2. [허용 목록] userId, feedId, feedSeq 등 내부 추적용 식별자는 단독 출력 시 허용 — mbrId 등 보호 필수 항목과 결합 출력 시에는 마스킹 필요.\n"
        "3. 운영 환경 로그 레벨을 INFO 이상으로 설정하고 DEBUG 로그 비활성화.\n"
        "4. Logback MessageConverter 커스텀 구현으로 전역 자동 마스킹 아키텍처 도입 권장.\n"
        "5. 로그 집계 시스템(ELK 등)의 접근 제어 강화."
    )

    for rel, buckets in file_hits.items():
        # High — info/warn/error/fatal 평문 노출 (취약)
        if "high" in buckets:
            hits = buckets["high"]
            line_nos = [t[0] for t in hits]
            first_ln, first_snip = hits[0]
            counter[0] += 1
            findings.append(DPFinding(
                finding_id=_make_id("SENSITIVE_LOGGING", counter[0]),
                category="SENSITIVE_LOGGING",
                severity="Critical",
                title=f"민감정보 로그 노출 — {len(hits)}건 ({rel.split('/')[-1]})",
                description=(
                    f"info/warn/error/fatal 레벨 로그에 민감정보(mbrId, email, accessToken 등)가 "
                    f"마스킹 없이 출력됨. 상용 환경 로그 파일 접근자에게 개인정보 노출 가능. "
                    f"({len(hits)}개 라인 — 상세 위치는 vulnerable_lines 참조)"
                ),
                file=rel, line=first_ln,
                code_snippet=first_snip,
                cwe_id="CWE-532",
                owasp_category="A09:2021 Security Logging and Monitoring Failures",
                recommendation=_REC,
                result="취약",
                needs_review=False,
                evidence={"vulnerable_lines": line_nos, "sample_count": len(hits)},
            ))

        # Low — debug/trace 노출 (정보)
        if "low" in buckets:
            hits = buckets["low"]
            line_nos = [t[0] for t in hits]
            first_ln, first_snip = hits[0]
            counter[0] += 1
            findings.append(DPFinding(
                finding_id=_make_id("SENSITIVE_LOGGING", counter[0]),
                category="SENSITIVE_LOGGING",
                severity="Medium",
                title=f"민감정보 로깅 (debug/trace, 수동확인) — {len(hits)}건 ({rel.split('/')[-1]})",
                description=(
                    f"debug/trace 레벨 로그에 민감정보가 포함됨. "
                    f"상용 환경에서는 출력되지 않으나 개발·검증계 로그 노출 위험. "
                    f"({len(hits)}개 라인 — 상세 위치는 vulnerable_lines 참조)"
                ),
                file=rel, line=first_ln,
                code_snippet=first_snip,
                cwe_id="CWE-532",
                owasp_category="A09:2021 Security Logging and Monitoring Failures",
                recommendation="개발계 로그에서도 PII 마스킹 적용 권장. 운영 프로파일 로그 레벨 확인.",
                result="정보",
                needs_review=True,
                evidence={"vulnerable_lines": line_nos, "sample_count": len(hits)},
            ))

        # Sysout — System.out PII (정보)
        if "sysout" in buckets:
            hits = buckets["sysout"]
            line_nos = [t[0] for t in hits]
            first_ln, first_snip = hits[0]
            counter[0] += 1
            findings.append(DPFinding(
                finding_id=_make_id("SENSITIVE_LOGGING", counter[0]),
                category="SENSITIVE_LOGGING",
                severity="Info",
                title=f"System.out 민감정보 직접 출력 — {len(hits)}건 ({rel.split('/')[-1]})",
                description=(
                    f"System.out.println으로 민감정보가 직접 출력됨. "
                    f"({len(hits)}개 라인 — 상세 위치는 vulnerable_lines 참조)"
                ),
                file=rel, line=first_ln,
                code_snippet=first_snip,
                cwe_id="CWE-532",
                owasp_category="A09:2021 Security Logging and Monitoring Failures",
                recommendation="System.out 제거 후 SLF4J Logger로 교체. PII는 마스킹 후 출력.",
                result="정보",
                needs_review=True,
                evidence={"vulnerable_lines": line_nos, "sample_count": len(hits)},
            ))

        # Masked — 마스킹 컨텍스트 근접 (정보, 수동확인)
        if "masked" in buckets:
            hits = buckets["masked"]
            line_nos = [t[0] for t in hits]
            first_ln, first_snip = hits[0]
            counter[0] += 1
            findings.append(DPFinding(
                finding_id=_make_id("SENSITIVE_LOGGING", counter[0]),
                category="SENSITIVE_LOGGING",
                severity="Info",
                title=f"민감정보 로깅 (마스킹 유틸 근접 확인 필요) — {len(hits)}건 ({rel.split('/')[-1]})",
                description=(
                    "로그 구문에 민감정보가 포함되나 근접 컨텍스트에서 마스킹 유틸 호출 확인. "
                    "실제 마스킹이 해당 변수에 적용되었는지 수동 확인 필요."
                ),
                file=rel, line=first_ln,
                code_snippet=first_snip,
                cwe_id="CWE-532",
                owasp_category="A09:2021 Security Logging and Monitoring Failures",
                recommendation='log.info("val={}", MaskingUtils.mask(pii)) 형태로 마스킹 인수가 직접 전달되는지 확인.',
                result="정보",
                needs_review=True,
                evidence={"vulnerable_lines": line_nos, "sample_count": len(hits)},
            ))

    return findings


# ============================================================
#  6. [C] 취약 암호화 알고리즘 스캔
# ============================================================

def scan_weak_crypto(source_dir: Path) -> list[DPFinding]:
    findings: list[DPFinding] = []
    counter = [0]

    CRYPTO_CHECKS = [
        (_C_WEAK_DIGEST_RE,      "Medium", "취약한 해시 알고리즘 사용",
         "MD5/SHA-1은 충돌 공격에 취약한 알고리즘입니다. 패스워드 해시나 무결성 검증에 사용 시 즉시 취약.",
         "CWE-327", "A02:2021 Cryptographic Failures",
         "SHA-256 이상(SHA-256/384/512) 또는 bcrypt/Argon2(패스워드용)로 교체."),
        (_C_WEAK_CIPHER_RE,      "Medium", "취약한 대칭 암호화 알고리즘/모드 사용",
         "DES/3DES/RC4는 알려진 취약점이 있으며, ECB 모드는 패턴 노출 취약점이 있습니다.",
         "CWE-327", "A02:2021 Cryptographic Failures",
         "AES-256-GCM 또는 AES-256-CBC(PKCS5Padding)로 교체. ECB 모드는 GCM으로 대체."),
        (_C_WEAK_KEYGEN_RE,      "Medium", "취약한 KeyGenerator 알고리즘",
         "DES/RC4 KeyGenerator 사용. 생성된 키는 취약한 암호화에만 사용 가능.",
         "CWE-327", "A02:2021 Cryptographic Failures",
         "AES KeyGenerator(256비트)로 교체."),
        (_C_DIGEST_UTILS_MD5_RE, "Medium", "DigestUtils/Hashing MD5 직접 사용",
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

        # [보완 2] 하드코딩 IV(초기화 벡터) 탐지
        # SecureRandom 기반 IV 생성이 있는 파일은 전체 skip (안전)
        if _C_SECURE_RANDOM_IV_RE.search(content):
            continue

        _IV_REC = (
            "SecureRandom을 사용하여 매 암호화마다 고유한 IV를 생성하세요:\n"
            "  byte[] iv = new byte[16];\n"
            "  new SecureRandom().nextBytes(iv);\n"
            "  new IvParameterSpec(iv);\n"
            "고정 IV 사용은 동일 키+IV 조합 반복으로 암호문 패턴 노출 취약점을 유발합니다."
        )

        # Pattern A: IvParameterSpec("literal".getBytes())
        for m in _C_IV_STRING_RE.finditer(content):
            ln = _line_of(content, m.start())
            snip = _snippet(content, m.start())
            if snip.lstrip().startswith(("//", "*", "/*")):
                continue
            counter[0] += 1
            findings.append(DPFinding(
                finding_id=_make_id("WEAK_CRYPTO", counter[0]),
                category="WEAK_CRYPTO",
                severity="High",
                title="하드코딩 IV — 문자열 리터럴 직접 사용",
                description=(
                    f"IvParameterSpec에 문자열 리터럴 \"{m.group(1)[:20]}...\"을 "
                    ".getBytes()로 변환하여 고정 IV로 사용. "
                    "동일 키+IV 조합 반복 시 CBC 모드에서 암호문 패턴이 노출되어 "
                    "Known-plaintext 공격에 취약합니다."
                ),
                file=rel, line=ln, code_snippet=snip,
                cwe_id="CWE-329",
                owasp_category="A02:2021 Cryptographic Failures",
                recommendation=_IV_REC,
                result="취약",
                needs_review=False,
            ))

        # Pattern B: IvParameterSpec(new byte[]{0x00, 0x01, ...})
        for m in _C_IV_BYTES_INLINE_RE.finditer(content):
            ln = _line_of(content, m.start())
            snip = _snippet(content, m.start())
            if snip.lstrip().startswith(("//", "*", "/*")):
                continue
            # 배열 내용에 숫자 리터럴이 없으면 skip (메서드 호출 결과일 가능성)
            array_body_m = re.search(r'\{([^}]+)\}', m.group())
            if not array_body_m or not _C_IV_NUMERIC_VALS_RE.search(array_body_m.group(1)):
                continue
            counter[0] += 1
            findings.append(DPFinding(
                finding_id=_make_id("WEAK_CRYPTO", counter[0]),
                category="WEAK_CRYPTO",
                severity="High",
                title="하드코딩 IV — 인라인 byte[] 리터럴 직접 사용",
                description=(
                    "IvParameterSpec에 고정 byte[] 배열 리터럴을 직접 전달. "
                    "IV가 매 암호화마다 동일하여 암호문 패턴 노출 위험."
                ),
                file=rel, line=ln, code_snippet=snip,
                cwe_id="CWE-329",
                owasp_category="A02:2021 Cryptographic Failures",
                recommendation=_IV_REC,
                result="취약",
                needs_review=False,
            ))

        # Pattern C: static final byte[] IV_BYTES = {...} + IvParameterSpec(IV_BYTES)
        static_iv_vars: dict[str, int] = {}
        for m in _C_STATIC_IV_DECL_RE.finditer(content):
            var_name = m.group(1)
            arr_body = m.group(2)
            # 배열 내용에 숫자 리터럴이 있어야 상수 배열로 판단
            if _C_IV_NUMERIC_VALS_RE.search(arr_body):
                static_iv_vars[var_name] = _line_of(content, m.start())

        if static_iv_vars:
            for m in _C_IV_VAR_REF_RE.finditer(content):
                var_name = m.group(1)
                if var_name not in static_iv_vars:
                    continue
                ln = _line_of(content, m.start())
                snip = _snippet(content, m.start())
                if snip.lstrip().startswith(("//", "*", "/*")):
                    continue
                counter[0] += 1
                findings.append(DPFinding(
                    finding_id=_make_id("WEAK_CRYPTO", counter[0]),
                    category="WEAK_CRYPTO",
                    severity="Medium",
                    title=f"하드코딩 IV — static final 상수 참조 ({var_name})",
                    description=(
                        f"IvParameterSpec에 static final byte[] 상수({var_name}, "
                        f"선언 {static_iv_vars[var_name]}번 줄)를 참조. "
                        "상수 IV는 매 암호화마다 동일하여 반복 패턴 노출 위험. "
                        "FP 가능성: 해당 배열이 외부에서 주입된 경우 수동 확인 필요."
                    ),
                    file=rel, line=ln, code_snippet=snip,
                    cwe_id="CWE-329",
                    owasp_category="A02:2021 Cryptographic Failures",
                    recommendation=_IV_REC,
                    result="취약",
                    needs_review=True,
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
        # JWT 라이브러리 import 없는 파일 제외 — FP 방지
        if not _J_JWT_IMPORT_RE.search(content):
            continue
        rel = _rel(fp, source_dir)

        # parseUnsecuredClaims
        for m in _J_PARSE_UNSIGNED_RE.finditer(content):
            ln = _line_of(content, m.start())
            counter[0] += 1
            findings.append(DPFinding(
                finding_id=_make_id("JWT_INCOMPLETE", counter[0]),
                category="JWT_INCOMPLETE",
                severity="Critical",
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
                severity="Critical",
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

def _build_handler_index(api_inventory: dict) -> dict[str, list[dict]]:
    """API 인벤토리에서 handler 문자열 → 엔드포인트 목록 인덱스 구축."""
    idx: dict[str, list[dict]] = {}
    for ep in api_inventory.get("endpoints", []):
        handler = ep.get("handler", "")
        if handler:
            idx.setdefault(handler, []).append(ep)
    return idx


def _classify_endpoint_type(ep: dict) -> str:
    """엔드포인트 유형 분류: external / admin / internal / consumer."""
    file_path = ep.get("file", "")
    api_path = ep.get("api", "")
    if "oki-admin-rest-api" in file_path:
        return "admin"
    if re.search(r"/internal/|/s2s/|/server/|/batch/", api_path):
        return "internal"
    if "consumer" in file_path.lower() or "batch" in file_path.lower():
        return "consumer"
    return "external"


def _extract_ctrl_methods_using_dto(content: str, dto_class: str) -> list[str]:
    """컨트롤러 파일에서 dto_class를 HTTP 응답/요청으로 사용하는 public 메서드 이름 목록 반환.

    두 가지 케이스를 탐지:
    1. 메서드 반환 타입 선언에 dto_class가 포함된 경우 (신뢰성 높음)
       예: public ResponseEntity<ApiResponse<UserInfoResponse>> getInfo(...)
    2. @RequestBody 파라미터로 dto_class를 받는 경우 (요청 DTO 노출)
       예: public ... method(@RequestBody UserInfoRequest req)

    단순 메서드 바디 내 변수 선언/사용은 제외 (FP 방지).
    네스티드 제네릭 처리: 메서드명 추출 후 반환 타입 구간에 DTO 이름 존재 여부 확인.
    """
    _dto_word_re = re.compile(r'\b' + re.escape(dto_class) + r'\b')

    # 메서드 시그니처 전체 파싱:
    # - 반환 타입 (제네릭 포함) + 메서드명 + '(' 까지 탐지
    # - 패턴: public/protected ... MethodName(
    _METH_SIG_RE = re.compile(
        r'^\s*(?:public|protected)\s+([\w<>\[\],\s.]+?)\s+(\w+)\s*\(',
        re.MULTILINE,
    )
    # RequestBody 파라미터 탐지 (메서드 파라미터 내에서)
    _REQ_BODY_RE = re.compile(
        r'@RequestBody\s+(?:\w+\s+)*\b' + re.escape(dto_class) + r'\b',
    )

    method_names: list[str] = []
    seen: set[str] = set()

    # 메서드 시그니처 + 파라미터 범위를 한 번에 수집
    lines = content.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        sig_m = _METH_SIG_RE.match(line)
        if sig_m:
            return_type_str = sig_m.group(1)
            mname = sig_m.group(2)
            # 파라미터 범위: 시그니처 라인부터 ')' 닫힘까지 (보통 1~3줄)
            param_block = line
            j = i + 1
            while ')' not in param_block and j < min(i + 6, len(lines)):
                param_block += " " + lines[j]
                j += 1

            # Case 1: 반환 타입에 DTO 포함 여부
            if _dto_word_re.search(return_type_str) and mname not in seen:
                seen.add(mname)
                method_names.append(mname)
            # Case 2: @RequestBody 파라미터에 DTO 포함 여부
            elif _REQ_BODY_RE.search(param_block) and mname not in seen:
                seen.add(mname)
                method_names.append(mname)
        i += 1

    return method_names


def _find_endpoint_usages(
    dto_class: str,
    source_dir: Path,
    handler_idx: dict[str, list[dict]],
) -> list[dict]:
    """주어진 DTO 클래스를 사용하는 컨트롤러 엔드포인트 목록 반환."""
    matched_eps: list[dict] = []
    seen_handlers: set[str] = set()

    _CTRL_FILE_RE = re.compile(r'(?i)controller\.(java|kt)$')
    _CTRL_CLASS_RE = re.compile(r'class\s+(\w+)\b')

    # 단순 substring 매칭 대신 단어경계 패턴 사용 (AdminUserResponse ≠ UserResponse 오탐 방지)
    _dto_word_re = re.compile(r'\b' + re.escape(dto_class) + r'\b')

    for fp in _iter_sources(source_dir):
        if not _CTRL_FILE_RE.search(fp.name):
            continue
        content = _read(fp)
        if not content or not _dto_word_re.search(content):
            continue

        cls_m = _CTRL_CLASS_RE.search(content)
        if not cls_m:
            continue
        ctrl_class = cls_m.group(1)

        method_names = _extract_ctrl_methods_using_dto(content, dto_class)
        for mname in method_names:
            handler_key = f"{ctrl_class}.{mname}()"
            if handler_key in handler_idx and handler_key not in seen_handlers:
                seen_handlers.add(handler_key)
                for ep in handler_idx[handler_key]:
                    ep_type = _classify_endpoint_type(ep)
                    matched_eps.append({
                        "method": ep.get("method", ""),
                        "api": ep.get("api", ""),
                        "handler": handler_key,
                        "auth_required": ep.get("auth_required", False),
                        "endpoint_type": ep_type,
                        "file": ep.get("file", ""),
                    })

    return matched_eps


def scan_dto_exposure(source_dir: Path, api_inventory: Optional[dict] = None) -> list[DPFinding]:
    """Response DTO 내 민감 필드에 @JsonIgnore / 마스킹 어노테이션 누락 여부 탐지.

    api_inventory가 있으면 실제 API 엔드포인트로 역추적하여 엔드포인트 단위로 결과 출력.
    엔드포인트 매핑 불가(Consumer/내부 DTO 등)는 Info 처리 후 별도 요약.
    """
    # ── Step 1: DTO 파일에서 노출 필드 수집 ──────────────────────────────
    # dto_class → [(field_snippet, file, line, has_lombok)]
    dto_exposed: dict[str, list[tuple[str, str, int, bool]]] = {}

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
        rel = _rel(fp, source_dir)
        has_lombok = bool(_D_LOMBOK_GETTER_RE.search(content))

        lines_list = content.splitlines()
        for i, line in enumerate(lines_list, 1):
            if not _D_SENSITIVE_FIELD_NAMES_RE.search(line):
                continue
            prev_ctx = "\n".join(lines_list[max(0, i - 4):i])
            if _D_JSON_IGNORE_RE.search(prev_ctx) or _D_MASKING_ANNOT_RE.search(prev_ctx):
                continue  # 보호 어노테이션 → 양호
            stripped = line.strip()[:120]
            dto_exposed.setdefault(class_name, []).append((stripped, rel, i, has_lombok))

    if not dto_exposed:
        return []

    # ── Step 2: 엔드포인트 매핑 ──────────────────────────────────────────
    handler_idx: dict[str, list[dict]] = {}
    if api_inventory:
        handler_idx = _build_handler_index(api_inventory)

    # endpoint_key → {"eps": [...], "dto_fields": [(dto_class, field_snippet, file, line)]}
    ep_map: dict[str, dict] = {}
    unmapped_dto_fields: list[tuple[str, str, str, int, bool]] = []  # (cls, field, file, line, has_lombok)

    for dto_class, field_list in dto_exposed.items():
        if handler_idx:
            ep_list = _find_endpoint_usages(dto_class, source_dir, handler_idx)
        else:
            ep_list = []

        if ep_list:
            for ep in ep_list:
                key = ep["handler"] + "|" + ep["api"]
                if key not in ep_map:
                    ep_map[key] = {"ep": ep, "dto_fields": []}
                for field_snip, file_, line_, has_lombok_ in field_list:
                    ep_map[key]["dto_fields"].append(
                        (dto_class, field_snip, file_, line_, has_lombok_)
                    )
        else:
            for field_snip, file_, line_, has_lombok_ in field_list:
                unmapped_dto_fields.append((dto_class, field_snip, file_, line_, has_lombok_))

    # ── Step 3: 엔드포인트 단위 Finding 생성 ─────────────────────────────
    findings: list[DPFinding] = []
    counter = [0]

    _EP_TYPE_LABEL = {
        "external": "외부 API",
        "admin": "관리자 API",
        "internal": "내부/S2S API",
        "consumer": "컨슈머(비HTTP)",
    }

    # Safe-by-Design 필드 패턴: 토큰/인증 엔드포인트에서 반환 목적 필드
    _TOKEN_EP_RE = re.compile(r'/token|/auth|/login|/logout', re.IGNORECASE)
    _TOKEN_FIELD_RE = re.compile(r'(?i)(accessToken|refreshToken|idToken|jwtToken)\b')

    for key, info in ep_map.items():
        ep = info["ep"]
        fields = info["dto_fields"]
        ep_type = ep["endpoint_type"]
        auth_req = ep["auth_required"]
        api_path = ep.get("api", "")

        # Safe-by-Design 판정: 토큰 엔드포인트에서 accessToken/refreshToken만 노출되는 경우
        field_names = {f[1].split()[-1].rstrip(";") for f in fields}
        is_token_endpoint = bool(_TOKEN_EP_RE.search(api_path))
        all_fields_are_token_fields = all(
            bool(_TOKEN_FIELD_RE.search(fn)) for fn in field_names
        )
        safe_by_design = is_token_endpoint and all_fields_are_token_fields

        if safe_by_design:
            sev = "Info"
            result = "정보"
        # severity: external + no_auth → High, external + auth → Medium, admin → Medium, internal → Info
        elif ep_type == "external" and not auth_req:
            sev = "High"
            result = "취약"
        elif ep_type == "external" and auth_req:
            sev = "Medium"
            result = "취약"
        elif ep_type == "admin":
            sev = "Medium"
            result = "정보"
        else:
            sev = "Info"
            result = "정보"

        # 노출 필드 요약
        field_summary = ", ".join(sorted(field_names))
        dto_classes_involved = sorted({f[0] for f in fields})
        ep_label = _EP_TYPE_LABEL.get(ep_type, ep_type)

        desc_lines = [
            f"[{ep_label}] {ep['method']} {ep['api']} 에서 민감 필드가 포함된 DTO가 응답으로 반환됩니다.",
            f"관련 DTO 클래스: {', '.join(dto_classes_involved)}",
            f"노출 민감 필드: {field_summary}",
        ]
        if safe_by_design:
            desc_lines.append("※ Safe by Design: 토큰 발급 엔드포인트의 토큰 필드 반환은 의도된 설계입니다.")
        elif not auth_req and ep_type == "external":
            desc_lines.append("인증(auth_required=false) 없이 접근 가능하여 즉시 조치가 필요합니다.")

        counter[0] += 1
        findings.append(DPFinding(
            finding_id=_make_id("DTO_EXPOSURE", counter[0]),
            category="DTO_EXPOSURE",
            severity=sev,
            title=f"민감 필드 노출 DTO — {ep['method']} {ep['api']} ({field_summary})",
            description="\n".join(desc_lines),
            file=fields[0][2] if fields else "",
            line=fields[0][3] if fields else 0,
            code_snippet=fields[0][1] if fields else "",
            cwe_id="CWE-200",
            owasp_category="A01:2021 Broken Access Control",
            recommendation=(
                "1. 응답 DTO에서 불필요한 민감 필드는 @JsonIgnore 적용.\n"
                "2. 마스킹이 필요한 경우 @JsonSerialize(using = MaskingSerializer.class) 적용.\n"
                "3. 응답 전용 DTO를 별도로 정의하여 민감 필드를 제외할 것."
            ),
            result=result,
            needs_review=(ep_type == "admin"),
            evidence={
                "endpoint": {
                    "method": ep["method"],
                    "api": ep["api"],
                    "handler": ep["handler"],
                    "auth_required": auth_req,
                    "endpoint_type": ep_type,
                },
                "exposed_fields": [
                    {"dto_class": f[0], "field": f[1], "file": f[2], "line": f[3]}
                    for f in fields
                ],
            },
        ))

    # ── Step 4: 매핑 불가 DTO 필드 → 단일 요약 Finding ──────────────────
    if unmapped_dto_fields:
        cls_field_map: dict[str, list[str]] = {}
        for dto_cls, field_snip, file_, line_, _ in unmapped_dto_fields:
            cls_field_map.setdefault(dto_cls, []).append(field_snip.split()[-1].rstrip(";"))

        cls_summary = "; ".join(
            f"{cls}({', '.join(sorted(set(fs)))})" for cls, fs in sorted(cls_field_map.items())
        )
        counter[0] += 1
        findings.append(DPFinding(
            finding_id=_make_id("DTO_EXPOSURE", counter[0]),
            category="DTO_EXPOSURE",
            severity="Info",
            title=f"엔드포인트 매핑 불가 DTO 민감 필드 ({len(unmapped_dto_fields)}건) — FP 검토 필요",
            description=(
                f"HTTP 엔드포인트로 역추적되지 않은 DTO 클래스의 민감 필드 {len(unmapped_dto_fields)}건이 탐지됨.\n"
                "Consumer(Kafka/MQ), 내부 서비스 DTO, Redis 엔티티 등 HTTP 직렬화 경로 없는 경우 FP 가능성 높음.\n\n"
                f"대상: {cls_summary}"
            ),
            file=unmapped_dto_fields[0][2],
            line=unmapped_dto_fields[0][3],
            code_snippet=unmapped_dto_fields[0][1],
            cwe_id="CWE-200",
            owasp_category="A04:2021 Insecure Design",
            recommendation=(
                "1. 각 DTO가 HTTP 응답 직렬화 경로에 있는지 수동 확인.\n"
                "2. Consumer/내부 DTO는 조치 불필요(FP).\n"
                "3. 실제 응답에 사용되는 경우 @JsonIgnore 또는 별도 응답 DTO 분리."
            ),
            result="정보",
            needs_review=True,
            evidence={
                "unmapped_dtos": [
                    {"dto_class": f[0], "field": f[1], "file": f[2], "line": f[3]}
                    for f in unmapped_dto_fields
                ],
            },
        ))

    return findings


# ============================================================
#  8-2. [보완 3] Lombok @ToString PII 노출 스캔
# ============================================================

_CLS_DECL_SCAN_RE = re.compile(
    r'(?:public|protected|private|abstract|final|\s)+class\s+\w+',
    re.MULTILINE,
)


def _build_class_map(
    lines_list: list[str],
) -> tuple[list[int], list[tuple[bool, set[str], bool]]]:
    """파일 내 모든 class 선언을 단일 패스로 사전 스캔.

    O(N) 전처리 — scan_toString_exposure 내부 O(N²) 루프를 O(N log N) 으로 낮추기 위한
    bisect 인덱스 구조 반환.

    Returns:
        cls_lines : class 선언 줄 번호 목록 (0-indexed, 정렬됨) — bisect 키
        cls_meta  : 동일 인덱스의 (has_tostring, excluded_fields, has_safe_tostring) 튜플
    """
    content = "\n".join(lines_list)
    cls_lines: list[int] = []
    cls_meta: list[tuple[bool, set[str], bool]] = []

    for cm in _CLS_DECL_SCAN_RE.finditer(content):
        cls_line = content[: cm.start()].count("\n")  # 0-indexed
        # ★ lookback 하한: 이전 class 선언 다음 줄 — class 경계를 넘어 이전 클래스의
        #   @ToString 어노테이션을 가져오는 FP 방지 (다중 클래스 파일 대응)
        prev_bound = cls_lines[-1] + 1 if cls_lines else 0
        annot_start = max(prev_bound, cls_line - 15)
        annot_ctx = "\n".join(lines_list[annot_start : cls_line + 1])
        has_ts = bool(_D_TOSTRING_ANNOT_RE.search(annot_ctx))
        has_safe = bool(_D_TOSTRING_SAFE_RE.search(annot_ctx))
        excl_m = _D_TOSTRING_EXCLUDE_LIST_RE.search(annot_ctx)
        excluded: set[str] = set(re.findall(r'"(\w+)"', excl_m.group(1))) if excl_m else set()
        cls_lines.append(cls_line)
        cls_meta.append((has_ts, excluded, has_safe))

    return cls_lines, cls_meta  # finditer 순서 = 문서 순서 = 이미 정렬됨


def scan_toString_exposure(source_dir: Path) -> list[DPFinding]:
    """Lombok @ToString / @Data 사용 클래스에서 PII 필드 @ToString.Exclude 미처리 탐지.

    @JsonIgnore는 JSON 직렬화만 차단하며 toString() 출력은 막지 못함.
    log.info("request: {}", dto) 호출 시 toString()이 호출되어 PII가 로그에 노출 가능.

    FP 방지:
    - @ToString(exclude = {"fieldName"}) 에 해당 필드가 포함된 경우 → 양호
    - @ToString(onlyExplicitlyIncluded = true) → 양호
    - 필드 레벨 @ToString.Exclude → 양호
    - @Data 없이 @JsonIgnore만 있는 경우 → @Getter가 없으면 toString FP 아님 → 체크
    """
    findings: list[DPFinding] = []
    counter = [0]

    for fp in _iter_sources(source_dir):
        content = _read(fp)
        if not content:
            continue
        # @ToString 또는 @Data (클래스 레벨 toString 생성 트리거) 없으면 skip
        # ★ Spring @Value("${...}")는 포함 안 함 (필드 레벨 — toString 생성 안 함)
        if not _D_TOSTRING_ANNOT_RE.search(content):
            continue

        # 추가 검증: @ToString/@Data가 실제 class 선언 앞에 있는지 확인
        # → 파일 내 @ToString 존재 + class 선언 근접 여부 (FP 방지)
        if not _D_CLASS_DECL_RE.search(content):
            # @ToString/@Data가 있지만 class 선언 앞에 없는 경우 (인터페이스 등) skip
            continue

        rel = _rel(fp, source_dir)
        lines_list = content.splitlines()

        # ── O(N) 사전 계산: 파일 내 모든 class 선언 위치와 @ToString 메타데이터 ──────────────
        # class_map 구조: cls_lines[k] = 클래스 선언 줄(0-indexed), cls_meta[k] = (has_ts, excluded, has_safe)
        # 이후 per-field 탐색은 bisect.bisect_right → O(log N) → 전체 O(N log N) (구버전 O(N²) 대비)
        cls_lines, cls_meta = _build_class_map(lines_list)

        for i, line in enumerate(lines_list):  # i: 0-indexed
            stripped = line.strip()
            if stripped.startswith(("//", "*", "/*")):
                continue
            if not _D_SENSITIVE_FIELD_NAMES_RE.search(line):
                continue

            # 필드명 추출
            field_name_m = re.search(
                r'(?:private|protected|public|var|val)\s+\S+\s+(\w+)\s*[;,=)]',
                line,
            )
            field_name = field_name_m.group(1) if field_name_m else None

            # ── O(log N) 이분탐색: 해당 필드를 감싸는 가장 최근 class 선언 탐색 ──────────────
            # bisect_right(cls_lines, i) - 1 → i(현재 줄) 이하 최대 class 선언 인덱스
            idx = bisect.bisect_right(cls_lines, i) - 1
            if idx < 0:
                continue  # class 선언보다 앞에 있는 필드 (정상적 Java에서 없어야 함)
            has_ts, excluded_by_class, has_safe_tostring = cls_meta[idx]
            if not has_ts:
                continue  # 해당 클래스에 @ToString/@Data 없음 → FP 방지

            # 클래스 레벨 onlyExplicitlyIncluded=true → 명시 필드만 출력 → 양호
            if has_safe_tostring:
                continue

            # 클래스 레벨 exclude 목록에 이 필드가 있는지 확인
            if field_name and field_name in excluded_by_class:
                continue

            # 필드 바로 앞 3줄에서 @ToString.Exclude 확인 (i: 0-indexed → slice 그대로 사용)
            prev_ctx = "\n".join(lines_list[max(0, i - 3):i])
            if _D_TOSTRING_FIELD_EXCL_RE.search(prev_ctx):
                continue  # 필드 레벨 제외 → 양호

            # @JsonIgnore / @JsonProperty 는 toString 차단 불가 → 여전히 취약

            counter[0] += 1
            findings.append(DPFinding(
                finding_id=_make_id("DTO_EXPOSURE", counter[0]),
                category="DTO_EXPOSURE",
                severity="Medium",
                title=f"Lombok @ToString 민감정보 필드 노출 — @ToString.Exclude 미처리 ({rel.split('/')[-1]})",
                description=(
                    f"@ToString/@Data 사용 클래스에 PII 필드"
                    f"({field_name or stripped[:30]})가 포함되어 "
                    "toString() 호출 시 민감정보가 평문으로 로그에 노출될 수 있음. "
                    "@JsonIgnore는 JSON 직렬화만 차단하며 toString() 출력을 막지 못함."
                ),
                file=rel, line=i + 1,  # 사용자 표시용 1-indexed 줄 번호
                code_snippet=stripped[:120],
                cwe_id="CWE-532",
                owasp_category="A09:2021 Security Logging and Monitoring Failures",
                recommendation=(
                    "1. 필드 레벨: @ToString.Exclude 추가.\n"
                    "2. 클래스 레벨: @ToString(exclude = {\"" + (field_name or "fieldName") + "\"}) 설정.\n"
                    "3. 또는 @ToString(onlyExplicitlyIncluded = true) + 노출 허용 필드에만 @ToString.Include 명시.\n"
                    "4. @Data 대신 @Getter + 명시적 toString() 오버라이드 권장."
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
                        severity="Medium",
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
                    severity="Medium",
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
                        choices=["secret", "logging", "crypto", "jwt", "dto", "tostring", "cors", "header"],
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

    if "tostring" not in skip:
        print("  [D+] Lombok @ToString PII 노출 스캔...")
        all_findings.extend(scan_toString_exposure(source_dir))

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
