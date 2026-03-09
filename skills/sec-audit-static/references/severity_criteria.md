# Severity Criteria — 취약점 위험도 등급 기준

> **출처**: 사내 애플리케이션 보안 취약점 평가 기준 (웹/모바일/HTS) — 공식 기준서
> **적용 범위**: sec-audit-static 진단 결과 전체 (자동 스캔 + LLM 보완)

---

## 등급 정의

| 등급 | 영문 | 설명 |
|------|------|------|
| **Risk 5** | Critical | 즉각적인 시스템 침해 또는 대규모 데이터 유출로 이어질 수 있는 취약점 |
| **Risk 4** | High    | 인증 우회, 세션 탈취, 악의적 콘텐츠 삽입 등 심각한 피해 가능 |
| **Risk 3** | Medium  | 암호화 약점, 설정 오류 등 조건부 악용 가능 취약점 |
| **Risk 2** | Low     | 제한적인 조건에서만 악용 가능하거나 영향 범위가 좁은 취약점 |
| **Risk 1** | Info    | 즉각적인 위험은 없으나 보안 강화 권고 대상 |

---

## 취약점 유형별 등급 매핑

### Risk 5 (Critical)

| 취약점 유형 | 스크립트 / 카테고리 | severity 값 |
|------------|-------------------|-------------|
| SQL Injection — [실제] 확인 | scan_injection_enhanced.py | `Risk 5` |
| OS Command Injection | scan_injection_enhanced.py (global_findings) | `Risk 5` |
| SSI Injection | scan_injection_enhanced.py (global_findings) | `Risk 5` |
| 악성파일 업로드 (UUID+ExtWL 모두 미적용) | scan_file_processing.py / UPLOAD | `Critical` |
| 파일 다운로드 / LFI (Path Traversal) | scan_file_processing.py / DOWNLOAD | `Critical` |
| 민감정보 평문 로깅 (info/warn/error/fatal) | scan_data_protection.py / SENSITIVE_LOGGING | `Critical` |
| JWT Algorithm NONE 허용 | scan_data_protection.py / JWT_INCOMPLETE | `Critical` |
| AWS/GCP 클라우드 키 하드코딩 | scan_data_protection.py / HARDCODED_SECRET | `Critical` |
| NoOpPasswordEncoder / Md5PasswordEncoder | scan_data_protection.py / WEAK_CRYPTO | `Critical` |

### Risk 4 (High)

| 취약점 유형 | 스크립트 / 카테고리 | severity 값 |
|------------|-------------------|-------------|
| SQL Injection — [잠재] (수동확인 필요) | scan_injection_enhanced.py | `Risk 4` |
| XSS (Persistent / Reflected / DOM) | scan_xss.py | `High` |
| Open Redirect | scan_xss.py | `High` |
| RFI / SSRF | scan_file_processing.py / RFI | `High` |
| DB 비밀번호 하드코딩 | scan_data_protection.py / HARDCODED_SECRET | `High` |
| JWT Secret Key 하드코딩 | scan_data_protection.py / HARDCODED_SECRET | `High` |
| JWT 서명 키 미설정 파서 | scan_data_protection.py / JWT_INCOMPLETE | `High` |
| JWT parseUnsecuredClaims() 사용 | scan_data_protection.py / JWT_INCOMPLETE | `Critical`* |
| DTO 민감 필드 @JsonIgnore 미적용 (Lombok) | scan_data_protection.py / DTO_EXPOSURE | `High` |

> \* parseUnsecuredClaims()는 인증 완전 우회 → Critical로 격상

### Risk 3 (Medium)

| 취약점 유형 | 스크립트 / 카테고리 | severity 값 |
|------------|-------------------|-------------|
| 취약 암호 알고리즘 (MD5/SHA-1/DES/RC4/ECB) | scan_data_protection.py / WEAK_CRYPTO | `Medium` |
| CORS allowedOrigins(*) + allowCredentials(true) | scan_data_protection.py / CORS_MISCONFIG | `Medium` |
| CORS Origin 헤더 그대로 반영 | scan_data_protection.py / CORS_MISCONFIG | `Medium` |
| @CrossOrigin 와일드카드 기본값 | scan_data_protection.py / CORS_MISCONFIG | `Medium` |
| 보안 헤더 비활성화 (.headers().disable() 등) | scan_data_protection.py / SECURITY_HEADER | `Medium` |
| 민감정보 로깅 (debug/trace 레벨) | scan_data_protection.py / SENSITIVE_LOGGING | `Medium` |
| JWT 클럭 스큐 과도 설정 | scan_data_protection.py / JWT_INCOMPLETE | `Medium` |
| 파일 업로드 일부 검증 미흡 (부분 누락) | scan_file_processing.py / UPLOAD | `Medium` |
| DTO 민감 필드 @JsonIgnore 미적용 (Lombok 없음) | scan_data_protection.py / DTO_EXPOSURE | `Medium` |

### Risk 2 (Low)

| 취약점 유형 | 스크립트 / 카테고리 | severity 값 |
|------------|-------------------|-------------|
| SQL Injection 진단 기본값 (양호/정보) | scan_injection_enhanced.py | `Risk 2` |

### Risk 1 (Info)

| 취약점 유형 | 스크립트 / 카테고리 | severity 값 |
|------------|-------------------|-------------|
| System.out PII 출력 | scan_data_protection.py / SENSITIVE_LOGGING | `Info` |
| 마스킹 유틸 근접 탐지 (수동확인) | scan_data_protection.py / SENSITIVE_LOGGING | `Info` |
| @JsonView 적용 (수동확인) | scan_data_protection.py / DTO_EXPOSURE | `Info` |
| 테스트 코드 내 시크릿 탐지 | scan_data_protection.py / HARDCODED_SECRET | `Info` |

---

## severity 값 표기 규칙

- **scan_injection_enhanced.py** (EndpointDiagnosis 포맷): `"Risk 5"` / `"Risk 4"` / `"Risk 2"` 형식
- **그 외 스크립트** (DPFinding / finding dict 포맷): `"Critical"` / `"High"` / `"Medium"` / `"Low"` / `"Info"` 형식

두 포맷 모두 등급 매핑은 동일:

| Risk N | 문자열 값 |
|--------|----------|
| Risk 5 | Critical |
| Risk 4 | High |
| Risk 3 | Medium |
| Risk 2 | Low |
| Risk 1 | Info |

---

## 변경 이력

| 날짜 | 요약 |
|------|------|
| 2026-03-09 | 사내 공식 취약점 등급 기준서 기반 전면 개정 — 취약점 유형별 매핑 테이블 추가 |
| 초기 | Grade 5→Critical ... Grade 1→Info 단순 매핑만 정의 |
