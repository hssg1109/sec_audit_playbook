# Severity Criteria — 취약점 위험도 등급 기준

> **근거 규정**
> - 전자금융감독규정 제37조의3 (전자금융기반시설 취약점 분석·평가)
> - 주요 정보통신기반시설 보호지침 제2021-28호 (과학기술정보통신부 고시, 3.3 취약점 평가 등급)
> - 금융보안원 소프트웨어 보안약점 진단 가이드 (위험도 분류 기준)
>
> **적용 범위**: sec-audit-static 진단 결과 전체 (자동 스캔 + LLM 보완)

---

## 등급 정의

진단 결과는 **결과(취약/정보/양호)** 와 **위험도(1~5)** 로 표시한다.
High/Critical 등의 영문 등급 표기는 사용하지 않는다.

| 위험도 | 판정 결과 | 기준 요약 | 조치 방침 |
|:------:|:--------:|---------|---------|
| **5** | 취약 | 즉각적 시스템 침해 가능. 원격 코드 실행, 인증 우회, 금융·개인정보 대량 유출 직접 경로 확인 | 즉시 조치 (제로데이 수준) |
| **4** | 취약 | 심각한 피해 가능. 권한 상승, 세션 탈취, 주요 데이터 직접 접근 경로 확인 | 우선 조치 (단기 내) |
| **3** | 정보 | 조건부 악용 가능. 암호화 약점, CORS 설정 오류, 정보 누출 간접 경로 | 검토 후 조치 (분기 내) |
| **2** | 양호 | 점검 통과. 잠재적 위험 미미 또는 보완 통제로 충분히 완화됨 | 개선 권고 (선택) |
| **1** | 정보 | 정보성 항목. 즉각적 위험 없음. 보안 강화 참고사항 | 참고 (장기 개선) |

> **위험도 5·4 (취약)**: 발견 즉시 담당 조직에 통보하고 조치 계획 수립
> **위험도 3 (정보)**: 수동 확인 후 취약 승격 여부 결정
> **위험도 2 (양호)**: 통과 항목 — 매트릭스 양호 건수에 산입
> **위험도 1 (정보)**: 정보성 항목 — 매트릭스 정보 건수에 산입

---

## 취약점 유형별 위험도 매핑

### 위험도 5 (취약)

| 취약점 유형 | 스크립트 / 카테고리 | severity 내부값 |
|------------|-------------------|----------------|
| SQL Injection — 실제 취약 확인 | scan_injection_enhanced.py | `Risk 5` |
| OS Command Injection | scan_injection_enhanced.py (global_findings) | `Risk 5` |
| SSI Injection | scan_injection_enhanced.py (global_findings) | `Risk 5` |
| 악성파일 업로드 (UUID+ExtWL 모두 미적용) | scan_file_processing.py / UPLOAD | `Critical` |
| 파일 다운로드 / LFI (Path Traversal) | scan_file_processing.py / DOWNLOAD | `Critical` |
| 민감정보 평문 로깅 (info/warn/error/fatal) | scan_data_protection.py / SENSITIVE_LOGGING | `Critical` |
| JWT Algorithm NONE 허용 | scan_data_protection.py / JWT_INCOMPLETE | `Critical` |
| AWS/GCP 클라우드 키 하드코딩 | scan_data_protection.py / HARDCODED_SECRET | `Critical` |
| NoOpPasswordEncoder / Md5PasswordEncoder | scan_data_protection.py / WEAK_CRYPTO | `Critical` |

### 위험도 4 (취약)

| 취약점 유형 | 스크립트 / 카테고리 | severity 내부값 |
|------------|-------------------|----------------|
| SQL Injection — 잠재 (수동확인 필요) | scan_injection_enhanced.py | `Risk 4` |
| XSS (Persistent / Reflected / DOM) | scan_xss.py | `High` |
| Open Redirect | scan_xss.py | `High` |
| RFI / SSRF | scan_file_processing.py / RFI | `High` |
| DB 비밀번호 하드코딩 | scan_data_protection.py / HARDCODED_SECRET | `High` |
| JWT Secret Key 하드코딩 | scan_data_protection.py / HARDCODED_SECRET | `High` |
| JWT 서명 키 미설정 파서 | scan_data_protection.py / JWT_INCOMPLETE | `High` |
| JWT parseUnsecuredClaims() 사용 | scan_data_protection.py / JWT_INCOMPLETE | `Critical`* |
| DTO 민감 필드 @JsonIgnore 미적용 (Lombok) | scan_data_protection.py / DTO_EXPOSURE | `High` |

> \* parseUnsecuredClaims()는 인증 완전 우회 → 위험도 5로 격상

### 위험도 3 (정보)

| 취약점 유형 | 스크립트 / 카테고리 | severity 내부값 |
|------------|-------------------|----------------|
| 취약 암호 알고리즘 (MD5/SHA-1/DES/RC4/ECB) | scan_data_protection.py / WEAK_CRYPTO | `Medium` |
| CORS allowedOrigins(*) + allowCredentials(true) | scan_data_protection.py / CORS_MISCONFIG | `Medium` |
| CORS Origin 헤더 그대로 반영 | scan_data_protection.py / CORS_MISCONFIG | `Medium` |
| @CrossOrigin 와일드카드 기본값 | scan_data_protection.py / CORS_MISCONFIG | `Medium` |
| 보안 헤더 비활성화 (.headers().disable() 등) | scan_data_protection.py / SECURITY_HEADER | `Medium` |
| 민감정보 로깅 (debug/trace 레벨) | scan_data_protection.py / SENSITIVE_LOGGING | `Medium` |
| JWT 클럭 스큐 과도 설정 | scan_data_protection.py / JWT_INCOMPLETE | `Medium` |
| 파일 업로드 일부 검증 미흡 (부분 누락) | scan_file_processing.py / UPLOAD | `Medium` |
| DTO 민감 필드 @JsonIgnore 미적용 (Lombok 없음) | scan_data_protection.py / DTO_EXPOSURE | `Medium` |

### 위험도 2 (양호)

| 취약점 유형 | 스크립트 / 카테고리 | severity 내부값 |
|------------|-------------------|----------------|
| SQL Injection 점검 통과 (잠재 없음) | scan_injection_enhanced.py | `Risk 2` |

### 위험도 1 (정보)

| 취약점 유형 | 스크립트 / 카테고리 | severity 내부값 |
|------------|-------------------|----------------|
| System.out PII 출력 | scan_data_protection.py / SENSITIVE_LOGGING | `Info` |
| 마스킹 유틸 근접 탐지 (수동확인) | scan_data_protection.py / SENSITIVE_LOGGING | `Info` |
| @JsonView 적용 (수동확인) | scan_data_protection.py / DTO_EXPOSURE | `Info` |
| 테스트 코드 내 시크릿 탐지 | scan_data_protection.py / HARDCODED_SECRET | `Info` |

---

## severity 내부값 → 위험도 매핑 (RISK_MAP)

스캔 스크립트가 JSON에 기록하는 내부 severity 값과 보고서 표시 위험도의 매핑:

| severity 내부값 | 판정 결과 | 위험도 | 비고 |
|----------------|:--------:|:-----:|------|
| `Critical` | 취약 | 5 | scan_data_protection, scan_file_processing |
| `High` | 취약 | 4 | scan_xss, scan_data_protection |
| `Medium` | 정보 | 3 | 조건부 위험 — 수동 확인 권고 |
| `Low` | 양호 | 2 | 점검 통과 |
| `Info` | 정보 | 1 | 정보성 항목 |
| `Risk 5` | 취약 | 5 | scan_injection_enhanced |
| `Risk 4` | 취약 | 4 | scan_injection_enhanced |
| `Risk 3` | 정보 | 3 | scan_injection_enhanced |
| `Risk 2` | 양호 | 2 | scan_injection_enhanced |
| `Risk 1` | 정보 | 1 | scan_injection_enhanced |

> **표시 원칙**: 보고서에서 severity 내부값(Critical/High 등)은 직접 노출하지 않는다.
> 결과(취약/정보/양호)와 위험도(1~5) 숫자만 표시한다.

---

## 변경 이력

| 날짜 | 요약 |
|------|------|
| 2026-03-17 | 전자금융감독규정·주요 정보통신기반시설 보호지침 기반 위험도 1~5 기준 재정의. High/Critical 영문 표기 폐기, 위험도 숫자+결과(취약/정보/양호) 단일 체계로 전환. RISK_MAP 위험도 수치 오류 수정(high→4, medium→3, low→2, info→1) |
| 2026-03-09 | 사내 공식 취약점 등급 기준서 기반 전면 개정 — 취약점 유형별 매핑 테이블 추가 |
| 초기 | Grade 5→Critical ... Grade 1→Info 단순 매핑만 정의 |
