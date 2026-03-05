# 25. 데이터 보호 검토

## Task 2-5: Data Protection Review

### 목적
CORS 설정, 중요정보 노출, 하드코딩된 민감정보, 관리자 페이지 분리, JWT 토큰 보안, 민감정보 로깅, 취약 암호화 등 데이터 보호 관련 취약점을 식별합니다.

### 선행 조건
- Task 2-1 완료 (`state/task_21_result.json` 존재)

### 입력
- `state/task_21_result.json` (API 목록)
- 소스코드

### 출력
- `state/task_25_result.json`

### 자동화 스크립트

```bash
python tools/scripts/scan_data_protection.py <source_dir> \
    --api-inventory state/<prefix>_api_inventory.json \
    -o state/<prefix>_task25.json
```

선택적 모듈 제외:
```bash
python tools/scripts/scan_data_protection.py <source_dir> \
    --api-inventory state/<prefix>_api_inventory.json \
    -o state/<prefix>_task25.json \
    --skip logging  # 특정 카테고리 제외 가능
```

### 진단 모듈 (7개)

| # | 모듈 | 설명 | CWE |
|---|------|------|-----|
| 1 | `HARDCODED_SECRET` | 하드코딩된 비밀번호·API키·AWS 자격증명·DB URL 내 Credentials | CWE-798 |
| 2 | `SENSITIVE_LOGGING` | 주민번호·전화번호·카드번호·비밀번호·이메일 직접 로깅 | CWE-532 |
| 3 | `WEAK_CRYPTO` | MD5·SHA-1 해시, DES·3DES·RC4·AES/ECB 암호화 | CWE-327 |
| 4 | `JWT_ISSUE` | `parseUnsecuredClaims()`, `SignatureAlgorithm.NONE`, 취약 비밀키 | CWE-347 |
| 5 | `DTO_EXPOSURE` | 응답 DTO 내 민감 필드 (주민번호·카드번호·비밀번호) `@JsonIgnore` 미적용 | CWE-200 |
| 6 | `CORS_MISCONFIGURATION` | `allowedOrigins("*")`, Origin 헤더 직접 반영, `@CrossOrigin` 무제한 | CWE-942 |
| 7 | `SECURITY_HEADER` | `.headers().disable()`, CSRF 비활성화, Clickjacking 보호 미설정 | CWE-693 |

### 수행 절차

1. **자동 스캔 실행** — `scan_data_protection.py` 실행 → `state/<prefix>_task25.json` 생성
2. **수동 심층진단** — `needs_review: true` 항목에 대해 `manual_review_prompt.md` 케이스 A/B/C 적용:
   - **케이스 A**: 하드코딩 시크릿 — Prod 키 vs. 테스트 더미 판별
   - **케이스 B**: 민감정보 로깅 — 마스킹 유틸 적용 여부 검증
   - **케이스 C**: 커스텀 암호화 유틸 — 내부 알고리즘 안전성 검증
3. **CORS 설정 검토**
   - `allowedOrigins("*")` + `credentials(true)` 동시 설정 여부
   - Origin 헤더값을 그대로 응답에 반영하는 코드 유무
   - `@CrossOrigin` 어노테이션 및 전역 CORS 설정 확인
4. **JWT 토큰 보안 검토**
   - 서명 알고리즘 `none` 사용 여부
   - Secret Key 복잡도 확인
   - `parseUnsecuredClaims()` / `parseClaimsJwt()` 미서명 토큰 허용 여부
5. **메타데이터 기록**
   - 결과 JSON `metadata`에 `source_repo_url`, `source_repo_path`, `source_modules` 포함
   - 위키 배포 시 `report_wiki_url`과 `report_wiki_status` 기록

### 판정 기준
| 심각도 | 조건 |
|--------|------|
| Critical | 소스코드 내 DB 비밀번호/API 시크릿/AWS 키 하드코딩 + 외부 접근 가능 |
| High | CORS 와일드카드 + credentials, JWT none 알고리즘, 미서명 토큰 허용 |
| Medium | 응답 DTO 민감정보 미마스킹, 관리자 페이지 미분리, Origin 우회 가능, PII 직접 로깅 |
| Low | 취약 해시(MD5·SHA-1) 사용, 에러 페이지 서버 버전 노출, 주석 내 테스트 계정 |
| Info | 보안 개선 권고 (JWT 만료 시간 미설정, CORS 정책 강화, AES/CBC→GCM 전환 등) |
