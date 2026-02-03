# 25. 데이터 보호 검토

## Task 2-5: Data Protection Review

### 목적
CORS 설정, 중요정보 노출, 하드코딩된 민감정보, 관리자 페이지 분리, JWT 토큰 보안 등 데이터 보호 관련 취약점을 식별합니다.

### 선행 조건
- Task 2-1 완료 (`state/task_21_result.json` 존재)

### 입력
- `state/task_21_result.json` (API 목록)
- 소스코드

### 출력
- `state/task_25_result.json`

### 수행 절차

1. **CORS 설정 검토**
   - `allowedOrigins("*")` + `credentials(true)` 동시 설정 여부
   - Origin 헤더값을 그대로 응답에 반영하는 코드 유무
   - `@CrossOrigin` 어노테이션 및 전역 CORS 설정 확인
   - 관련 CWE: CWE-942

2. **중요정보 노출 검토**
   - 소스코드 내 비밀번호, API 키, 토큰 등 하드코딩 여부
   - 응답 DTO에 불필요한 민감 필드 (CI값, 주민번호, 전화번호) 포함 여부
   - 에러 응답에 스택 트레이스, DB 정보, 절대 경로 노출 여부
   - 관련 CWE: CWE-200, CWE-798

3. **관리자 페이지 분리 검토**
   - 관리자 페이지와 일반 사용자 페이지의 물리적/논리적 분리 여부
   - IP 접근제어 등 접근 통제 설정 확인
   - 관련 CWE: CWE-284

4. **JWT 토큰 보안 검토**
   - 서명 알고리즘 `none` 사용 여부
   - Secret Key 복잡도 확인
   - 토큰 만료 시간 설정 여부
   - 관련 CWE: CWE-347

### 판정 기준
| 심각도 | 조건 |
|--------|------|
| Critical | 소스코드 내 DB 비밀번호/API 시크릿 하드코딩 + 외부 접근 가능 |
| High | CORS 와일드카드 + credentials, JWT none 알고리즘 |
| Medium | 응답 내 민감정보 포함, 관리자 페이지 미분리 |
| Low | 에러 페이지 서버 버전 노출, 주석 내 테스트 계정 |
| Info | 보안 개선 권고 |
