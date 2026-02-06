# 22. 인젝션 취약점 검토

## Task 2-2: Injection Vulnerability Review

### 목적
SQL Injection, NoSQL Injection, Command Injection, LDAP Injection 등 인젝션 계열 취약점을 식별합니다.

### 선행 조건
- Task 2-1 완료 (`state/task_21_result.json` 존재)

### 입력
- `state/task_21_result.json` (API 목록)
- 소스코드

### 출력
- `state/task_22_result.json`

### 수행 절차
1. **API 목록 로드**
   - `task_21_result.json`에서 API 엔드포인트 목록 읽기
   - 파라미터를 받는 API를 우선 검토

2. **SQL Injection 검토**
   - 문자열 연결로 SQL 쿼리 구성하는 코드 탐지
   - Prepared Statement / Parameterized Query 미사용 확인
   - ORM 사용 시 raw query 부분 집중 검토

3. **NoSQL Injection 검토**
   - MongoDB `$where`, `$regex` 등 연산자 주입 가능성
   - 사용자 입력이 쿼리 객체에 직접 전달되는 경우

4. **Command Injection 검토**
   - `exec()`, `system()`, `spawn()` 등 시스템 명령 실행 함수
   - 사용자 입력이 명령줄 인자로 전달되는 경우

5. **기타 인젝션**
   - LDAP Injection
   - XML Injection (XXE)
   - Template Injection (SSTI)
6. **메타데이터 기록**
   - 결과 JSON `metadata`에 `source_repo_url`, `source_repo_path`, `source_modules` 포함
   - 위키 배포 시 `report_wiki_url`과 `report_wiki_status` 기록

### 판정 기준
| 심각도 | 조건 |
|--------|------|
| Critical | 인증 없이 접근 가능 + SQL 직접 삽입 |
| High | 인증 필요 + SQL 직접 삽입 |
| Medium | 간접적 삽입 가능성 (ORM bypass 등) |
| Low | 이론적 가능성만 존재 |
| Info | 개선 권고 사항 |

### 금지사항
- 코드 근거 없는 추측 판정 금지
- 실제 Exploit 코드 작성 금지
- 민감정보(DB 비밀번호 등) 보고서 포함 금지
