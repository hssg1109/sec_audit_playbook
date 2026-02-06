# 23. XSS 취약점 검토

## Task 2-3: Cross-Site Scripting Review

### 목적
Reflected XSS, Stored XSS, DOM-based XSS 취약점을 식별합니다.

### 선행 조건
- Task 2-1 완료 (`state/task_21_result.json` 존재)

### 입력
- `state/task_21_result.json` (API 목록)
- 소스코드 (프론트엔드 + 백엔드)

### 출력
- `state/task_23_result.json`

### 수행 절차
1. **Reflected XSS**
   - URL 파라미터가 응답 HTML에 직접 출력되는 경우
   - 서버 측 이스케이프/인코딩 미적용 확인
   - 검색 기능, 에러 메시지 등 우선 검토

2. **Stored XSS**
   - 사용자 입력이 DB에 저장 후 다른 사용자에게 출력되는 경우
   - 게시판, 댓글, 프로필 등 UGC 영역 집중 검토
   - 출력 시점의 이스케이프 처리 확인

3. **DOM-based XSS**
   - `innerHTML`, `document.write()`, `eval()` 사용
   - `location.hash`, `location.search` 등 사용자 제어 가능 소스
   - JavaScript 프레임워크의 위험 패턴 (`dangerouslySetInnerHTML` 등)

4. **보호 메커니즘 확인**
   - Content-Security-Policy (CSP) 헤더 설정
   - X-XSS-Protection 헤더
   - 템플릿 엔진의 자동 이스케이프 설정
   - DOMPurify 등 sanitizer 라이브러리 사용 여부
5. **메타데이터 기록**
   - 결과 JSON `metadata`에 `source_repo_url`, `source_repo_path`, `source_modules` 포함
   - 위키 배포 시 `report_wiki_url`과 `report_wiki_status` 기록

### 판정 기준
| 심각도 | 조건 |
|--------|------|
| Critical | Stored XSS + 관리자 페이지 노출 |
| High | Stored XSS + 일반 사용자 영향 |
| Medium | Reflected XSS + CSP 미설정 |
| Low | DOM-based XSS + 제한적 영향 |
| Info | CSP 개선 권고 |
