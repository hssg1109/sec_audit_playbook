# 24. 파일 처리 검토

## Task 2-4: File Handling Review

### 목적
파일 업로드/다운로드 관련 취약점을 식별합니다.

### 선행 조건
- Task 2-1 완료 (`state/task_21_result.json` 존재)

### 입력
- `state/task_21_result.json` (API 목록)
- 소스코드

### 출력
- `state/task_24_result.json`

### 수행 절차
1. **파일 업로드 검토**
   - 파일 확장자 검증 (화이트리스트 방식 여부)
   - MIME 타입 검증
   - 파일 크기 제한
   - 업로드 경로가 웹 루트 외부인지 확인
   - 파일명 변경(랜덤화) 처리 여부

2. **파일 다운로드 검토**
   - Path Traversal 취약점 (`../` 패턴)
   - 직접 객체 참조 (IDOR) 취약점
   - 접근 권한 검증

3. **파일 처리 검토**
   - 이미지 처리 라이브러리 취약점 (ImageMagick 등)
   - 압축 파일 해제 시 Zip Bomb / Zip Slip
   - 문서 파싱 시 XXE 취약점
4. **메타데이터 기록**
   - 결과 JSON `metadata`에 `source_repo_url`, `source_repo_path`, `source_modules` 포함
   - 위키 배포 시 `report_wiki_url`과 `report_wiki_status` 기록

### 판정 기준
| 심각도 | 조건 |
|--------|------|
| Critical | 웹쉘 업로드 가능 |
| High | Path Traversal로 임의 파일 읽기 |
| Medium | 파일 타입 검증 우회 가능 |
| Low | 파일 크기 미제한 |
| Info | 개선 권고 |
