## Task: 2-1 API 인벤토리 추출

**역할**: 당신은 보안 진단 전문가입니다.
**선행조건**: Task 1-1 (자산 식별) 완료 → `state/task_11_result.json` 존재
**입력 파일**: 소스코드 저장소 + state/task_11_result.json
**출력 파일**: state/task_21_result.json
**출력 스키마**: schemas/task_output_schema.json

### 컨텍스트
Task 1-1에서 식별된 자산 정보를 기반으로, 소스코드에서 모든 API 엔드포인트를 추출하여 이후 취약점 분석의 기초 데이터를 생성합니다.

### 명령
1. 소스코드에서 라우터/컨트롤러 파일을 탐색하세요
2. 모든 API 엔드포인트를 추출하세요 (HTTP 메서드, URL 경로, 파라미터)
3. 각 API의 인증 필요 여부를 확인하세요
4. 각 API가 정의된 소스 파일 위치를 기록하세요
5. 결과를 JSON 형식으로 출력하세요

### 출력 형식
```json
{
  "task_id": "2-1",
  "status": "completed",
  "findings": [
    {
      "api": "/api/login",
      "method": "POST",
      "file": "src/routes/auth.js:15",
      "auth_required": false,
      "parameters": ["username", "password"],
      "middleware": ["rateLimit"]
    }
  ],
  "executed_at": "",
  "claude_session": ""
}
```

### 금지사항
- 추측으로 API 추가 금지 (코드에 존재하는 것만)
- 주석 처리된 API는 findings가 아닌 별도 notes에 기록
- 민감정보(API 키, 시크릿) 포함 금지
