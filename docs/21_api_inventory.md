# 21. API 인벤토리 추출

## Task 2-1: API Inventory

### 목적
소스코드에서 모든 API 엔드포인트를 추출하여 목록화합니다.

### 입력
- 소스코드 저장소
- `state/task_11_result.json` (자산 목록 참조)

### 출력
- `state/task_21_result.json`

### 수행 절차
1. **라우터/컨트롤러 파일 탐색**
   - Express.js: `app.get()`, `app.post()`, `router.*()` 패턴
   - Spring: `@RequestMapping`, `@GetMapping`, `@PostMapping` 어노테이션
   - Django: `urlpatterns`, `path()`, `re_path()` 패턴
   - FastAPI: `@app.get()`, `@app.post()` 데코레이터

2. **API 정보 추출**
   - HTTP 메서드 (GET, POST, PUT, DELETE 등)
   - URL 경로
   - 파라미터 (query, body, path)
   - 인증 필요 여부
   - 미들웨어/데코레이터

3. **결과 정리**
   - JSON 형식으로 API 목록 생성
   - 각 API별 파일 위치(소스 참조) 기록
   - 인증 미적용 API 별도 표시

### 출력 형식 예시
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
      "parameters": ["username", "password"]
    },
    {
      "api": "/api/users",
      "method": "GET",
      "file": "src/routes/users.js:8",
      "auth_required": true,
      "parameters": ["page", "limit"]
    }
  ],
  "executed_at": "",
  "claude_session": ""
}
```

### 주의사항
- 동적 라우팅 패턴도 포함할 것 (예: `/api/users/:id`)
- 주석 처리된 API는 제외하되 별도 기록
- 숨겨진 디버그/관리자 API 특별 주의
