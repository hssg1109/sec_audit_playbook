## Task: 2-1 API 인벤토리 추출

**역할**: 당신은 보안 진단 전문가입니다.
**선행조건**: Task 1-1 (자산 식별) 완료 → `state/task_11_result.json` 존재
**입력 파일**: 소스코드 저장소 + state/task_11_result.json
**출력 파일**: state/task_21_result.json
**출력 스키마**: references/schemas/task_output_schema.json

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

### 자동화 스크립트 활용

scan_api.py v3.0 + scan_dto.py v1.0을 사용하면 API 인벤토리를 자동 추출할 수 있습니다.

```bash
# 1. DTO 카탈로그 생성 (파라미터 타입 해석용)
python3 tools/scripts/scan_dto.py <source_dir> -o state/{prefix}_dto_catalog.json

# 2. API 인벤토리 추출 (인증 탐지 + DTO 연동)
python3 tools/scripts/scan_api.py <source_dir> \
    --dto-catalog state/{prefix}_dto_catalog.json \
    -o state/{prefix}_api_inventory.json
```

프로젝트별 커스텀 인증 어노테이션이 있으면 `--auth-annotations` 옵션으로 추가:
```bash
python3 tools/scripts/scan_api.py <source_dir> --auth-annotations Session LoginUser
```

### 인증 분류 기준

#### 이진 분류 (auth_required: true/false)

`required` 속성을 기준으로 이진 분류합니다:
- `required=true` → `auth_required: true` (로그인 필수)
- `required=false` → `auth_required: false` (비로그인 접근 가능)

**판정 우선순위:**

| 우선순위 | 조건 | auth_required | 근거 |
|---|---|---|---|
| 1 | `@PreAuthorize` | **true** | Spring Security 메서드 레벨 보안 |
| 2 | `@Secured` | **true** | Spring Security 역할 기반 보안 |
| 3 | Security Config 경로 매칭 | **true/false** | `pathMatchers`/`antMatchers` 설정에 따름 |
| 4 | `@Session(required=true, permitted=true)` | **true** | Level 1: 완전 인증 |
| 4 | `@Session(required=true)` / bare `@Session` | **true** | Level 2: 기본 인증 |
| 4 | `@Session(required=false)` | **false** | Level 3: 비인증 |
| 4 | `@Session(required=false, permitted=true)` | **false** | Level 4: 조건부 인증 |
| 5 | 어노테이션 없음 | **false** | 인증 설정 미적용 |

#### 보안 등급 4-Level 매트릭스 (auth_detail_stats)

`permitted`는 "게스트 허용"이 아니라 **유저 활동 상태 검증**(정지/탈퇴/휴면 여부) 플래그입니다.

| Level | required | permitted | 분류 명칭 | 설명 |
|---|---|---|---|---|
| **L1** | true | true | **완전 인증** (Active User) | 로그인 필수 + 활동 가능한 정상 유저만. 보상, 결제, 글쓰기 등 핵심 기능 |
| **L2** | true | false | **기본 인증** (Logged-in Only) | 로그인 필수. 유저 상태는 미검증. 로그아웃, 내 정보 조회 등 |
| **L3** | false | false | **비인증** (Public) | 로그인 불필요. 누구나 접근 가능. 로그인 페이지, 공지사항 등 |
| **L4** | false | true | **조건부 인증** (Guest or Safe User) | 비회원 OK, 로그인 시 정상 유저만. 특수 케이스 |

**출력 통계:**
- `auth_stats`: `{"auth_required": N, "auth_not_required": N}` (이진 집계)
- `auth_detail_stats`: 4-Level 보안 등급별 상세 통계
- `auth_annotations`: 각 엔드포인트의 인증 어노테이션 원본 속성

### 블록 주석 처리 정책

`/* ... */` 블록 주석으로 감싸진 컨트롤러는 **엔드포인트 목록에서 제외**됩니다.
주석 내 `@Controller`/`@RestController`가 감지되면 `commented_controllers` 필드에 별도 기록됩니다.

```json
"commented_controllers": [
  {"class": "PerformanceTestController", "endpoint_count": 9, "reason": "Block comment (/* ... */)"}
]
```

### DTO 카탈로그 활용

`resolved_fields`가 있는 파라미터는 커스텀 타입의 필드가 해석된 것입니다.
취약점 분석 시 각 필드 단위로 입력 검증을 확인하세요.

예시:
```json
{
  "name": "request",
  "type": "body",
  "data_type": "AuthDTO.LoginRequest",
  "resolved_fields": [
    {"name": "authType", "data_type": "String", "annotations": ["@NotEmpty"]},
    {"name": "password", "data_type": "String", "annotations": []}
  ],
  "resolved_from": "AuthDTO.LoginRequest"
}
```

### 금지사항
- 추측으로 API 추가 금지 (코드에 존재하는 것만)
- 주석 처리된 API는 findings가 아닌 별도 notes에 기록
- 민감정보(API 키, 시크릿) 포함 금지
