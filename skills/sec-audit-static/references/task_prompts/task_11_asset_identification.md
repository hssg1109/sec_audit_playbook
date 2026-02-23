## Task: 1-1 자산 목록 작성 (Asset Identification)

**역할**: 당신은 보안 진단 전문가입니다.
**입력 파일**: 고객 제공 자산 정보 Excel 파일 + 로컬 소스코드
**출력 파일**: state/task_11_result.json
**출력 스키마**: references/schemas/task_output_schema.json

### 컨텍스트
보안 진단의 첫 단계로, 고객이 제공한 자산 정보 Excel 파일을 파싱하고 소스코드를 분석하여 진단 대상 자산을 식별합니다.

### 명령

#### Step 1: Excel 파싱
1. `tools/scripts/parse_asset_excel.py`를 실행하여 Excel 파일을 JSON으로 변환하세요
   ```bash
   python tools/scripts/parse_asset_excel.py <excel_file> --output state/task_11_result.json
   ```
2. 파싱 결과에서 자산명, 유형, 도메인, IP, 중요도, 기술스택 등을 확인하세요

#### Step 2: 소스코드 기반 보완
1. 로컬 소스코드의 프로젝트 구조를 분석하세요
2. 빌드 설정 파일(build.gradle, pom.xml, package.json 등)에서 기술 스택을 확인하세요
3. 설정 파일(application.yaml, .env 등)에서 외부 연동 서비스를 파악하세요
4. Excel 파싱 결과와 소스코드 분석 결과를 병합하여 최종 자산 목록을 생성하세요

#### Step 3: 결과 검증
1. 결과를 `task_output_schema.json` 형식에 맞춰 JSON으로 출력하세요
2. `validate_task_output.py`로 스키마 검증을 수행하세요

### 출력 형식
```json
{
  "task_id": "1-1",
  "status": "completed",
  "findings": [
    {
      "asset_name": "서비스명",
      "asset_type": "Web Server",
      "domain": "example.com",
      "ip": "[REDACTED_IP]",
      "criticality": "High",
      "tech_stack": ["Spring Boot", "Kotlin", "PostgreSQL"],
      "ports": [80, 443],
      "source_code_path": "/path/to/source",
      "framework": "Spring Boot 3.x",
      "build_tool": "Gradle"
    }
  ],
  "metadata": {
    "source_file": "자산정보.xlsx",
    "total_assets": 1,
    "parse_method": "openpyxl"
  },
  "executed_at": "",
  "claude_session": ""
}
```

### 금지사항
- 실제 IP 주소는 반드시 마스킹 (REDACTION_RULES.md 참조)
- 추측으로 자산 추가 금지 (Excel과 소스코드에 확인된 것만)
- 고객 내부 네트워크 구조 상세 노출 금지
- 민감 정보(API 키, 시크릿, 비밀번호) 포함 금지
