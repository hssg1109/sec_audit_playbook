# 10. 자산 식별 (Asset Identification)

## Phase 1 - Asset Identification

### 목적
고객이 제공한 자산 정보 Excel 파일을 파싱하고, 로컬 소스코드를 분석하여 진단 대상 자산 목록을 생성합니다.

### 사전 조건
- 고객사로부터 자산 정보 Excel 파일 수령
- 진단 대상 소스코드 로컬 접근 가능
- Python 의존성 설치 완료 (`pip install openpyxl`)

### 작업 목록

#### Task 1-1: 자산 목록 작성 (Excel 파싱)
- **프롬프트**: `prompts/static/task_11_asset_identification.md`
- **스크립트**: `tools/scripts/parse_asset_excel.py`
- **출력**: `state/task_11_result.json`
- **담당**: Claude 인스턴스 #1

**수행 내용:**
1. `parse_asset_excel.py`로 Excel 파일을 JSON으로 변환
   ```bash
   python tools/scripts/parse_asset_excel.py <excel_file> --output state/task_11_result.json
   ```
2. 소스코드 프로젝트 구조 분석 (빌드 설정, 기술 스택 확인)
3. 설정 파일에서 외부 연동 서비스 파악
4. Excel 데이터와 소스코드 분석 결과 병합
5. 결과 JSON `metadata`에 다음 필드를 반드시 포함
   - `source_repo_url`, `source_repo_path`, `source_modules`
6. 위키 배포 시 `report_wiki_url`과 `report_wiki_status` 기록

**Excel 파서 기능:**
- 한/영 헤더 자동 인식 (자산명/asset_name, 도메인/domain 등)
- 기술 스택 문자열 자동 분리 (쉼표, 슬래시, 세미콜론 구분)
- 포트 번호 자동 파싱
- 최대 10행까지 헤더 행 자동 탐색

### 완료 기준
- [ ] 자산 목록 JSON 생성 완료 (`state/task_11_result.json`)
- [ ] `validate_task_output.py` 검증 통과
- [ ] Phase 2 (정적 분석) 시작 가능 상태 확인
