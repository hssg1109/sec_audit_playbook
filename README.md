# sec-audit-playbook

A Git repository scaffold for parallel, AI-assisted security audits with clear task atomicity, dependency tracking, and schema-validated outputs.

## Goals
- Make each audit step a standalone, parallel-safe task
- Encode dependencies in a DAG
- Require structured JSON outputs with validation
- Track execution state as the single source of truth

## Quick start
1) Review the workflow DAG in `workflows/audit_workflow.yaml`
2) Open the relevant task prompt under `prompts/` and follow the inputs/outputs
3) Write results to `state/task_<id>_result.json`
4) Validate with `tools/scripts/validate_task_output.py`

## Repository map
- `workflows/` Task DAG and parallel execution guidance
- `schemas/` JSON Schemas for task outputs, findings, evidence
- `prompts/` Task prompts with dependencies and quality gates
- `state/` Execution results (source of truth)
- `tools/scripts/` Validation and automation helpers
- `docs/` Audit process docs and procedures

## Conventions
- Task IDs map to prompt filenames (e.g., 3-1 -> `prompts/static/task_31_api_inventory.md`)
- Task output schema is `schemas/task_output_schema.json`
- Do not edit `state/` by hand; use tools/scripts

## Confluence 게시
- Server/DC용 자동 게시 스크립트: `tools/scripts/publish_confluence.py`
- 페이지 제목 매핑: `tools/confluence_page_map.json`

### 환경 변수 (권장)
- `CONFLUENCE_BASE_URL` 예: `https://wiki.skplanet.com`
- `CONFLUENCE_SPACE_KEY` 예: `SECDIG`
- `CONFLUENCE_PARENT_ID` 예: `728911946`
- `CONFLUENCE_USER` (Basic Auth용, 선택)
- `CONFLUENCE_TOKEN` (PAT)

### .env 사용
- 루트에 `.env` 파일을 만들고 `.env.example`를 참고
- `.env`는 `.gitignore`에 포함됨

예시:
```
CONFLUENCE_BASE_URL=https://wiki.skplanet.com
CONFLUENCE_SPACE_KEY=SECDIG
CONFLUENCE_PARENT_ID=728911946
CONFLUENCE_USER=
CONFLUENCE_TOKEN=YOUR_PAT
```

### 실행 예시
```bash
CONFLUENCE_BASE_URL=https://wiki.skplanet.com \
CONFLUENCE_SPACE_KEY=SECDIG \
CONFLUENCE_PARENT_ID=728911946 \
CONFLUENCE_TOKEN=YOUR_PAT \
python tools/scripts/publish_confluence.py
```

- `CONFLUENCE_USER`를 주면 Basic Auth, 없으면 Bearer 토큰으로 전송
- 먼저 `--dry-run`으로 페이지 생성/업데이트 대상 확인 권장
