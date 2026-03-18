# Reporting Summary (Common Index)

Use a single JSON index to summarize all analysis outputs across skills.

Schema:
- `references/output_schemas.md` (reporting summary section, TBD)

Generator:
- `tools/scripts/generate_reporting_summary.py`

Severity mapping:
- `references/severity_criteria.md`

Required source fields (analysis entry):
- `source_repo_url`, `source_repo_path`, `source_modules`

Optional wiki fields (analysis entry):
- `report_wiki_url`, `report_wiki_page_id`, `report_wiki_status`

---

## 현황 컬럼 작성 기준 (태스크별 요약표)

`generate_finding_report.py`의 각 태스크 요약표 "현황" 열은 **title 기반** 짧은 문구를 사용한다.
description 텍스트를 직접 잘라 쓰지 않는다 (말줄임 "..." 발생 방지).

### 생성 절차

1. **title 로드**: `finding.title` 사용
2. **"(N건)" 제거**: `\s*\(\d+건\)\s*$` 정규식으로 파일 건수 suffix 제거
3. **"— anything (file.ext)" 제거**: 파일명 참조 suffix 제거 (java/kt/xml/json/properties/py)
4. **"— 설명" 제거**: `"앞부분 — 뒤설명"` 패턴에서 앞부분이 40자 이하이면 앞부분만 사용
5. **일반 title fallback**: 정제 후 title이 subcategory와 동일하거나 비어 있으면 description 첫 문장 사용 (말줄임 없음)

### 올바른 현황 예시

| 취약점 항목 | 현황 (올바른 예) |
|-----------|--------------|
| 전역 XSS 입력 필터(Lucy/AntiSamy) 미적용 | 전역 XSS 입력 필터(Lucy/AntiSamy) 미적용 |
| 민감정보(PII) 평문 로깅 (25건) | 민감정보(PII) 평문 로깅 |
| 하드코딩된 비밀정보 — DB 패스워드 (Config.java) | 하드코딩된 비밀정보 |
| SQL Injection 잠재 (UserMapper.java) | SQL Injection 잠재 |

### 주의사항

- 현황 칸에 "..." 말줄임이 나타나면 title 정제 로직 오류 → `generate_finding_report.py` 1504번 부근 확인
- description을 직접 80자 truncate 하는 방식은 사용하지 않는다
