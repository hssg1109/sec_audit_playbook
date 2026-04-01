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

## 보고서 서비스 개요 섹션 작성 기준 (Phase 4 필수)

### 1. 서비스 개요 표 — 스크립트 자동 생성 (권장)

`generate_finding_report.py`는 `--asset-info`로 task_11 JSON을 전달하면 **서비스 개요 표를 자동 생성**한다.
데이터 소스: `state/<prefix>_task11.json`의 `metadata` 필드 + `findings[0]` (framework, tech_stack, build_tool).

#### Phase 4 스크립트 호출 형식 (서비스 개요 자동화 필수 인자)

```bash
python3 tools/scripts/generate_finding_report.py <source_dir> \
    <finding_jsons...> \
    --service "<서비스명>" \
    --source-label "<레포URL>" \
    --asset-info state/<prefix>_task11.json \   # ← 서비스 개요 표 자동 삽입 (필수)
    --anchor-style md2cf \
    --page-map tools/confluence_page_map.json \
    --output state/<prefix>_진단보고서.md
```

**`--asset-info` 없이 실행하면** Branch/Commit/담당자/커밋 일자가 빠진 불완전한 표가 생성된다. 반드시 task_11 JSON을 전달하라.

#### 자동 생성되는 표 형식

```markdown
| 항목 | 내용 |
|---|---|
| **진단 대상** | {서비스명} ({repo명}) |
| **소스 경로** | {source_repo_url} |
| **Branch / Commit** | `{branch}` / `{commit}` |
| **최종 커밋 일자** | {commit_date} |
| **최종 커밋 메시지** | {commit_message} |
| **담당자 (최종 커밋)** | {responsible_person} |
| **진단 일자** | {diagnosis_date} |
| **진단 유형** | {diagnosis_type} |
| **언어 / 프레임워크** | {tech_stack} / {framework} |
| **빌드 도구** | {build_tool} |
```

**필수 항목**: 소스 경로, Branch/Commit, 담당자 — 이 3가지가 빠지면 서비스 개요 미완성.
담당자가 확인 안 되면 `"미확인 (최종 커밋: {name})"` 으로 기재.

#### LLM이 직접 보고서를 작성하는 경우 (스크립트 미사용 시)

스크립트를 거치지 않고 LLM이 Phase 4 보고서를 직접 작성할 때는 아래 순서로 서비스 개요 표를 채워야 한다:

1. `state/<prefix>_task11.json` → `metadata` 필드에서 source_repo_url / branch / commit / commit_date / commit_message / responsible_person 읽기
2. `task11.json` → `findings[0]`에서 framework / tech_stack / build_tool 읽기
3. 필수 3항목(소스 경로, Branch/Commit, 담당자) 중 하나라도 누락이면 task_11 재수집 또는 git log 직접 확인 후 채울 것

### 2. 섹션 번호 규칙

```
## 1. 서비스 개요
  → 표 (진단 대상, 소스 경로, Branch/Commit, 커밋 일자, 담당자, 진단 일자, 진단 유형, 언어/프레임워크, 빌드 도구)

### 1.1 자산 구조 (task_11 findings에 환경별 데이터 있을 때만)
  → 환경(상용/개발/알파)별 도메인, 포트, 노출 범위

### 1.1 또는 1.2 진단 결과 통계
  → 취약/정보/양호 집계 표
  (자산 구조 섹션 유무에 따라 번호 자동 결정)

### 1.2 또는 1.3 주요 식별 취약점 (Critical / High)
  → Critical + High 등급 finding만, 각 2~3문장 구어체 설명

## 2. 종합 진단 결과 요약
  → Task별 진단 매트릭스 + 항목별 상세 목록
```

**금지**: 섹션 헤더에 "LLM 수동 검토 확정", "LLM 확정 기준" 등의 내부 진단 방법론 명시 금지.
개발자/보안 담당자가 읽는 문서이므로 진단 도구 언급 없이 결과만 서술.

### 3. 주요 식별 취약점 작성 기준 (1.2 섹션)

- **포함 대상**: severity ∈ {Critical, High} AND result = "취약" 인 finding만
- **제외**: Medium/Low/정보 등급 (섹션 2 매트릭스에서 확인)
- **서술 방식**: finding 제목 + 구어체 2~3문장 (현황 + 보안 위협 + 핵심 조치)
  - finding_writing_guide.md의 description 3단 구성과 동일 원칙 적용
  - 기술 용어 나열 금지, 개발자가 "왜 위험한지" 바로 이해할 수 있도록

```markdown
**[{ID}] {Severity} — {제목}**

{파일/함수}에서 {현황을 1문장으로}. {공격자가 어떻게 악용할 수 있는지 1문장으로}. {핵심 조치 1문장}.
```

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

---

## LLM 수동분석 결과 통합 규칙 (요약보고서 매트릭스)

Phase 3 LLM 수동분석이 완료된 태스크는 **LLM 확정 수치가 자동스캔 수치를 반드시 덮어써야 한다.**

### 원칙

1. **LLM 확정 수치 우선**: `<prefix>_task22_llm.json` 등 LLM 보완 JSON이 존재하면
   해당 태스크의 취약/정보/양호 수치는 LLM JSON의 `endpoint_summary` 기준으로 표기한다.
   자동스캔 원본 수치(`_injection.json` 등)를 그대로 매트릭스에 쓰지 않는다.

2. **스캐너 FP 정정 명시**: LLM이 스캐너 "취약"을 FP로 판정한 경우 매트릭스 주석(footnote)에
   `스캐너 취약 N건 → LLM FP 정정 M건` 형태로 표기한다.

3. **정보(잠재) 건수 분리**: 취약(TP) / 정보(잠재·패턴) / 양호(N/A 포함)를 반드시 별도 열로 구분한다.
   자동스캔 결과에만 존재하는 "needs_review" 항목은 LLM 최종 판정으로 치환한다.

4. **태스크별 진단 대상 EP 수 표기**: 각 행에 "진단 대상 EP" 수를 명시한다.
   (예: 221 EP | 취약 0 | 정보 1 | 양호 220)

### 매트릭스 작성 순서

```
1. <prefix>_task22_llm.json → endpoint_summary 확인
   - total, 취약, 정보, 양호, scanner_fp_corrected 필드 사용
2. <prefix>_task23_llm.json → xss_endpoint_review.endpoint_summary 확인
3. <prefix>_task24_llm.json → file_handling_summary 확인
4. <prefix>_task25_llm.json → summary 확인
5. LLM JSON 없는 태스크 → 자동스캔 원본 수치 사용하되 "(자동스캔 미검증)" 주석 추가
```

### Finding 목록 작성 원칙

요약보고서의 "항목별 상세 목록" 테이블은 LLM 확정 finding만 포함한다.
자동스캔 원시 결과(수백 건의 raw "정보" 항목)를 그대로 나열하지 않는다.

| 포함 대상 | 제외 대상 |
|---------|---------|
| LLM이 TP·FP·정보로 명시 판정한 finding | 자동스캔 only, LLM 미검토 항목 |
| `needs_review: false` + result 확정 | `needs_review: true` 미처리 항목 |
| INJ-LLM-xxx / XSS-xxx / DATA-xxx ID 부여된 항목 | ID 없는 raw scan 항목 |

Finding 행 컬럼: `No | Finding ID | 점검구분 | 점검항목 | 결과 | 위험도 | 대상 EP/파일 | 양호 EP | 정보 EP | 취약 EP`

**Finding ID 셀 anchor 링크 (필수)**:
Finding ID 셀은 섹션 3 상세 항목 앵커로 반드시 링크한다. HTML table 내에서는 `<a href>` 방식이 Confluence에서 동작하지 않으므로 반드시 Confluence 네이티브 `ac:link` 형식으로 직접 삽입한다:
```html
<td><ac:link ac:anchor="detail-{id-lowercase}"><ac:plain-text-link-body><![CDATA[FINDING-ID]]></ac:plain-text-link-body></ac:link></td>
```
앵커 이름 규칙: `detail-{id-lowercase}` (예: `FILE-001` → `detail-file-001`)
섹션 3 상세에는 `[[ANCHOR:detail-{id}]]` 마커를 반드시 삽입한다 (publish_confluence.py가 Confluence anchor macro로 변환).
섹션 3에 상세 항목이 없는 집계성 행(예: XSS-AUTO)은 plain text로 기재한다.

**위험도 열 표기 (필수)**:
`finding_writing_guide.md §4` 기준 1~5 숫자 등급을 사용한다. 형식: `N 표기명`
```
5 매우 위험 (Critical) / 4 고위험 (High) / 3 중간 위험 (Medium) / 2 저위험 (Low) / 1 매우 낮음 (Info)
```
영문 severity(Critical/High/Medium)만 단독 기재 금지. LLM 재판정으로 조정된 경우 실제 위험도 기준.
