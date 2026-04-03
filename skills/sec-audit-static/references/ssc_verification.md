# SSC 정합성 검증 절차 (Phase 5)

Fortify SSC에서 수집한 High/Critical 취약점 건을 소스코드와 교차하여 TP/FP를 판정하고
별도 보고서를 생성하는 선택적 Phase.

기존 Phase 1~4(SAST 자체 진단)와 독립적으로 실행 가능하며, 동일 testbed가 있어야 한다.

---

## 사전 준비

### 인증 설정 (.env)

```bash
SSC_BASE_URL=https://ssc.skplanet.com/ssc
SSC_TOKEN=<CIToken 또는 UnifiedLoginToken>  # 우선 사용
# SSC_USERNAME=<AD계정>   # 토큰 없을 때 fallback
# SSC_PASSWORD=<AD비밀번호>
```

### 토큰 발급 방법

**A. 웹 UI (권장)**:
1. `https://ssc.skplanet.com/ssc/html/ssc/profile` 접속
2. Token Management 섹션 → Generate Token (Type: `CIToken`)
3. 발급된 값 → `.env`의 `SSC_TOKEN=` 에 추가

**B. API (AD 계정)**:
```bash
python3 tools/scripts/fetch_ssc.py --generate-token
# .env에 SSC_USERNAME=<AD계정>, SSC_PASSWORD=<AD비밀번호> 추가 후 실행
```

---

## Step 5-0: 브랜치/커밋 일치 검증 ⚠️ 필수

> SSC 스캔 대상과 testbed 소스코드 버전이 다르면 finding 라인 번호가 맞지 않거나(stale),
> 이미 수정된 취약점이 여전히 TP로 잘못 판정될 수 있다.
> **Step 5-1 수행 전에 반드시 일치 여부를 확인한다.**

### 자동 검증 (권장)

`--testbed` 옵션을 사용하면 fetch 단계에서 브랜치/커밋을 자동 비교한다.

```bash
python3 tools/scripts/fetch_ssc.py \
    --project "<SSC 프로젝트명>" \
    --version "<버전명>" \
    --testbed testbed/<project>/<repo>@<branch>@<commit> \
    -o state/<prefix>/ssc_findings.json
```

**출력 예시**:
```
[SSC] 대상: OCBWEBVIEW/ocb-webview-api / 1_dev (id=292)
[SSC] 스캔 커밋: 886aad0f3c12  ← SSC가 스캔한 커밋
[SSC] testbed: branch=master, commit=886aad0
[SSC] 브랜치 일치 검증: ✅ MATCH — 커밋 해시 일치: SSC=886aad0f3c12, testbed=886aad0
```

결과는 출력 JSON의 `metadata.branch_match`에 저장된다.

### 판정 기준

| status | 의미 | stale 위험 | 처리 방침 |
|--------|------|-----------|----------|
| **MATCH** | 커밋 해시 일치 | 낮음 | 정상 진행 |
| **PARTIAL** | 버전명/브랜치명 유사 일치, 커밋 미확인 | 중간 | 진행하되 stale finding 주의. 라인 OOB 시 stale로 판정. |
| **MISMATCH** | 버전명 또는 커밋 불일치 | 높음 | ⚠️ **진행 전 검토 필요**. testbed를 SSC 스캔 시점 커밋으로 교체하거나, 전체 결과를 참고용으로만 활용. |
| **UNKNOWN** | SSC에서 커밋 정보 미제공 | 알 수 없음 | 수동 확인 (아래 "수동 확인" 절차) |

### 수동 확인 절차 (SSC가 커밋 정보 미제공 시)

SSC가 커밋 해시를 API에 노출하지 않는 경우:

1. **SSC 웹 UI 확인**: `SSC > 프로젝트 > 버전 > 아티팩트` 탭 → FPR 파일 업로드 날짜 확인
2. **최근 스캔 날짜 vs 소스 커밋 날짜 비교**:
   ```bash
   # testbed 디렉토리 내 최근 커밋 날짜 확인
   git -C testbed/<project>/<repo>@<branch>@<commit> log -1 --format="%ci %H"
   ```
3. **SSC `foundDate` 분포 확인**: findings의 `found_date` 가 최근 스캔과 일치하는지 확인
4. **라인 번호 OOB 비율**: Step 5-2 검증 중 "라인 범위 초과" 건이 전체의 10% 초과 시 → 버전 불일치 의심, 즉시 보고서에 명시

### branch_match JSON 구조

```json
{
  "metadata": {
    "ssc_scan_commit": "886aad0f3c12",
    "branch_match": {
      "ssc_version_name":  "1_dev",
      "ssc_commit":        "886aad0f3c12",
      "testbed_branch":    "master",
      "testbed_commit":    "886aad0",
      "status":            "MATCH",
      "detail":            "커밋 해시 일치: SSC=886aad0f3c12, testbed=886aad0",
      "stale_risk":        "낮음"
    }
  }
}
```

---

## Step 5-1: SSC findings 수집

```bash
# 브랜치 일치 검증 + findings 수집 (통합 권장)
python3 tools/scripts/fetch_ssc.py \
    --project "<SSC 프로젝트명>" \
    --version "<버전명>" \
    --testbed testbed/<project>/<repo>@<branch>@<commit> \
    -o state/<prefix>/ssc_findings.json

# 버전 ID 직접 지정
python3 tools/scripts/fetch_ssc.py --list-projects
python3 tools/scripts/fetch_ssc.py \
    --version-id 12345 \
    --testbed testbed/<project>/<repo>@<branch>@<commit> \
    -o state/<prefix>/ssc_findings.json
```

**수집 기준**:
- `friority`: Critical 또는 High
- `suppressed: false` (억제된 건 제외)
- `hidden: false` 포함 여부는 SSC 설정에 따름

**출력**: `state/<prefix>/ssc_findings.json`
```json
{
  "metadata": {
    "project_name": "...", "version_name": "...", "version_id": 12345,
    "ssc_scan_commit": "886aad0f3c12",
    "branch_match": { "status": "MATCH", "stale_risk": "낮음", ... }
  },
  "summary": {
    "total_issues_in_version": 200,
    "high_critical_count": 45,
    "by_friority": { "Critical": 10, "High": 35 },
    "by_kingdom": { "Input Validation and Representation": 20, ... }
  },
  "findings": [
    {
      "ssc_issue_id": "abc123",
      "issue_name": "SQL Injection",
      "friority": "Critical",
      "severity": 5.0,
      "kingdom": "Input Validation and Representation",
      "category_path": "SQL Injection/Parameterization",
      "primary_location": "src/main/java/com/example/FooService.java",
      "line_number": 42,
      "issue_status": "Unreviewed",
      "reviewed": false,
      "suppressed": false,
      "verification": {
        "result": null,
        "judgment": null,
        "code_evidence": null,
        "recommendation": null
      }
    }
  ]
}
```

---

## Step 5-2: LLM 정합성 검증 — 유형별 그룹 검증 (Approach A)

**핵심 원칙**: issue_name이 같은 finding은 동일한 Fortify 분석 규칙으로 탐지된 것이므로
대표 건의 TP/FP 패턴이 그룹 전체에 적용된다.
→ 14개 그룹 × 대표 3~5건 분석으로 1,314건을 효율 처리.

---

### 사전 준비: 그룹 현황 파악

```python
import json
from collections import defaultdict

with open("state/<prefix>/ssc_findings.json") as f:
    ssc = json.load(f)

groups = defaultdict(list)
for f in ssc["findings"]:
    groups[f["issue_name"]].append(f)

# Critical 보유 그룹 우선 출력
for name, items in sorted(groups.items(),
        key=lambda x: (-sum(1 for i in x[1] if i["friority"]=="Critical"), -len(x[1]))):
    crits = sum(1 for i in items if i["friority"] == "Critical")
    print(f"[{len(items):>4}건 / Critical:{crits:>3}]  {name}")
```

### 검증 순서 (Critical 수 기준 우선)

아래 순서로 그룹을 처리한다. Critical=0인 그룹은 마지막에 처리.

| 순서 | issue_name | 전체 | Critical | 검증 전략 |
|------|-----------|------|---------|----------|
| 1 | Privacy Violation | 621 | 213 | 대표 5건 분석 → 패턴 분류 (개인정보 로깅/응답 노출 구분) |
| 2 | Cross-Site Scripting: Persistent | 30 | 30 | 대표 3건 분석 → DB저장 경로 + 응답 타입 확인 |
| 3 | Path Manipulation | 9 | 9 | 전건 분석 (9건) |
| 4 | SQL Injection | 7 | 7 | 전건 분석 (7건) |
| 5 | Cross-Site Scripting: Reflected | 7 | 7 | 전건 분석 (7건) |
| 6 | Insecure Transport | 6 | 6 | 전건 분석 (6건) |
| 7 | Dynamic Code Evaluation: Unsafe Deserialization | 1 | 1 | 단건 분석 |
| 8 | Insecure SSL: Server Identity Verification Disabled | 1 | 1 | 단건 분석 |
| 9 | Privacy Violation: Heap Inspection | 17 | 0 | 대표 3건 → 패턴 적용 |
| 10 | Server-Side Request Forgery | 59 | 0 | 대표 5건 → URL 소스 확인 |
| 11 | HTTP Parameter Pollution | 33 | 0 | 대표 3건 → 파라미터 전달 경로 확인 |
| 12 | Access Control: Database | 520 | 0 | 대표 5건 → 인증/인가 로직 확인 |
| 13 | Mass Assignment: Sensitive Field Exposure | 2 | 0 | 전건 분석 (2건) |
| 14 | Weak Encryption: Inadequate RSA Padding | 1 | 0 | 단건 분석 |

---

### 그룹별 검증 절차

#### Step A: 그룹 findings 로드

```python
group_name = "SQL Injection"   # 현재 검증 그룹
items = groups[group_name]
# Critical → High 순 정렬, 대표 건 선택 (최대 5건, 다양한 파일 우선)
seen_files = set()
reps = []
for item in sorted(items, key=lambda x: 0 if x["friority"]=="Critical" else 1):
    fp = item["full_file_path"]
    if fp not in seen_files:
        reps.append(item)
        seen_files.add(fp)
    if len(reps) >= 5:
        break
print(f"대표 건 {len(reps)}개 / 전체 {len(items)}건")
for r in reps:
    print(f"  [{r['friority']}] {r['full_file_path']}:{r['line_number']}  — {r['ssc_issue_id'][:8]}")
```

#### Step B: 대표 건 소스코드 검증

각 대표 건에 대해:

```
1. full_file_path → testbed/<repo>/<full_file_path> 열기
   ±30 라인 컨텍스트 확인 (line_number 기준)

2. issue_name별 검증 포인트:

   SQL Injection
   └─ 동적 쿼리 문자열 결합(+/"") / MyBatis ${} / 미파라미터화 쿼리 확인
   └─ Prepared Statement / @Query :param / MyBatis #{} → 양호

   XSS: Persistent
   └─ DB 저장 경로: 사용자 입력 → Repository 저장 확인
   └─ 응답 타입: @RestController/REST_JSON → 양호, HTML/JSP 렌더링 → 취약 가능

   XSS: Reflected
   └─ 사용자 입력 파라미터 → 응답에 이스케이프 없이 반영 여부
   └─ 전역 XSS 필터(Lucy/자체) 적용 여부

   Path Manipulation
   └─ 사용자 입력 → File/Path 생성에 검증 없이 사용 여부
   └─ 화이트리스트 경로 제한 / normalize 적용 → 양호

   Privacy Violation
   └─ 개인정보(이름/주민번호/카드번호/전화번호 등) → 로그 출력 또는 응답 노출 여부
   └─ 마스킹 처리 여부 확인

   Access Control: Database
   └─ DB 접근 시 현재 로그인 사용자 기준 필터링 여부
   └─ userId/memberId 파라미터가 타인 데이터 조회 가능한지 확인

   SSRF
   └─ 사용자 입력 URL → 외부 HTTP 요청에 직접 사용 여부
   └─ 허용 도메인 화이트리스트 / 내부망 차단 여부

   Insecure Transport
   └─ HTTP(비암호화) 사용 / SSL 검증 비활성화 여부
   └─ HttpsURLConnection / TrustAllCertificates 패턴 확인

3. 판정
   ┌──────────────┬────────────────────────────────────────────────┐
   │ 취약 (TP)    │ 취약 패턴 확인 + 사용자 입력 도달 경로 존재     │
   ├──────────────┼────────────────────────────────────────────────┤
   │ 양호 (FP)    │ 안전한 API / 정적값 / 프레임워크 자동처리       │
   ├──────────────┼────────────────────────────────────────────────┤
   │ 검토필요     │ 외부 의존성 / 동적 로딩 / 트레이스 불완전        │
   └──────────────┴────────────────────────────────────────────────┘
```

#### Step C: 그룹 전체에 패턴 적용

대표 건 분석 후 **그룹 패턴 판정**을 확정하고 나머지 건에 일괄 적용한다.

```python
# 그룹 패턴 판정 결과 예시
GROUP_PATTERN = {
    "result": "양호(FP)",          # 대표 건 분석으로 확정된 그룹 패턴
    "judgment": "Access Control: Database 탐지 건 전체가 ...(공통 FP 근거)",
    "code_evidence": None,          # 그룹 패턴 적용 건은 생략
    "recommendation": None,
    "diagnosis_method": "그룹패턴적용",   # 대표 건 외 나머지 건에 추가
}

# 나머지 건에 그룹 패턴 적용
non_reps = [i for i in items if i not in reps]
for item in non_reps:
    item["verification"] = {**GROUP_PATTERN}

# 대표 건은 개별 분석 결과 유지
for rep in reps:
    rep["verification"] = {
        "result": "...",           # 개별 판정
        "judgment": "...",
        "code_evidence": "...",
        "recommendation": "...",
        "diagnosis_method": "소스코드직접확인",
    }
```

#### Step D: 예외 처리

- 그룹 내 패턴이 **혼재** (일부 TP + 일부 FP): 파일별 sub-그룹으로 분리 처리
- 소스파일 **접근 불가** (testbed 미존재): `result: "검토필요"`, `judgment: "testbed 소스 미확인"`
- **단건 그룹** (1~9건): 전건 개별 분석

---

### 검증 완료 후 저장

```python
import json

with open("state/<prefix>/ssc_findings.json") as f:
    ssc = json.load(f)

# 그룹별 검증 완료된 findings로 교체
# (groups 딕셔너리의 모든 items를 flat list로 합침)
all_verified = [item for items in groups.values() for item in items]
ssc["findings"] = all_verified

# 검증 요약 통계 추가
verified_counts = {}
for f in all_verified:
    r = f["verification"].get("result") or "미검증"
    verified_counts[r] = verified_counts.get(r, 0) + 1
ssc["verification_summary"] = {
    "verified_at": "<YYYY-MM-DD>",
    "by_result": verified_counts,
    "by_group": {
        name: {
            "total": len(items),
            "취약": sum(1 for i in items if i["verification"].get("result")=="취약"),
            "FP": sum(1 for i in items if i["verification"].get("result")=="양호(FP)"),
            "검토필요": sum(1 for i in items if i["verification"].get("result")=="검토필요"),
        }
        for name, items in groups.items()
    }
}

with open("state/<prefix>/ssc_findings.json", "w") as f:
    json.dump(ssc, f, ensure_ascii=False, indent=2)
print(f"저장 완료. 검증 결과: {verified_counts}")
```

---

## Step 5-3: 정합성 보고서 생성

검증 완료된 `state/<prefix>/ssc_findings.json`으로 Markdown 보고서를 생성한다.

```bash
python3 tools/scripts/generate_ssc_report.py \
    state/<prefix>/ssc_findings.json \
    -o state/<prefix>/ssc_report.md
```

> `generate_ssc_report.py`는 아직 구현 예정. 임시로 아래 LLM 인라인 생성 사용.

### LLM 인라인 보고서 생성 (generate_ssc_report.py 대체)

아래 구조로 `state/<prefix>/ssc_report.md`를 직접 생성한다.

#### 심각도 색상 규칙 (표준)

`publish_confluence.py`의 `_postprocess_severity_in_tables()`가 Markdown 테이블 셀에서
심각도 키워드를 **자동으로** Confluence 상태 배지로 변환한다. 별도 마크업 불필요.

| 키워드 | Confluence 색상 | 의미 |
|--------|----------------|------|
| `Critical` | 🔴 Red | 즉시 조치 |
| `High` | 🟡 Yellow (amber/주황) | 단기 조치 |
| `Medium` | 🟡 Yellow | 중기 조치 |
| `Low` | 🔵 Blue | 장기/모니터링 |
| `Info` | ⚫ Grey | 정보 |

> Confluence 상태 매크로에 Orange 색상이 없으므로 High는 Yellow(amber)로 렌더링.
> Markdown 보고서에 `Critical` / `High` 텍스트를 그대로 쓰면 게시 시 자동 변환됨.

```markdown
# Fortify SSC 정합성 검증 보고서

**대상 레포지토리**: <프로젝트> / <레포>
**SSC 버전**: <version_name> (version_id=N)
**검증 기준 브랜치**: <branch>@<commit>
**검증 일자**: YYYY-MM-DD
**검증 방식**: Approach A — issue_name 그룹 기반 대표 사례 검증 후 패턴 일괄 적용

---

## 1. 요약

| 항목 | 수치 |
|------|------|
| SSC High/Critical 수집 건수 | N건 |
| 취약 확인 (True Positive) | **N건** (중복 병합 후) |
| 양호 판정 (False Positive) | N건 |
| 추가 검토 필요 | N건 |

> 취약 확인 건수는 동일 취약점 유형 + 동일 파일 기준으로 병합한 수치임 (원본 SSC 발견 건수 N건).

### 그룹별 검증 결과

| # | issue_name | 전체 | Critical | 취약(TP) | 양호(FP) | 검토필요 | 비고 |
|---|-----------|------|---------|---------|---------|---------|------|
| 1 | ... | N | N | N | N | N | ... |
| **합계** | | **N** | **N** | **N** | **N** | **N** | |

---

## 2. 취약 확인 건 상세 (True Positive)

### 취약 확인 건 목록 (N건, 병합 기준)

<!-- 정렬 규칙: Critical → High 순. 동일 취약점 유형 + 동일 파일은 라인 무관하게 1행으로 병합. -->
<!-- 심각도 셀(Critical/High)은 Confluence 게시 시 자동으로 컬러 배지로 변환됨 -->

| # | 취약점 유형 | 심각도 | 파일 | 탐지 라인 | 판정 |
|---|-----------|--------|------|---------|------|
| 1 | <issue_name> | Critical | `파일명.java` | 164 | **취약** |
| 2 | <issue_name> | High | `파일명.java` | 198, 238, 317 | **취약** |
| ... | | | | | |

---

### 2-1. <취약점 유형> — Critical

<!-- 관련 파일 expand 블록: <details><summary>Title</summary>Body</details> 문법 사용 -->
<!-- publish_confluence.py가 Confluence expand 매크로로 자동 변환함 -->

<details>
<summary>관련 파일 (N개 파일, M개 지점)</summary>

| 파일 | 경로 | 탐지 라인 | 비고 |
|------|------|---------|------|
| `파일명.java` | `src/main/java/.../패키지/` | 164 | 간략 설명 |
| `파일명2.java` | `src/main/java/.../패키지/` | 198, 238 | 간략 설명 |

</details>

#### 취약 패턴 (대표 코드)

```java
// 대표 코드
```

#### 테인트 추적 경로

```
[입력 소스] → [전파 경로] → [실행 지점]
```

#### 영향 범위

...

#### 조치 방안

```java
// 수정 예시
```

---

## 3. 양호 판정 요약 (False Positive)

| issue_name | 건수 | FP 판정 근거 |
|-----------|------|-------------|
| ... | N | ... |

---

## 4. 조치 우선순위

| 우선순위 | 취약점 | 파일 | CVSS 추정 | 조치 기한 |
|---------|-------|------|---------|---------|
| **P1 — 즉시** | ... | `...` | 9.8 (Critical) | 즉시 조치 |
| **P2 — 단기** | ... | `...` | 7.4 (High) | 1개월 이내 |

---

## 부록. 검증 방법론

- **수집**: Fortify SSC REST API (`/api/v1/issues`) — High/Critical, suppressed=false 필터
- **검증**: Approach A + LLM 추가분석
- **판정 기준**:
  - **취약**: taint source→sink 경로 확인, 방어 코드 부재
  - **양호(FP)**: 프레임워크/설계상 위험 미실현, 또는 SSC 탐지 오류
  - **검토필요**: 소스 미존재(stale), 라인 범위 초과

---

---

## [참조] 추가 검토 필요

| # | issue_name | 파일 | 라인 | LLM 분석 결과 | 판정 |
|---|-----------|------|------|--------------|------|
| 1 | ... | `...` | N | ... | **검토필요** |

---

## [참조] 주요 FP 패턴 (이 레포 특이사항)

1. **<FP 유형>**: <근거>
```

---

---

## Step 5-4: SSC TP → SAST 피드백 환류

> Phase 5 완료 후 수행. SSC에서 확인된 TP 취약점이 현재 `/sec-audit-static` SAST 절차에서
> 탐지 가능했는지 분석하고, 미탐이면 개선 액션을 적용한다.
> 상세 절차: `references/ssc_feedback_ruleset.md`

### 실행 절차

```
1. TP 목록 확인: state/<prefix>/ssc_findings.json 의 result=="취약" 건
2. SAST 결과 대조: Phase 2~3 산출물에서 동일 파일/라인 탐지 여부 확인
3. 분류:
   - Type A (탐지 가능 → 미탐): 스크립트 패턴 / LLM 체크리스트 보완
   - Type B (범위 밖): Semgrep 룰 추가 + task prompt 체크리스트 추가
4. ssc_feedback_ruleset.md 업데이트 (누적 기록)
```

### 미탐 원인 코드

| 코드 | 의미 |
|------|------|
| `PAT-MISSING` | 스크립트 패턴 목록에 API/메서드 없음 |
| `TAINT-BREAK` | 멀티홉 테인트 체인 미추적 |
| `FRAMEWORK-DEFAULT` | 프레임워크 기본값이 취약 (설정 누락 패턴) |
| `SCOPE-MISSING` | 현재 task 범위 밖 (신규 카테고리) |
| `LLM-FP` | LLM 오판정 |

### 개선 적용 기준

| Type A 개선 | Type B 개선 |
|-------------|-------------|
| `injection_diagnosis_criteria.md` 패턴 추가 | `references/rules/semgrep/` 신규 룰 추가 |
| `taint_tracking.md` 소스→싱크 등록 | `task_prompts/task_2*.md` 체크리스트 추가 |
| scan 스크립트 정규식 패턴 보완 | 신규 scan 스크립트 패턴 추가 검토 |

---

## Phase 5 완료 조건

```
□ state/<prefix>/ssc_findings.json의 모든 finding에 verification.result 채워짐
□ 취약 건: code_evidence 및 recommendation 필수
□ FP 건: judgment에 FP 근거 명시
□ 검토필요 건: LLM 추가분석 수행 → 전건 TP 또는 FP로 해소
□ 보고서 생성: state/<prefix>/ssc_report.md (아래 섹션 전체 포함)
   □ 섹션1: 요약 + 그룹별 검증 결과 표 (실제 그룹 수)
   □ 섹션2: 취약 확인 건 목록 표 — Critical → High 순 정렬, 동일 유형+파일 병합 (1건=1행)
   □ 섹션2 하위: 취약점 유형별 상세 — 각 항목에 <details><summary>관련 파일 목록</summary>표</details> expand 블록 포함
   □ 섹션2 하위: 코드 증적 + 테인트 경로 + 조치 방안
   □ 섹션3: 양호 판정 요약 (issue_name별 FP 근거)
   □ 섹션4: 조치 우선순위
   □ 부록: 검증 방법론
   □ [참조] 추가 검토 필요 — 보고서 맨 끝 참조 섹션으로 분리
   □ [참조] 주요 FP 패턴 — 보고서 맨 끝 참조 섹션으로 분리
□ 심각도 색상 — Markdown에 "Critical"/"High" 텍스트 그대로 사용
   (게시 시 _postprocess_severity_in_tables()가 자동으로 컬러 배지 변환:
    Critical=🔴Red / High=🟡Yellow(amber) / Medium=🟡Yellow / Low=🔵Blue)
□ Confluence 게시 완료 (필수)
   □ confluence_page_map.json에 테스트N 그룹 등록 (type: "doc")
   □ python3 tools/scripts/publish_confluence.py --filter-group "테스트N" 실행
   □ page_id 확인 (created/updated 로그)
□ Step 5-4: TP 건 분류 완료 + ssc_feedback_ruleset.md 업데이트
   □ LLM 검토 게이트([5-4-2]) 통과 후 승인 건만 적용
```

---

## 유형별 보고서 작성 가이드라인 (실무 컨설턴트 관점)

> 아래 항목은 개발팀 전달 시 발생하는 마찰과 오해를 방지하기 위한 표준 주의사항이다.
> 각 취약점 유형의 "조치 방안" 섹션에 반드시 해당 맥락을 포함할 것.

### SQL Injection — 테이블명 바인딩 불가 명시

EntityManager.createNativeQuery() 패턴에서 테이블명(`tableName`)이 동적으로 조립되는 경우:

> **개발팀 전달 시 필수 강조**: `tableName`은 JPA Named Parameter(`:param`)로 바인딩할 수 없다.
> 테이블명은 반드시 코드 내부에서 **Enum 또는 Map 형태의 화이트리스트**로만 검증·치환해야 하며,
> 클라이언트가 보낸 값을 그대로 쿼리에 조립해서는 안 된다.

```java
// 올바른 패턴 — 테이블명은 화이트리스트 검증, 컬럼값은 Named Parameter 바인딩
private static final Map<String, String> ALLOWED_TABLES = Map.of(
    "user", "tb_user",
    "point", "tb_point"
);
String safeTable = ALLOWED_TABLES.get(inputTableKey);  // null이면 예외
String query = "DELETE FROM " + safeTable + " WHERE mbr_id = :mbrId";
em.createNativeQuery(query).setParameter("mbrId", mbrId).executeUpdate();
```

---

### Insecure Transport (SSL 우회) — 운영/테스트 환경 선행 확인

`NoCertRestTemplate`, `TrustAllRestTemplate` 등 클래스명에 의도적 비활성화 의미가 있는 경우:

> **조치 지시 전 선행 확인 필수**: "이 클래스가 운영(Production) 환경에서 실제 민감 데이터
> (결제·개인정보·보험정보 등) 전송에 사용되고 있는가?"를 먼저 확인한다.
>
> | 환경 | 판정 | 심각도 |
> |------|------|--------|
> | 운영에서 실제 민감 데이터 전송 | 취약 | Critical 유지 |
> | 테스트 환경 전용, 운영 미사용 | 양호 가능성 | Info로 하향 검토 |

개발자가 제휴사 테스트 서버의 만료·사설 인증서 문제로 임시 우회한 경우가 많으므로,
무조건 즉시 조치 요구보다는 **운영 사용 여부 확인 → 판정 확정 → 조치** 순서로 진행한다.

---

### Insecure Transport (gRPC usePlaintext) — 서비스 메시 아키텍처 확인 필수

**절대 "취약" 단정 금지** — 반드시 인프라 아키텍처를 확인한 후 판정한다.

> Kubernetes + Istio / Linkerd 등 서비스 메시 환경에서는 사이드카(Sidecar) 프록시가
> 투명하게 mTLS 암호화를 처리한다. 애플리케이션 코드에서 `usePlaintext()`를 사용하는 것이
> **클라우드 네이티브 표준 아키텍처(Best Practice)**이므로, 이 환경에서는 코드가 안전하다.

| 인프라 환경 | 판정 | 심각도 | 조치 |
|------------|------|--------|------|
| 서비스 메시(Istio/Linkerd) mTLS 확인 | 양호(FP) | — | 불필요 |
| 서비스 메시 미확인 | 정보 | 2 | 인프라팀 확인 요청 |
| 서비스 메시 없음 + 내부 클러스터 통신 | 잠재적 위협 | 2~3 | mTLS 구성 권고 |
| 서비스 메시 없음 + 클러스터 외부 통신 | 취약 | 3 | useTransportSecurity() 적용 |

인프라 확인 방법:
```bash
# k8s manifest에서 Istio sidecar 주입 어노테이션 확인
kubectl get pod <pod-name> -o yaml | grep -E "istio|sidecar"
# 또는 namespace 레벨 확인
kubectl get namespace <ns> -o yaml | grep istio-injection
```

---

### Unsafe Deserialization (RedisTemplate) — JSON 직렬화 교체 표준 조치

`new RedisTemplate<>()` + 직렬화 설정 누락 패턴은 완벽한 TP로 확정 후 즉시 조치 지시.

```java
// 표준 조치 — GenericJackson2JsonRedisSerializer로 전환
redisTemplate.setDefaultSerializer(new GenericJackson2JsonRedisSerializer());
redisTemplate.setKeySerializer(new StringRedisSerializer());
redisTemplate.setValueSerializer(new GenericJackson2JsonRedisSerializer());
```

`StringRedisTemplate`은 문자열 전용이므로 JDK 직렬화 적용되지 않음 → FP 처리.

---

## 주의사항

- SSC `reviewed: true` + 판정 "취약" → **불일치** 케이스 → judgment에 명시
- `suppressed: true` 건은 수집하지 않음 (fetch_ssc.py가 제외 처리)
- 동일 파일 내 50건 이상 같은 패턴 → 대표 5건만 상세 분석, 나머지는 일괄 처리
