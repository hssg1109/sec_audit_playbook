# Cross-Verification Procedure

자동 스캐너 결과에 대한 교차검증 및 수동 심층진단 절차. 오탐 제거 및 정밀도 향상 목적.

---

## Phase 3-1: 자동판정 "취약" 항목 교차검증

### 적용 시점

- Phase 2 자동 스캔 완료 후
- 자동 판정 `result: "취약"` 건에 대해 전수 교차검증 실시

### Step 1: 데이터 흐름 추적 (Source → Sink)

```
Controller (@RequestParam/PathVariable/RequestBody)
    → Service (비즈니스 로직)
        → Repository (데이터 접근)
            → SQL Builder (쿼리 생성 - Kotlin/Java)
                → DB 실행
```

각 단계에서 취약 파라미터의 **값의 출처**를 확인:
- 사용자 입력 (HTTP 요청) → **취약 가능**
- 내부 하드코딩 값 → **정보 (잠재적 위험)**
- DB 조회 결과 → **검토 필요** (2차 인젝션 가능성)
- Spring 설정값 (`@Value`) → **정보 (타입에 따라)**

### Step 2: 타입 안전성 확인

| 타입 | SQL Injection 가능 여부 |
|------|----------------------|
| `String` | 가능 - 문자열 조작 가능 |
| `long`, `int`, `boolean` | 불가 - 숫자/불린만 허용 |
| `enum` | 불가 - 정의된 값만 허용 |
| `List<String>` | 가능 - 개별 요소 확인 필요 |

### Step 3: 코드 활성화 여부

- `/* ... */` 블록 주석으로 감싼 클래스/메서드 → "정보(비활성 코드)"
- `@Deprecated` + 호출부 없음 → "정보(미사용 코드)"
- `@Profile("test")` 등 특정 환경 전용 → 명시

### Step 4: 분기 경로 도달 확인

Service에서 switch/if 분기로 여러 Repository 메서드를 호출하는 경우:
- Controller에서 전달되는 `filter`, `type` 등의 값으로 **어떤 case에 도달하는지** 확인
- 취약 메서드가 포함된 case에 도달하지 않으면 → "정보(경로 미도달, 오탐)"

### Step 5: 최종 판정

| 조건 | 판정 |
|------|------|
| 사용자 입력 String → SQL 직접 삽입 (검증 없음) | **취약** |
| 사용자 입력이지만 화이트리스트/enum 검증 존재 | 양호 |
| 하드코딩 값만 사용 | 정보 (잠재적 위험) |
| long/int 타입 설정값 | 정보 (타입 안전) |
| 주석 처리 비활성 코드 | 정보 (비활성 코드) |
| 코드 경로 미도달 | 정보 (오탐) |

### 결과 업데이트

교차검증 완료 시 JSON 결과에 반영:
```json
{
  "result": "정보",
  "diagnosis_type": "정보: 잠재적 위험 (하드코딩 값만 사용)",
  "diagnosis_detail": "정보(잠재적 위험): ... 상세 사유 ...",
  "diagnosis_method": "교차검증(수동)",
  "needs_review": false
}
```

### 보고서 표기

교차검증으로 재분류된 건은 보고서에 다음과 같이 구분 표기:
- **취약(확인됨)**: 교차검증 통과 - 실제 Exploit 가능
- **정보(잠재적 위험)**: 코드 패턴은 취약하나 현재 Exploit 불가
- **정보(비활성 코드)**: 주석 처리 등으로 실행되지 않는 코드
- **정보(오탐)**: 코드 경로 분석 결과 취약 메서드에 도달 불가

---

## Phase 3-2: "정보/수동검토" 항목 LLM 수동 심층진단

### 적용 시점

Phase 3-1 완료 후, 아래 조건 중 하나 이상에 해당하는 항목을 대상으로 실시:
- `result: "정보"` 이면서 `needs_review: true`인 항목
- `result: "취약"` 이면서 `diagnosis_method: "추정"` 또는 `taint_confirmed: null`인 항목
- `diagnosis_type`이 `[잠재] 취약한 쿼리 구조`인 항목
- **스캐너 Taint 추적 실패** (`diagnosis_type ∈ {"자동 판정 불가", "DB 접근 미확인", "추적 불가"}`) — 인젝션 전용 절차 아래 참조

---

### Phase 3-2 [인젝션 전용]: 스캐너 추적 실패 API LLM 취약 여부 갱신 절차

> **이 절차는 scan_injection_enhanced.py가 DB 흐름을 따라가지 못한 API들에 대해
> LLM이 직접 코드를 읽고 취약 여부를 확정하여 task22_llm.json에 반영하는 전체 과정이다.**

#### Step 0: 추적 실패 규모 및 유형 파악

```bash
python3 -c "
import json
from collections import Counter
d = json.load(open('state/<prefix>/injection.json'))
eps = d.get('endpoint_diagnoses', [])
failed = [e for e in eps if e.get('diagnosis_type') in [
    '자동 판정 불가', 'DB 접근 미확인', '추적 불가'
] or e.get('access_type') == 'mybatis_dynamic_review']
cnt = Counter(e.get('diagnosis_type') or e.get('access_type','?') for e in failed)
print(f'총 추적 실패: {len(failed)}건')
for k, v in cnt.most_common(): print(f'  {v}건: {k}')
"
```

`injection_diagnosis_criteria.md Section 9.1` 유형표를 참조하여 각 유형의 **근본 원인**을 파악한다.

#### Step 1: "DB 로직 없음" 조기 확정 (분리 우선)

추적 실패 API 중 **DB 접근 자체가 없는 것을 먼저 분리**하면 실제 확인 대상이 크게 줄어든다.

```bash
# 각 Service 클래스 파일에서 DB 키워드 검색
rg "(Repository|Mapper|JdbcTemplate|SqlSession|createQuery|executeQuery|entityManager)" \
   <ServiceFile.kt> -c
# 0건: DB 접근 없음 확정

# FeignClient/RestTemplate 외부 HTTP 클라이언트 사용 여부
rg "(@FeignClient|restTemplate\.|webClient\.|FeignClient)" <ServiceFile> -l
# 발견: 외부 API 위임 → DB 없음

# Redis 전용 서비스 여부
rg "(redisTemplate\.|StringRedisTemplate|@Cacheable|@RedisHash)" <ServiceFile> -l
```

**확정된 "DB 없음" endpoint** → `group_judgments`에 별도 group 추가:
```json
{
  "group": "DB 접근 없음 (N건)",
  "root_cause": "FeignClient 외부 API 호출 전용 서비스 / Redis 전용 / 단순 계산 로직",
  "judgment": "해당없음(DB접근없음)",
  "llm_resolution_method": "Service 직접 확인: DB 키워드 0건, FeignClient 호출만 존재",
  "endpoints_reviewed": [...]
}
```

#### Step 2: 나머지 추적 실패 API 코드 확인 → 취약 여부 판정

**그룹별 대표 endpoint 샘플링**:
- 동일 Service/DAO 클래스를 공유하는 endpoint들은 **그룹으로 묶어** 대표 3~5개만 확인
- 대표 샘플에서 확인된 패턴을 **그룹 전체에 적용**

**코드 확인 순서**:

```
[1] Controller 파일 탐색
    rg "매핑경로" testbed/ -l   # Controller 파일 찾기

[2] Service 구현체 탐색 (인터페이스인 경우)
    rg "implements <ServiceName>" testbed/ -l
    rg "class <ServiceName>Impl" testbed/ -l

[3] DAO/Repository 구현체 탐색
    rg "class <DaoName>Impl" testbed/ -l
    rg "@Mapper" <파일> -l

[4] SQL 패턴 확인
    # MyBatis XML 전수 ${}  스캔
    find testbed/ -name "*.xml" | xargs grep -n '\${' 2>/dev/null | grep -v "<!--"
    # iBatis $param$ 스캔
    find testbed/ -name "*.xml" | xargs grep -n '\$[a-zA-Z]' 2>/dev/null | grep -v "<!--"
    # JPA @Query 문자열 결합
    rg '@Query.*\+' testbed/ -n
    # JDBC 문자열 결합
    rg 'execute\(.*\+|query\(.*\+|update\(.*\+' testbed/ -n
```

**판정 적용**:

| 확인 결과 | judgment | 출력 |
|---|---|---|
| DB 없음 확정 | `해당없음(DB접근없음)` | group으로 분리 (Step 1) |
| `#{}` / `:param` 바인딩만 확인 | `양호` | group_judgments.services_reviewed |
| `${}` 있으나 외부 입력 미도달 | `정보` | group_judgments + 근거 |
| `${}` + 외부 String 입력 직삽 | `취약` | findings INJ-00N 등록 |
| 그룹 내 예외 endpoint | 개별 판정 | endpoint_verdicts 배열 |

#### Step 3: task22_llm.json 최종 갱신

```json
{
  "task_id": "2-2",
  "status": "completed",
  "sqli_endpoint_review": {
    "total_info_endpoints": N,
    "no_db_logic_count": M,           ← DB 없음 확정 건수
    "no_db_logic_note": "FeignClient N건, Redis M건",
    "group_judgments": [...],          ← DB없음 group + 패턴별 group
    "endpoint_verdicts": [...],        ← 그룹 판정과 다른 개별 endpoint
    "overall_sqli_judgment": "양호|정보|취약"
  },
  "findings": [...]                    ← 취약 확정 건만
}
```

#### Step 4: 완료 검증

```bash
# 추적 실패 전체 건수
python3 -c "
import json
d = json.load(open('state/<prefix>/injection.json'))
failed = [e for e in d.get('endpoint_diagnoses',[]) if e.get('diagnosis_type') in [
    '자동 판정 불가', 'DB 접근 미확인', '추적 불가'
] or e.get('access_type')=='mybatis_dynamic_review']
print(len(failed), '건 추적 실패')
"
# → 이 수치 == group_judgments의 모든 endpoints_reviewed 합계이어야 함
```

---

### Phase 3-2 [일반]: needs_review/잠재취약 항목 수동진단 진행 방법

**대상**: `result: "정보"` + `needs_review: true`, `taint_confirmed: null`, `[잠재] 취약한 쿼리 구조`
(Taint 추적 실패 API는 위 [인젝션 전용] 절차로 처리)

`references/manual_review_prompt.md`에 정의된 LLM 수동진단 프롬프트를 사용합니다.

**절차**:

1. **페르소나 선언**: `manual_review_prompt.md`의 "LLM 페르소나 선언" 블록으로 LLM을 초기화합니다.
2. **항목 제공**: 아래 정보를 구조화하여 제공합니다.
   - API 경로 + HTTP Method
   - 스크립트 판정 결과 및 `diagnosis_detail`
   - Controller / Service / Repository 코드 스니펫
   - DTO 구조 (있는 경우)
3. **답변 원칙 준수 확인**: LLM이 불확실 사항을 명시하거나 추가 코드를 요청하는 경우,
   해당 코드를 제공하거나 "확인 불가" 사유로 `manual_review_note`에 기록합니다.
4. **JSON 결과 반영**: 판정 결과를 `diagnosis_method: "수동진단(LLM)"`으로 업데이트합니다.

### 판정 흐름

```
정보/수동검토 항목
    ↓
페르소나 + 코드 제공
    ↓
LLM 심층 분석
    ├─ 판정 가능 → 취약 / 양호 / 정보 결정
    │     └─ JSON 업데이트 (diagnosis_method: "수동진단(LLM)")
    └─ 추가 코드 필요 → 코드 보완 후 재분석
          └─ 끝내 불가 → needs_review: true 유지 + 사유 기록
```

### 결과 JSON 예시

```json
{
  "result": "취약",
  "diagnosis_type": "[실제] SQL Injection",
  "diagnosis_detail": "Controller String 파라미터가 DTO 래핑 없이 MyBatis ${} 구문에 직접 전달됨. OWASP A03:2021 기준 취약.",
  "diagnosis_method": "수동진단(LLM)",
  "needs_review": false,
  "manual_review_note": "추측 없음 — 코드 흐름 완전 추적 가능"
}
```

```json
{
  "result": "정보",
  "diagnosis_type": "정보: 확인 불가",
  "diagnosis_detail": "Service 위임 구조가 3단계 이상이어서 Taint 경로를 확정할 수 없음.",
  "diagnosis_method": "수동진단(LLM)",
  "needs_review": true,
  "manual_review_note": "ExchangePointsChainService 내부 구조 코드 미제공으로 판정 보류"
}
```

### 참고

상세 프롬프트 및 공식 문서 링크: `references/manual_review_prompt.md`
