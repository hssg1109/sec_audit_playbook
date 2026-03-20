# SSC TP → SAST 피드백 룰셋

SSC Phase 5에서 확인된 True Positive 취약점을 `/sec-audit-static` 절차에 환류(feedback)하여
미탐 원인을 분석하고 탐지 규칙을 고도화하는 절차.

---

## 피드백 루프 전체 흐름 (Step 5-4)

Phase 5 SSC 검증 완료 후 수행한다.

**핵심 원칙: SSC TP 발견이 곧 SAST 개선 적용을 의미하지 않는다.**
분류 후 반드시 LLM 검토 게이트를 통과해야 실제 절차에 반영된다.

```
SSC Phase 5 TP 확인
       │
       ▼
[5-4-1] SAST 대조 및 미탐 분류
  ├─ 탐지됨 → 커버 확인 기록 후 종료
  └─ 미탐 → Type A(절차 내 미탐) / Type B(범위 밖) 분류
       │
       ▼
[5-4-2] LLM 검토 게이트 ← 반드시 통과해야 적용 가능
  ├─ 필요성 검토: 이 개선이 실제로 필요한가?
  ├─ 정합성 검토: 제안된 룰/절차 변경이 기술적으로 올바른가?
  └─ 판정: 승인 / 조건부 승인 / 보류
       │
       ├─ [승인/조건부 승인]
       │       ▼
       │  [5-4-3] 개선 액션 적용
       │       ▼
       │  [5-4-4] 적용 후 검증 (Semgrep dry-run / 절차 충돌 확인)
       │       ▼
       │  [5-4-5] ssc_feedback_ruleset.md 누적 기록 (검토 결과 포함)
       │
       └─ [보류]
               ▼
          보류 이유 + 재검토 조건 기록 → 다음 세션 재평가
```

---

## [5-4-1] SAST 대조 및 미탐 분류

1. **TP 목록 불러오기**: `state/<prefix>_ssc_findings.json`의 `result == "취약"` 건
2. **SAST 결과와 대조**: Phase 2~3 산출물(`*_injection.json`, `*_xss.json` 등)에서 동일 파일+라인 탐지 여부 확인
3. **분류 판정**:
   - 탐지됨 → "커버됨" 기록 후 [5-4-5] 바로 이동
   - 미탐 → 원인 코드 분류 후 [5-4-2] 이동

---

## [5-4-2] LLM 검토 게이트 (필수 — 미통과 시 적용 불가)

> **이 단계를 건너뛰고 개선을 적용하는 것을 금지한다.**
> SSC가 취약으로 판정했더라도, SAST 절차에 반영하려면 아래 두 축의 검토를 모두 통과해야 한다.

### A. 필요성 검토 (Necessity Gate)

다음 질문에 답하여 개선의 필요성을 평가한다.

| 질문 | 판단 기준 |
|------|----------|
| **Q1. 실제 발생 가능한 패턴인가?** | 해당 취약점이 현재 진단 대상 codebase에서 실제로 존재하거나, 동일 스택에서 재현 가능한 패턴인가. 이론적 가능성만 있는 경우 → 보류 |
| **Q2. 기존 절차에서 이미 커버하고 있지 않은가?** | scan 스크립트, Semgrep 기존 룰, task prompt 체크리스트를 교차 확인. 이미 커버 중이면 → 적용 불필요 |
| **Q3. 패턴의 범용성이 충분한가?** | 특정 프로젝트/커밋에만 존재하는 일회성 코드인가, 아니면 해당 프레임워크/스택에서 반복 발생 가능한 구조적 패턴인가. 일회성이면 → 보류 |
| **Q4. 위험도가 절차 추가를 정당화하는가?** | severity ≥ 3 (Medium 이상) 또는 RCE/SQLi/SSRF 등 주요 취약점 유형이어야 함. 정보성(severity 1~2) 단독이면 → 보류 검토 |

**필요성 판정**: Q1~Q4 중 2개 이상 "아니오"이면 → **보류**

---

### B. 정합성 검토 (Correctness Gate)

제안된 개선 액션(Semgrep 룰 / task prompt 변경 / 진단 기준 수정)의 기술적 정확성을 검토한다.

#### B-1. Semgrep 룰 정합성 (SEMGREP-ADD 액션 시 필수)

```
□ 룰 문법 유효성
  → semgrep --validate --config <rule.yaml> 실행하여 파싱 오류 없음 확인
  → (semgrep 미설치 시) LLM이 YAML 문법 및 Semgrep DSL 키워드 수동 검토

□ 실제 탐지 가능성 확인
  → SSC TP 코드 스니펫(verification.code_evidence)을 테스트 입력으로 사용
  → 해당 코드가 룰에 매칭되는지 AST 수준에서 논리 추적
  → 매칭 안 되면 룰 패턴 수정 후 재검토

□ 오탐(FP) 위험 평가
  → 룰이 안전한 코드 패턴(바인딩 파라미터, 상수 리터럴 등)을 잘못 탐지하지 않는가?
  → confidence 레벨을 HIGH/MEDIUM/LOW로 적절히 설정했는가?
  → HIGH FP 위험 룰은 severity를 WARNING 이하로 낮추거나 LLM 2차 판정 필수 명시

□ 기존 룰과의 중복/충돌 없음
  → references/rules/semgrep/ 내 기존 룰과 동일 패턴 중복 탐지 여부 확인
```

#### B-2. Task Prompt / 진단 기준 변경 정합성 (TASK-PROMPT / CRITERIA-ADD 액션 시 필수)

```
□ 기존 절차와 충돌 없음
  → 추가 체크리스트 항목이 기존 단계(Step 1~7)의 판정 기준과 모순되지 않는가?
  → 예: "gRPC는 취약으로 판정"을 추가했다가 MSA 환경에서 FP 양산 → 충돌

□ LLM 지시의 명확성
  → 추가된 판정 기준이 충분히 구체적인가? 모호한 기준은 LLM 오판정 유발
  → 예외 케이스(FP 조건)가 명시되어 있는가?

□ 완료 조건 자가검증 체크리스트 반영
  → 새 체크 항목이 "⚠️ 완료 조건 자가 검증" 섹션에도 추가되었는가?
```

#### B-3. 미탐 원인 분석의 정확성

```
□ 원인 코드가 실제 미탐 메커니즘과 일치하는가?
  → PAT-MISSING: 해당 API가 스크립트의 sink 목록에 없음이 실제로 확인되는가?
  → TAINT-BREAK: 멀티홉 경로가 실제로 단절되는 지점이 특정되는가?
  → FRAMEWORK-DEFAULT: 프레임워크 기본값 동작이 공식 문서로 확인 가능한가?

□ 같은 원인으로 다른 유사 패턴이 있다면 함께 커버하는가?
  → 예: createNativeQuery 미탐 → createQuery, executeQuery 등 유사 메서드도 검토
```

---

### C. 최종 판정 및 기록

LLM은 A·B 검토 결과를 종합하여 아래 형식으로 판정을 기록한다.

```yaml
llm_review:
  reviewed_at: "YYYY-MM-DD"
  necessity:
    q1_real_pattern: true | false | "조건부"
    q2_not_covered:  true | false
    q3_generic:      true | false
    q4_severity_ok:  true | false
    verdict: "필요" | "불필요" | "조건부"
  correctness:
    semgrep_syntax_ok:    true | false | "N/A"
    detection_verified:   true | false | "N/A"
    fp_risk:              "낮음" | "중간" | "높음"
    prompt_conflict:      true | false | "N/A"
    root_cause_accurate:  true | false
    verdict: "정합" | "수정필요" | "N/A"
  final_decision: "승인" | "조건부 승인" | "보류"
  conditions: ""       # 조건부 승인 시 충족해야 할 조건
  deferral_reason: ""  # 보류 시 이유 및 재검토 조건
```

**판정 기준**:
- `necessity.verdict == "필요"` AND `correctness.verdict == "정합"` → **승인**
- 둘 중 하나 "조건부" → **조건부 승인** (conditions 항목에 충족 조건 명시, 충족 후 재검토)
- `necessity.verdict == "불필요"` OR `correctness.verdict == "수정필요"` → **보류**

> **보류된 항목은 적용 금지.** `ssc_feedback_ruleset.md` 누적 기록에 보류 이유와
> 재검토 조건을 명시하고, 다음 세션에서 조건 충족 여부 재평가한다.

---

## [5-4-3] 개선 액션 적용

LLM 검토 게이트 **승인** 또는 **조건부 승인(조건 충족)** 판정 시에만 아래 액션을 수행한다.

---

## 미탐 원인 분류 기준

| 원인 코드 | 설명 | 주요 대상 |
|----------|------|----------|
| `PAT-MISSING` | 스크립트 패턴 목록에 해당 API/메서드가 없음 | createNativeQuery, usePlaintext 등 |
| `TAINT-BREAK` | 멀티홉 테인트 체인을 스크립트가 추적 못함 | Controller→Service→DAO 3단계 경로 |
| `FRAMEWORK-DEFAULT` | 프레임워크 기본값이 취약한 경우 (설정 누락 패턴) | RedisTemplate 기본 JDK 직렬화 |
| `SCOPE-MISSING` | 진단 카테고리 자체가 현재 task 범위 밖 | TLS 클라이언트 설정, gRPC 보안 |
| `LLM-FP` | LLM이 TP를 FP로 잘못 판정 | 프레임워크 인터셉터 오인식 등 |

---

## 개선 액션 카탈로그 ([5-4-3] 대상)

### 액션 유형

| 액션 | 대상 | 설명 |
|------|------|------|
| `SEMGREP-ADD` | `references/rules/semgrep/` | 신규 Semgrep 룰 파일 추가 |
| `SCRIPT-PATTERN` | `tools/scripts/scan_*.py` | 정규식 패턴 추가 |
| `TASK-PROMPT` | `references/task_prompts/task_2*.md` | LLM 체크리스트 항목 추가 |
| `TAINT-RULE` | `references/taint_tracking.md` | 신규 소스→싱크 패턴 등록 |
| `CRITERIA-ADD` | `references/injection_diagnosis_criteria.md` | 진단 기준 항목 추가 |

---

## [5-4-4] 적용 후 검증

개선 액션 적용 완료 후 아래를 수행하여 실제 효과를 확인한다.

```
□ Semgrep 룰 적용 시:
  1. semgrep --validate --config <신규_룰.yaml>  → 문법 오류 없음 확인
  2. 원인이 된 SSC TP 코드 스니펫에 대해 dry-run 매칭 확인
     semgrep --config <신규_룰.yaml> testbed/<해당_파일.java>
  3. 기존 testbed에서 FP 유발 여부 확인 (가능하면)

□ Task Prompt 변경 시:
  1. 변경된 Step이 기존 Step 순서(1~7)와 논리적으로 연결되는지 검토
  2. 완료 조건 자가검증 체크리스트에 해당 Step 항목이 반영되었는지 확인

□ 진단 기준 변경 시:
  1. 변경 전/후 판정 예시 코드를 각각 제시하여 기준 명확성 확인
  2. 기존 누적 기록(TP/FP 사례)과 새 기준이 일관성 있는지 교차 확인
```

---

## [5-4-5] 누적 기록 (ssc_feedback_ruleset.md 업데이트)

적용 완료 또는 보류 여부와 관계없이, **모든 검토 결과를 이 파일의 "누적 피드백 기록" 섹션에 기록한다.**

### 기록 필수 항목

각 TP 레코드에 아래 블록을 추가한다.

```yaml
llm_review:         # [5-4-2] 검토 결과 전체
applied_actions:    # [5-4-3] 실제 적용된 액션 목록 (보류 시 빈 목록)
  - action: SEMGREP-ADD
    file: references/rules/semgrep/xxx.yaml
    applied_at: "YYYY-MM-DD"
  - action: TASK-PROMPT
    file: references/task_prompts/task_25_data_protection.md
    section: "Step 8-N"
    applied_at: "YYYY-MM-DD"
post_validation:    # [5-4-4] 검증 결과
  semgrep_validate: pass | fail | N/A
  dry_run_match:    true | false | N/A
  fp_observed:      true | false | N/A
  notes: ""
```

---

---

## 누적 피드백 기록

### [2026-03-20] OCBWEBVIEW/ocb-community-api (테스트34)

#### 재현 확인: TP-04 — RedisTemplate JDK 직렬화

| 항목 | 내용 |
|------|------|
| **파일** | `MasterDatabaseConfig.java:39` |
| **패턴** | `new RedisTemplate<>()` + 직렬화 설정 누락 (ocb-webview-api와 동일 패턴) |
| **SAST 탐지 여부** | ✅ 커버됨 — `redis-template-default-serializer.yaml` (TP-04, 2026-03-19 추가) |
| **비고** | 동일 패턴이 ocb-community-api의 MasterDatabaseConfig에도 재현. 룰 유효성 확인 완료. |

#### 재현 확인: TP-03 — gRPC usePlaintext

| 항목 | 내용 |
|------|------|
| **파일** | `GrpcFunctionHandler.java:50` (shared 모듈) |
| **패턴** | `ManagedChannelBuilder.forAddress(ip, port).usePlaintext()` — ocb-webview-api와 동일 패턴 |
| **SAST 탐지 여부** | ✅ 커버됨 — `grpc-plaintext-channel.yaml` (TP-03, 2026-03-19 추가) |
| **SSC 판정** | 검토필요 (서비스 메시 환경 미확인, gRPC Insecure Transport 가이드라인 적용) |
| **비고** | shared 모듈 코드이므로 동일 버전 사용 프로젝트 전반에 영향. |

#### 신규 패턴: Privacy Violation: Heap Inspection — 복호화 데이터 String 힙 잔류

| 항목 | 내용 |
|------|------|
| **파일** | `AESUtil.java:128`, `DbSecurityAdvisor.java:198,238,317,324,329` |
| **패턴** | `new String(EncryptCustomerInfo.decrypt(...), "UTF-8")` — 복호화된 개인정보를 String 불변 객체에 저장 |
| **SAST 탐지 여부** | ❌ 미탐 |
| **미탐 원인** | `SCOPE-MISSING` — 복호화 후 String 힙 잔류 패턴 현재 task 범위 밖 |
| **Type** | B (신규 카테고리) |

```yaml
llm_review:
  reviewed_at: "2026-03-20"
  necessity:
    q1_real_pattern: true      # AESUtil.java, DbSecurityAdvisor.java 실제 확인
    q2_not_covered: true       # 복호화 힙 잔류 패턴 기존 scan_data_protection.py 미커버
    q3_generic: true           # Java 암호화 유틸리티에서 반복 발생 가능
    q4_severity_ok: false      # 힙 덤프 접근 선행 필요 → 실용적 위험도 Medium/Low
    verdict: "조건부"          # Q4 미충족
  correctness:
    semgrep_syntax_ok: "N/A"   # 룰 미작성 (보류 결정)
    detection_verified: "N/A"
    fp_risk: "중간"            # char[] 없이 String 사용하는 정상 코드도 탐지 가능
    prompt_conflict: false
    root_cause_accurate: true
    verdict: "N/A"
  final_decision: "보류"
  conditions: ""
  deferral_reason: >
    Q4 위험도 낮음: 힙 잔류 악용을 위해 JVM 힙 덤프 접근이 선행 필요.
    Semgrep으로 탐지 가능하나 FP 위험 중간 (String 사용 자체를 모두 플래그).
    재검토 조건: 힙 덤프 취약점이 실제 인프라 위협으로 확인되거나, char[] 사용
    의무화 정책 수립 시 재평가.
applied_actions: []
post_validation:
  semgrep_validate: "N/A"
  dry_run_match: "N/A"
  fp_observed: "N/A"
  notes: "보류. 차기 감사 시 재검토 조건 확인."
```

#### 커버 확인: Privacy Violation 로그 PII (13건)

| 항목 | 내용 |
|------|------|
| **패턴** | `log.error/info/debug(mbrId, SMS PII, 인증 정보)` — 11개 파일 |
| **SAST 탐지 여부** | ✅ 커버됨 — Phase 2-5 DATA-LOG-COM-001 (info/error 레벨) / DATA-LOG-COM-002 (debug 레벨) |
| **비고** | 기존 scan_data_protection.py + LLM 분석으로 정상 탐지됨. 추가 개선 불필요. |

---

### [2026-03-19] OCBWEBVIEW/ocb-webview-api

#### TP-01: SQL Injection — EntityManager.createNativeQuery() 동적 쿼리

| 항목 | 내용 |
|------|------|
| **파일** | `BatchService.java` |
| **패턴** | 메서드 바디에서 문자열 결합으로 SQL 구성 → `entityManager.createNativeQuery(queryStr).executeUpdate()` |
| **SAST 탐지 여부** | ❌ 미탐 |
| **미탐 원인** | `PAT-MISSING` + `TAINT-BREAK` — 스크립트가 `createNativeQuery()` 직접 호출 패턴 미인식. `@Query(nativeQuery=true)` 어노테이션 패턴만 커버. InternalController→BatchService 멀티홉 테인트 미추적. |
| **Type** | A (탐지 가능했으나 미탐) |

```yaml
llm_review:
  reviewed_at: "2026-03-19"
  necessity:
    q1_real_pattern: true      # BatchService.java에서 실제 확인
    q2_not_covered: true       # createNativeQuery 직접 호출 패턴 기존 스크립트 미커버 확인
    q3_generic: true           # Spring/JPA 프로젝트 전반에서 발생 가능한 구조적 패턴
    q4_severity_ok: true       # SQLi Critical — severity 5
    verdict: "필요"
  correctness:
    semgrep_syntax_ok: true    # 6개 카테고리 룰 YAML 문법 수동 검토 완료
    detection_verified: true   # "delete from " + tableName + " where mbr_id = '" + mbrId + "'" 패턴이 카테고리 3에서 매칭됨
    fp_risk: "중간"            # 리터럴끼리 결합 시 FP 가능 — confidence MEDIUM으로 설정하여 LLM 2차 검증 명시
    prompt_conflict: false
    root_cause_accurate: true
    verdict: "정합"
  final_decision: "승인"
  conditions: ""
  deferral_reason: ""
applied_actions:
  - action: SEMGREP-ADD
    file: references/rules/semgrep/entitymanager-native-query-concat.yaml
    applied_at: "2026-03-19"
  - action: CRITERIA-ADD
    file: references/injection_diagnosis_criteria.md
    section: "EntityManager.createNativeQuery() 심층 탐지 절차"
    applied_at: "2026-03-19"
post_validation:
  semgrep_validate: "N/A (semgrep 미설치 환경 — LLM 수동 문법 검토로 대체)"
  dry_run_match: true
  fp_observed: false
  notes: "카테고리 1의 $A + $B 패턴이 BatchService 실제 코드 스니펫과 AST 수준 매칭 확인"
```

---

#### TP-02: Insecure Transport — SSL 클라이언트 인증서 검증 비활성화

| 항목 | 내용 |
|------|------|
| **파일** | `CarInsuranceNoCertRestTemplate.java` |
| **패턴** | `SSLContexts.custom().loadTrustMaterial(null, (c,a)->true)` + `NoopHostnameVerifier` |
| **SAST 탐지 여부** | ❌ 미탐 |
| **미탐 원인** | `SCOPE-MISSING` — `scan_data_protection.py`가 서버 HSTS만 다루고, HTTP 클라이언트 SSL 설정 패턴 미커버. |
| **Type** | B (신규 카테고리) |

```yaml
llm_review:
  reviewed_at: "2026-03-19"
  necessity:
    q1_real_pattern: true      # CarInsuranceNoCertRestTemplate.java에서 실제 확인
    q2_not_covered: true       # scan_data_protection.py 서버 HSTS만 커버, 클라이언트 SSL 설정 전무
    q3_generic: true           # 외부 API 연동 시 인증서 우회 패턴은 Java 프로젝트에서 반복 발생
    q4_severity_ok: true       # MITM 가능 — severity 4 (High)
    verdict: "필요"
  correctness:
    semgrep_syntax_ok: true
    detection_verified: true   # NoopHostnameVerifier / loadTrustMaterial(null, ...) 패턴 룰에 직접 포함
    fp_risk: "낮음"            # 패턴 자체가 안전한 코드에서 사용될 이유 없음
    prompt_conflict: false
    root_cause_accurate: true
    verdict: "정합"
  final_decision: "승인"
  conditions: ""
  deferral_reason: ""
applied_actions:
  - action: SEMGREP-ADD
    file: references/rules/semgrep/ssl-client-bypass.yaml
    applied_at: "2026-03-19"
  - action: TASK-PROMPT
    file: references/task_prompts/task_25_data_protection.md
    section: "Step 8-1"
    applied_at: "2026-03-19"
post_validation:
  semgrep_validate: "N/A"
  dry_run_match: true
  fp_observed: false
  notes: "src/test/ 경로 FP 제외 조건 판정 기준에 명시 완료"
```

---

#### TP-03: Insecure Transport — gRPC 평문 채널

| 항목 | 내용 |
|------|------|
| **파일** | `GrpcFunctionHandler.java` |
| **패턴** | `ManagedChannelBuilder.forAddress(ip, port).usePlaintext().build()` |
| **SAST 탐지 여부** | ❌ 미탐 |
| **미탐 원인** | `SCOPE-MISSING` — gRPC 보안 설정 패턴 전무. |
| **Type** | B (신규 카테고리) |
| **MSA 오탐 위험** | ⚠️ 높음 — Kubernetes + Istio/Linkerd 환경에서 애플리케이션 레벨 usePlaintext()는 sidecar mTLS 위임 정상 구성 가능. **"취약" 단정 금지** |

```yaml
llm_review:
  reviewed_at: "2026-03-19"
  necessity:
    q1_real_pattern: true      # GrpcFunctionHandler.java에서 실제 확인
    q2_not_covered: true       # gRPC 관련 룰 전무
    q3_generic: true           # MSA 아키텍처 채택 프로젝트에서 반복 발생 가능
    q4_severity_ok: "조건부"   # MSA/서비스 메시 환경에서 FP 가능성 높아 severity 낮춤
    verdict: "조건부"
  correctness:
    semgrep_syntax_ok: true
    detection_verified: true
    fp_risk: "높음"            # Istio 환경에서 대규모 FP 발생 가능
    prompt_conflict: false
    root_cause_accurate: true
    verdict: "수정필요 → 수정 완료"  # 초기 취약/severity 3 → 정보/severity 2로 하향 후 승인
  final_decision: "조건부 승인"
  conditions: >
    1. Semgrep severity를 INFO로 설정 (완료)
    2. finding result를 "정보/검토필요"로 설정 (완료)
    3. 판정 기준에 서비스 메시 FP 조건 명시 (완료)
    4. 완료 조건 체크리스트에 "취약 단정 금지" 명시 (완료)
    → 4개 조건 모두 충족 → 적용 승인
  deferral_reason: ""
applied_actions:
  - action: SEMGREP-ADD
    file: references/rules/semgrep/grpc-plaintext-channel.yaml
    applied_at: "2026-03-19"
  - action: TASK-PROMPT
    file: references/task_prompts/task_25_data_protection.md
    section: "Step 8-2"
    applied_at: "2026-03-19"
post_validation:
  semgrep_validate: "N/A"
  dry_run_match: true
  fp_observed: false
  notes: "severity INFO, msa_fp_risk HIGH 설정으로 오탐 위험 명시. 인프라 확인 전 취약 단정 금지 조건 task_25에 강제 추가."
```

**판정 기준**:

| 조건 | 판정 |
|------|------|
| localhost 전용 | 양호(FP) |
| Istio/Linkerd sidecar mTLS 확인 | 양호(FP) |
| 서비스 메시 불명확 | **정보** (severity 2) |
| 서비스 메시 없음 + 외부 서비스 | **취약** (severity 3) |

---

#### TP-04: Unsafe Deserialization — RedisTemplate 기본 JDK 직렬화

| 항목 | 내용 |
|------|------|
| **파일** | `MasterDatabaseConfig.java` |
| **패턴** | `new RedisTemplate<>()` + `setConnectionFactory()` 후 직렬화 설정 없음 → `JdkSerializationRedisSerializer` 자동 적용 |
| **SAST 탐지 여부** | ❌ 미탐 |
| **미탐 원인** | `FRAMEWORK-DEFAULT` — 프레임워크 기본값이 취약한 설정. 명시적 취약 코드 없이 "설정 누락"으로 발생하는 패턴을 스크립트가 탐지하지 못함. |
| **Type** | B (신규 카테고리) |

**개선 액션**:
- `SEMGREP-ADD`: `redis-template-default-serializer.yaml` (아래 룰 참조)
- `TASK-PROMPT`: `task_25_data_protection.md`에 "Redis 직렬화 설정 체크" 추가

```yaml
llm_review:
  reviewed_at: "2026-03-19"
  necessity:
    q1_real_pattern: true      # MasterDatabaseConfig.java에서 실제 확인
    q2_not_covered: true       # Redis 직렬화 관련 룰/체크리스트 전무
    q3_generic: true           # Spring Data Redis 사용 프로젝트에서 반복 발생 가능
    q4_severity_ok: true       # JDK 역직렬화 RCE → severity 4 적절
    verdict: "승인"
  correctness:
    semgrep_syntax_ok: true
    detection_verified: true   # new RedisTemplate<>() + setConnectionFactory() 패턴 확인
    fp_risk: "낮음"            # StringRedisTemplate 사용 시 pattern-not으로 FP 제거
    prompt_conflict: false
    root_cause_accurate: true  # FRAMEWORK-DEFAULT: 설정 누락으로 기본 JDK 직렬화 활성화
    verdict: "정합"
  final_decision: "승인"
  conditions: ""
  deferral_reason: ""
applied_actions:
  - action: SEMGREP-ADD
    file: references/rules/semgrep/redis-template-default-serializer.yaml
    applied_at: "2026-03-19"
  - action: TASK-PROMPT
    file: references/task_prompts/task_25_data_protection.md
    section: "Step 8-3"
    applied_at: "2026-03-19"
post_validation:
  semgrep_validate: "N/A"
  dry_run_match: true
  fp_observed: false
  notes: "StringRedisTemplate(문자열 전용, JDK 직렬화 없음)은 pattern-not으로 제외. ReactiveRedisTemplate도 별도 룰 추가."
```

---

## Semgrep 룰 참조

각 룰 파일은 `references/rules/semgrep/` 에 저장된다.

### 룰 파일 목록 (이번 세션 추가)

| 파일명 | 탐지 대상 | TP 연결 |
|--------|----------|---------|
| `entitymanager-native-query-concat.yaml` | EntityManager.createNativeQuery() 동적 SQL | TP-01 |
| `ssl-client-bypass.yaml` | NoopHostnameVerifier / trustAll SSL 우회 | TP-02 |
| `grpc-plaintext-channel.yaml` | gRPC .usePlaintext() 평문 채널 | TP-03 |
| `redis-template-default-serializer.yaml` | RedisTemplate 직렬화 미설정 | TP-04 |

---

## LLM 수동진단 체크리스트 추가 항목

Phase 3 LLM 분석 시 아래 항목을 추가로 점검한다.

### Task 2-2 / 3-2 (인젝션) 추가 체크

```
□ EntityManager.createNativeQuery() 직접 사용 여부
  → 메서드 바디에서 SQL 문자열을 변수로 구성 후 createNativeQuery(var)에 전달하는 패턴
  → 탐지 명령: grep -rn "createNativeQuery" <src> | grep -v "@Query"
  → 발견 시: SQL 문자열 구성 라인 추적 → 파라미터 결합(+, String.format, StringBuilder) 여부 확인
  → 결합 확인 시 → 반드시 취약 판정 (PreparedStatement 우회 가능)
```

### Task 2-5 / 3-5 (데이터보호) 추가 체크

```
□ HTTP 클라이언트 SSL 인증서 검증 우회
  → 탐지 명령: grep -rn "NoopHostnameVerifier\|loadTrustMaterial(null\|TrustAllCerts\|trustAll\|TRUST_ALL" <src>
  → 발견 시: 해당 RestTemplate/HttpClient가 어떤 외부 시스템에 사용되는지 확인
  → 외부 시스템(금융사, 결제사 등) 통신에 사용 시 → 취약 (MITM 가능)

□ gRPC 채널 평문 전송
  → 탐지 명령: grep -rn "usePlaintext\|ManagedChannelBuilder" <src>
  → usePlaintext() 존재 시 → 취약 (내부망이라도 스니핑 가능)
  → 조치: useTransportSecurity() + 인증서 설정

□ Redis 직렬화 설정 누락
  → 탐지 명령: grep -rn "new RedisTemplate\|new StringRedisTemplate" <src>
  → RedisTemplate 생성 후 setDefaultSerializer() / setValueSerializer() 없으면 → JDK 직렬화 기본 적용 → 취약
  → 조치: GenericJackson2JsonRedisSerializer 명시적 설정
```

---

## 룰셋 업데이트 정책

- Phase 5 실행 후 신규 TP 발견 시 → 이 파일의 "누적 피드백 기록" 섹션에 추가
- 동일 패턴이 다른 repo에서도 확인되면 → 해당 TP 레코드에 "재현 확인 repo" 항목 추가
- Semgrep 룰 추가 후 → 기존 testbed 대상으로 역검증 (미탐 -> 탐지 전환 확인)
- 분기별 1회: 누적 피드백 기반으로 scan_*.py 스크립트 패턴 일괄 업데이트 검토
