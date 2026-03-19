# Task SCA — 소프트웨어 구성 분석 (SCA) 진단 및 보고서 작성

## 목적

오픈소스 의존성 라이브러리 CVE 취약점 식별 → CISA KEV 대조 → 실사용(Reachability) 검증 →
개발팀 실무 적용 가능한 수준의 조치 권고 보고서 생성.

---

## 실행 절차

### Step 1. 의존성 추출

```bash
# Gradle dep tree (빌드 성공 시)
./gradlew dependencies --configuration runtimeClasspath > state/<prefix>_dep_tree.log

# JAR 존재 시
python3 tools/scripts/scan_sca.py <src> --jar state/<prefix>_build_manifest_primary.jar \
    --project <name> --poc -o state/<prefix>_sca.json

# Gradle dep tree 기반 (빌드 실패 시 대체)
python3 tools/scripts/scan_sca.py <src> --dep-tree state/<prefix>_dep_tree.log \
    --project <name> --poc --publish -o state/<prefix>_sca.json
```

### Step 2. CVE 조회 및 필터링

- OSV.dev `/v1/querybatch` 배치 조회 → HIGH/CRITICAL만 유지 (CVSS ≥ 7.0)
- 각 취약점별 `/v1/vulns/{id}` 단건 조회로 severity/CWE/fixed version 확보
- CISA KEV 피드 대조 → KEV 해당 CVE는 `★` 표시 및 즉시 패치 우선

### Step 3. 소스코드 실사용(Reachability) 검증

`_auto_relevance()` grep 기반 자동 판정:

| 라이브러리 | 판정 기준 |
|---|---|
| spring-webflux | `WebFlux\|RouterFunction\|@EnableWebFlux` grep → 없으면 조건미충족 |
| tomcat-embed | MultipartFile 업로드 또는 직접 Tomcat API 호출 여부 |
| jackson-databind | ObjectMapper/JsonNode/readValue 사용 여부 |
| logback-classic | SocketAppender/ServerSocketAppender 설정 여부 |
| snakeyaml | Yaml.load() / Yaml.loadAll() 직접 호출 여부 |
| spring-web | UriComponentsBuilder + 외부 URL 조합 여부 |
| spring-security | BCryptPasswordEncoder 사용 여부 |
| grpc-netty | gRPC 서비스 노출 여부 |

판정 결과:
- **적용**: 실사용 조건 grep 확인 → 즉시 조치 필요
- **제한적**: 내부 프레임워크 사용, 외부 노출 제한적 → 추가 확인 필요
- **조건미충족**: 발생 조건 코드 미존재 → False Positive

### Step 4. 결과 그룹화 및 정렬

- 라이브러리별 1행 (CVE 여러 건을 한 셀에)
- 정렬: CRITICAL → HIGH, 동일 심각도 내 적용 → 제한적 → 조건미충족

---

## 조치 권고 작성 원칙 (보고서 작성 룰셋)

> **IMPORTANT**: 아래 3개 원칙은 모든 SCA 보고서에 반드시 적용한다.
> LLM이 조치 방안 문구를 작성할 때 이 원칙을 위반하는 문구는 생성하지 않는다.

---

### [Rule 1] Major 버전 마이그레이션 리스크 경고 (Big Bang 방지)

**적용 조건**: Spring Boot 2.x → 3.x, Java EE → Jakarta EE 기반으로 메이저 버전업을 권고해야 하는 경우

**금지 문구**: `"Spring Boot 3.x로 업그레이드하십시오"`처럼 단순 버전업만 기술하는 것

**필수 포함 문구**:
> *"단기적으로는 현재 메이저 버전의 최신 패치(예: 2.7.x의 최신)를 적용하여 Critical 취약점을 방어하고, 중장기적으로 Java 17 및 jakarta.* 패키지 전환을 동반하는 3.x 마이그레이션 계획을 별도 수립할 것."*

**이유**: Spring Boot 2→3은 `javax.*` → `jakarta.*` 패키지 전환, Spring Security 6 API 변경, Hibernate 6 마이그레이션을 동반하는 대규모 변경으로, 무계획 업그레이드 시 운영 장애 위험이 높음.

---

### [Rule 2] 전이적 의존성(Transitive Dependency) 오버라이딩 경고

**적용 조건**: Tomcat, Jackson, SnakeYAML 등 BOM/Starter Parent가 관리하는 하위 라이브러리 버전업을 권고하는 경우

**금지 문구**: `"build.gradle에서 tomcat-embed-core 버전을 10.1.x로 강제 지정하십시오"` 등 개별 라이브러리 직접 오버라이딩 권고

**필수 포함 문구**:
> *"개별 라이브러리(Tomcat, Jackson 등)의 버전을 강제로 오버라이딩하면 프레임워크 내부 클래스와 충돌(NoClassDefFoundError 등)이 발생할 수 있습니다. 가급적 Spring Boot Starter Parent(또는 BOM) 버전을 일괄 업그레이드하여 의존성 충돌을 방지하십시오."*

**이유**: Spring Boot BOM은 호환 검증된 버전 조합을 제공함. 개별 오버라이딩은 BOM 검증을 우회하여 런타임 NoClassDefFoundError, 기능 이상, ClassCastException을 유발할 수 있음.

**예외**: 라이브러리가 BOM 외부에서 직접 선언된 경우(예: 자체 추가한 의존성), 개별 버전업 권고 허용.

---

### [Rule 3] CWE 노이즈 축약 (가독성 최적화)

**적용 조건**: 단일 라이브러리에 매핑된 CWE가 5개 이상인 경우

**처리 방식**: `scan_sca.py`의 `_compress_cwe_ids()` 함수가 자동 처리:
- CWE 우선순위 기준으로 상위 4개만 유지
- 나머지는 `(+N개 생략)` 주석으로 표시

**CWE 우선순위 (높을수록 먼저 표시)**:
1. RCE/임의 코드 실행: CWE-502(역직렬화), CWE-78(OS Command), CWE-94(코드 인젝션)
2. 경로 탐색/파일 접근: CWE-22, CWE-23, CWE-44
3. 인증·인가 우회: CWE-287, CWE-862, CWE-863, CWE-284, CWE-281, CWE-285
4. SSRF: CWE-918
5. HTTP 스머글링: CWE-444
6. DoS/자원 소모: CWE-400, CWE-770, CWE-521, CWE-696, CWE-121, CWE-404
7. 인젝션/XSS: CWE-116, CWE-74
8. 기타: CWE-20, CWE-190, CWE-601, CWE-367, CWE-776, CWE-755

**이유**: Tomcat처럼 취약점이 많은 라이브러리는 10개 이상의 CWE가 붙어 개발자 피로도를 높이고 실제 위협 파악을 방해함. 핵심 위협 3~4개로 집약하여 조치 우선순위 파악 용이하게 함.

---

## 보고서 출력 형식

### Confluence XHTML 컬럼 구성

| # | 라이브러리(현재버전) | 심각도 | CVE 목록(★=KEV) | 패치필요버전 | 소스관련성 및 판단근거 | CWE 및 취약현황 |
|---|---|---|---|---|---|---|

### 조치 권고 섹션 (Rule 1, 2 적용 예시)

Tomcat, Spring Boot BOM 관련 취약점 보고 시 아래 문구를 **조치 권고** 섹션에 추가:

```
[조치 권고]
1. (즉시) CISA KEV 등재 취약점(★): 현재 메이저 버전(2.7.x) 내 최신 패치 버전 적용
2. (단기) Spring Boot 2.7.x 최신 BOM 업그레이드 → Tomcat, Jackson, SnakeYAML 일괄 패치
   ⚠️ tomcat-embed-core, jackson-databind 등 개별 오버라이딩 금지:
      NoClassDefFoundError 등 런타임 충돌 위험. Spring Boot BOM 전체 업그레이드 권장.
3. (중장기) Spring Boot 3.x 마이그레이션:
   Java 17 전환 + javax.* → jakarta.* 패키지 전환 + Spring Security 6 API 변경 포함.
   별도 마이그레이션 계획 수립 필요 (단순 버전 변경으로 해결 불가).
```

---

## 출력 스키마 (`<prefix>_sca.json`)

```json
{
  "project": "프로젝트명",
  "source_dir": "...",
  "scan_metadata": {
    "total_deps": 186,
    "osv_findings": 44,
    "kev_count": 1,
    "analysis_date": "2026-03-19"
  },
  "findings": [
    {
      "dep": "org.apache.tomcat.embed:tomcat-embed-core:9.0.83",
      "group": "org.apache.tomcat.embed",
      "artifact": "tomcat-embed-core",
      "version": "9.0.83",
      "vuln_id": "GHSA-xxxx",
      "cve_id": "CVE-2025-24813",
      "severity": "CRITICAL",
      "cvss": 9.8,
      "kev": true,
      "fixed_version": "9.0.99",
      "cwe_ids": ["CWE-22"],
      "relevance_status": "적용",
      "relevance_reason": "MultipartFile 업로드 엔드포인트 사용 확인 (85개 파일)"
    }
  ],
  "grouped": [
    {
      "ga": "org.apache.tomcat.embed:tomcat-embed-core",
      "artifact": "tomcat-embed-core",
      "version": "9.0.83",
      "severity_max": "CRITICAL",
      "cvss_max": 9.8,
      "relevance_max": "적용",
      "fixed_version": "9.0.99",
      "cves": [...]
    }
  ]
}
```

---

## 참고

- `scan_sca.py` v2.0: `--dep-tree` (OSV 경로), `--publish` (Confluence 자동 게시)
- `_compress_cwe_ids()`: CWE 5개 이상 시 우선순위 기준 상위 4개로 자동 축약
- CISA KEV: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
- OSV API: https://osv.dev/docs/
