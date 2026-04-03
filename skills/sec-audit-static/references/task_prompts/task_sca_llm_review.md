# Task 3-SCA — SCA LLM 수동 검토 (관련성 분석 + 한국어 설명)

## 목적

`scan_sca_gradle_tree.py` 또는 `scan_sca.py` 자동 스캔으로 식별된 CVE 취약점 각각에 대해:
1. 이 프로젝트 소스코드에서 해당 라이브러리가 **실제로 사용되는지** 확인
2. CVE가 요구하는 **발생 조건(취약 API 호출 / 설정 / 입력 경로)**이 코드에 존재하는지 확인
3. **오탐(False Positive) 여부** 판정
4. 개발팀이 이해할 수 있는 **한국어 취약점 설명** 작성

---

## 실행 전 준비

```bash
# 스캔 결과 로드
cat state/<prefix>/sca.json | python3 -c "
import json, sys
d = json.load(sys.stdin)
meta = d.get('metadata', {})
print('프로젝트:', meta.get('project_name'))
print('스캔방법:', meta.get('scan_method'))
print('HIGH+CRITICAL CVE:', meta.get('high_critical_cve'))
for g in d.get('grouped', []):
    print(f\"  [{g['severity']}] {g['package']} {g['version']} — CVE {len(g['cves'])}건\")
"
```

---

## 검토 절차 (라이브러리 단위)

각 `grouped[]` 항목 (라이브러리 단위)에 대해 아래 체크리스트 순서대로 수행한다.

### [1단계] 소스코드 내 라이브러리 사용 여부 확인

```bash
# artifactId (package 뒷부분) 기준 import/사용 검색
rg -l "<artifact-id>" <src_dir> --include="*.java" --include="*.kt" --include="*.ts" --include="*.js"

# 예시: tomcat-embed-core
rg -l "MultipartFile\|CommonsFileUpload\|StandardMultipartResolver" <src_dir>

# 예시: jackson-databind
rg -l "ObjectMapper\|JsonNode\|readValue\|@JsonDeserialize" <src_dir>

# 예시: spring-security-core
rg -l "@PreAuthorize\|@Secured\|@EnableMethodSecurity\|hasRole\|hasAuthority" <src_dir>
```

**판정 기준:**
- import/사용 코드 없음 → 전이적 의존성만 존재 → `"확인불가"` 또는 `"조건미충족"` 후보

### [2단계] CVE 발생 조건 확인

각 CVE summary를 읽고, 취약점이 트리거되는 조건을 소스코드에서 직접 확인:

| CVE 유형 | 확인할 코드 패턴 |
|---|---|
| 경로 순회 / Path Traversal | `getOriginalFilename()`, `Paths.get()`, `File()` + 외부 입력 |
| 역직렬화 (Deserialization) | `ObjectInputStream`, `readObject()`, `enableDefaultTyping()` |
| SSRF | `RestTemplate`, `WebClient`, `HttpURLConnection` + user-controlled URL |
| ReDoS | 외부 입력이 정규식 패턴 파라미터로 사용되는 코드 |
| DoS (메모리/CPU) | 대용량 파일 파싱, 무한 루프 가능성 |
| 인증/인가 우회 | `@PreAuthorize`, `@Secured`, method security annotation 사용 여부 |
| XXE | `DocumentBuilderFactory`, `SAXParserFactory`, `XMLInputFactory` + `setFeature` 미설정 |
| AES ECB/고정IV | `Cipher.getInstance("AES/ECB")`, `IvParameterSpec(new byte[16])` |

### [3단계] 관련성 판정

| 판정 | 기준 | 조치 |
|---|---|---|
| **적용** | 취약 API/기능 실사용 + 발생 조건 충족 | 즉시 패치 필요 |
| **제한적** | 라이브러리 사용되나 취약 기능 직접 호출 미확인 | 추가 확인 권고 |
| **조건미충족** | 발생 조건 코드 미존재 (라이브러리만 있음) | False Positive — 낮은 우선순위 |
| **확인불가** | 소스코드에서 판정 불가 (바이너리 의존, 동적 로딩 등) | 패치 권고 유지 |

### [4단계] 한국어 취약점 설명 작성

각 CVE에 대해 아래 형식으로 한국어 설명 작성:

```
{
  "description_ko": "<취약점 한국어 요약 (1문장)>",
  "impact_ko": "<이 프로젝트에서의 실제 영향: 공격 시나리오 + 영향 범위 (1~2문장)>",
  "condition_ko": "<발생 조건: 어떤 기능/설정/입력 경로에서 트리거되는지>"
}
```

**예시:**
```json
{
  "description_ko": "Apache Tomcat에서 특수 문자가 포함된 파일 업로드 요청 처리 시 경로 탈출이 가능한 취약점",
  "impact_ko": "파일 업로드 API(/api/upload)에서 MultipartFile 처리 시 악성 파일명으로 웹루트 외부 경로에 파일 저장 가능. 공격자가 서버 사이드 코드(.jsp 등)를 업로드하면 원격 코드 실행으로 이어질 수 있음.",
  "condition_ko": "MultipartFile.getOriginalFilename()을 경로 생성에 직접 사용하고 파일명 정규화 없이 저장 시 발생. 현재 코드에서 확인 필요."
}
```

---

## 출력 스키마 (`<prefix>_sca_llm.json`)

```json
{
  "task_id": "P3-SCA",
  "source_tool": "SCA-LLM-Review",
  "source_sca_file": "state/<prefix>/sca.json",
  "reviewed_at": "2026-03-24",
  "reviewer": "LLM",
  "reviews": [
    {
      "package": "org.apache.tomcat.embed:tomcat-embed-core",
      "version": "10.1.40",
      "relevance_status": "제한적",
      "relevance_reason": "MultipartFile 업로드 API 다수 존재하나 getOriginalFilename() 직접 경로 조합 패턴은 미발견. UUID 기반 파일명 사용 확인.",
      "cves": [
        {
          "cve": "CVE-2025-55754",
          "description_ko": "Apache Tomcat HTTP/2 요청 처리 과정에서 응답 헤더 인젝션이 가능한 취약점",
          "impact_ko": "HTTP/2 활성화 시 공격자가 CRLF 시퀀스를 주입하여 응답 스플리팅 공격이 가능. 이 프로젝트는 Embedded Tomcat 기본 설정으로 운영 중이며 영향을 받을 수 있음.",
          "condition_ko": "HTTP/2 프로토콜 활성화 시 발생. application.properties에서 server.http2.enabled 설정 확인 필요.",
          "fp_reason": null
        }
      ]
    }
  ],
  "summary": {
    "총_검토_라이브러리": 10,
    "적용": 3,
    "제한적": 5,
    "조건미충족": 1,
    "확인불가": 1
  }
}
```

---

## 관련성 판정 패턴 참조

### Gradle/Spring Boot 프로젝트

| 라이브러리 artifact | 적용 판정 grep 패턴 | 주의사항 |
|---|---|---|
| `tomcat-embed-core` | `MultipartFile`, `CommonsMultipartFile`, `Part` | 직접 Tomcat API 호출 시 적용 |
| `jackson-databind` | `ObjectMapper`, `readValue`, `JsonNode`, `@JsonDeserialize` | 외부 JSON 입력 처리 여부 확인 |
| `spring-security-core` | `@PreAuthorize`, `@Secured`, `hasRole`, method security | 어노테이션 기반 메서드 보안 사용 여부 |
| `spring-web` / `spring-webmvc` | `RestTemplate`, `UriComponentsBuilder` | user-controlled URL 파라미터 조합 여부 |
| `snakeyaml` | `Yaml.load(`, `Yaml.loadAll(` | new Constructor() 없이 직접 호출 시 위험 |
| `logback-classic` | `SocketAppender`, `ServerSocketAppender` | logback.xml 설정 확인 |
| `spring-webflux` | `WebFlux`, `RouterFunction`, `@EnableWebFlux` | Reactive stack 사용 여부 |
| `netty` | gRPC 서비스 노출 또는 직접 Netty 사용 여부 | |

### npm 프로젝트

| 패키지 | 적용 판정 패턴 | 주의사항 |
|---|---|---|
| `react-router` | `<Route`, `useNavigate`, SSR 설정 | SSR(서버사이드 렌더링) 사용 여부 |
| `axios` | `axios.get/post` + 외부 URL 파라미터 | SSRF 조건: user-controlled URL |
| `lodash` | `_.template(`, `_.set(` | 직접 prototype 오염 조건 |
| `postcss` | `postcss()` 직접 호출 | 빌드 도구만이면 런타임 영향 없음 |
| `webpack` | 빌드 도구 의존성 | 런타임에서 미사용이면 조건미충족 |

---

## 주의사항

- **전이적 의존성(transitive dependency)**: 직접 사용하지 않아도 취약점은 런타임에 메모리에 로드됨. 단, 취약 기능을 호출하는 코드가 없다면 실제 익스플로잇은 불가.
- **전이적 의존성 오버라이딩 금지 원칙**: 조치 권고 시 개별 라이브러리 버전 강제 변경이 아닌 **상위 BOM 업그레이드**를 권고할 것.
- **KEV 등재 CVE**: 실제 악용 사례 있음. 조건미충족이라도 패치 권고 유지.
- **복수 CVE가 동일 라이브러리**: 심각도 가장 높은 CVE 기준으로 관련성 판정, 나머지는 동일 라이브러리이므로 일괄 적용.

---

## Confluence 게시 방법

LLM 검토 결과를 SCA 페이지에 병합 게시:

```json
// confluence_page_map.json 항목 예시
{
  "source": "state/<prefix>/sca.json",
  "title": "테스트NN - SCA (오픈소스 취약점) 진단 결과",
  "type": "sca",
  "supplemental_sources": ["state/<prefix>/sca_llm.json"]
}
```

`publish_confluence.py`가 `_json_to_xhtml_sca_v2()`를 통해 SCA 자동 스캔 결과 + LLM 검토 결과를 하나의 페이지로 통합 렌더링한다.
