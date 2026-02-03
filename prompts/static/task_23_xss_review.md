## Task: 2-3 XSS 취약점 검토

**역할**: 당신은 보안 진단 전문가입니다.
**입력 파일**: state/task_21_result.json (API 인벤토리)
**출력 파일**: state/task_23_result.json
**출력 스키마**: schemas/finding_schema.json

---

### 컨텍스트
Task 2-1에서 추출한 API 인벤토리를 기반으로 **Persistent XSS**, **Reflected XSS**, **Redirect XSS**, **View XSS** 취약점을 정적 분석합니다.

---

### 파일 탐색 전략 (토큰 최적화)

> **전체 소스코드를 탐색하지 마세요.** 아래 순서로 필요한 파일만 추적합니다.

1. `state/task_21_result.json`에서 API 엔드포인트 목록을 로드
2. 각 API의 **Controller 파일**을 확인 → `@Controller` vs `@RestController` 어노테이션 판별
3. Controller에서 View로 데이터를 전달하는 패턴 확인 (`model.addAttribute()` 등)
4. **View 파일** 추적: JSP, Thymeleaf, Pug, React/Vue/Angular 컴포넌트
5. 전역 필터/인터셉터 확인: XSS 필터 설정 (web.xml, SecurityConfig, Lucy Filter 설정 등)

```
API 목록 → Controller (@Controller/@RestController 판별)
              ├→ Service → DB 저장 로직 (Persistent XSS)
              ├→ View 파일 (JSP/Thymeleaf/React/Vue) (View XSS)
              └→ Redirect 로직 (sendRedirect/forward) (Redirect XSS)
```

---

### 1. Persistent XSS (저장형)

사용자 입력 파라미터가 **DB에 저장될 때** XSS 필터링 없이 저장되는 경우.

**진단 방법:**
1. Controller → Service → Repository 추적하여 사용자 입력이 DB에 저장되는 흐름 확인
2. 저장 시점에 XSS 필터가 적용되는지 확인
3. 저장된 데이터가 출력되는 View가 제한되고 프론트에서 양호 확인 시 → 예외 가능 (증적 필요)

**판정:**
- 필터 없이 DB 저장 → **취약**
- 서블릿 필터(Lucy 등) 적용 중이나 `multipart/form-data`에 대한 `multipartFilter` 미설정 → **취약**

---

### 2. Reflected XSS (반사형)

서버 응답을 통해 사용자 입력이 그대로 클라이언트에 반환되는 경우.

**정적 분석 핵심 판별법:**

| 어노테이션 | 반환 타입 | Content-Type | 판정 |
|---|---|---|---|
| `@Controller` | String (view name) | text/html | **취약** (필터 없으면) |
| `@Controller` + `@ResponseBody` | Object/DTO | application/json | **양호** |
| `@RestController` | 모든 반환값 | application/json | **양호** |

**예외사항:**
- `Gson` 라이브러리 사용 시 `disableHtmlEscaping()` 옵션 → JSON 내 HTML escape 미처리 → **취약**
- `com.google.gson.GsonBuilder` 사용 여부 확인 필요

**JSP 출력 검증:**
- `<c:out value="${값}" />` (escapeXml 기본값 true) → **양호**
- `<c:out value="${값}" escapeXml="false" />` → **취약**
- `${값}`, `<%= %>` 직접 출력 → **취약** (HTML escape 미지원)

**Front로 데이터 전달 패턴:**
- `model.addAttribute()` → JSP 영역으로 데이터 전달 (String, Object, DTO, Map, List 모두 가능) → 확인 필요

---

### 3. Redirect XSS (리다이렉트)

사용자 입력값을 검증 없이 리다이렉트 대상으로 사용하는 경우.

**서버단 검색 키워드:**

| 키워드 | 설명 |
|---|---|
| `redirect:` | Spring 리디렉션 지시어 |
| `sendRedirect(` | Java Servlet 리디렉션 |
| `response.setHeader("Location"` | Location 헤더 수동 설정 |
| `UriComponentsBuilder.fromUriString(` | URI 조합 함수 |
| `@RequestParam("next"/"returnUrl"/"callback")` | 리디렉션용 파라미터 |
| `RequestDispatcher.forward(` | 서버 내부 포워딩 |

**프론트단 검색 키워드:**

| 키워드 | 설명 |
|---|---|
| `location.href =` | URL 이동 |
| `window.location =` | 리디렉션 |
| `document.location` | DOM 기반 처리 |

**판정:**
- 사용자 입력값을 검증 없이 리다이렉트 → **취약**
- 리다이렉트 대상이 화이트리스트/고정 URL → **양호**

---

### 4. View XSS (뷰 단)

View에서 스크립트 문자열이 렌더링될 때 실행 가능한 경우.

**프론트엔드 프레임워크별 취약 패턴:**

| 프레임워크 | 취약 패턴 | 비고 |
|---|---|---|
| React | `dangerouslySetInnerHTML` | HTML 직접 삽입 |
| Vue | `v-html` | HTML 직접 삽입 |
| Angular | `innerHTML` 바인딩 | HTML 직접 삽입 |
| Handlebars | `{{{변수}}}` (triple brace) | HTML escape 미적용 |
| jQuery | `.html()`, `.append()`, `.prepend()`, `.after()`, `.before()`, `.wrap()`, `.insert*()` | DOM XSS 취약 |

**jQuery 안전 함수:** `.text()`, `.attr()`, `.prop()`, `.val()`

**Template Engine별 안전 출력:**
- Thymeleaf: `th:text="${}"` → 자동 escape (양호)
- Pug(Jade): `#{}` → 자동 escape (양호, 단 `<script>` + `JSON.stringify` 사용 시 추가 조치 필요)
- JSTL: `<c:out>` + `escapeXml=true` (기본값) → 양호

**DOMPurify 적용 확인:**
- `vue-dompurify-html`, `DOMPurify.sanitize()` 등 사용 시 → **양호**

---

### 5. XSS 필터 충분성 검증

**필수 필터 문자 (8개):**

| 문자 | HTML Entity |
|---|---|
| `<` | `&lt;` |
| `>` | `&gt;` |
| `'` | `&#x27;` |
| `"` | `&quot;` |
| `(` | `&#40;` |
| `)` | `&#41;` |
| `/` | `&#x2F;` |
| `#` | `&#35;` |

**판정:**
- `< > ' "` 중 하나라도 필터 누락 → **취약**
- `< > ' "` 필터 중이나 `( ) / #` 중 하나 이상 누락 → **Info**
- 8개 문자 모두 필터 중 → **양호**

**검사 대상 필터 라이브러리:**
- OWASP AntiSamy
- Lucy XSS Filter / Lucy XSS Servlet Filter
- ESAPI
- Java Servlet Filter

---

### 판정 기준

| 심각도 | 조건 |
|---|---|
| **Critical** | 인증 없는 API + Persistent XSS + 필터 없음 |
| **High** | Persistent XSS 필터 없음, 또는 @Controller HTML 반환 + 필터 없음 |
| **Medium** | 부분 필터 적용 (필수 4문자 중 일부 누락), Redirect 검증 미흡 |
| **Low** | @RestController JSON 반환이나 Gson disableHtmlEscaping 사용 |
| **Info** | 필터 개선 권고 (8개 중 보조 4문자 누락) |

---

### 출력 형식

```json
{
  "task_id": "2-3",
  "status": "completed",
  "findings": [
    {
      "id": "XSS-001",
      "title": "취약점 제목",
      "severity": "High",
      "category": "XSS / Persistent",
      "description": "상세 설명",
      "affected_endpoint": "/api/xxx",
      "evidence": {
        "file": "src/controller/XxxController.java",
        "lines": "30-45",
        "code_snippet": "취약 코드"
      },
      "cwe_id": "CWE-79",
      "owasp_category": "A03:2021 Injection",
      "recommendation": "조치 방안"
    }
  ],
  "executed_at": "",
  "claude_session": ""
}
```

---

### 금지사항
- 추측 금지 (코드 근거 없으면 finding 생성 금지)
- 실제 XSS 페이로드 작성 금지
- 민감정보 포함 금지
- API 인벤토리에 없는 파일을 임의로 탐색 금지
