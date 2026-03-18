## Task: 2-4 파일 처리 검토 (LLM 수동분석 보완)

**역할**: 당신은 보안 진단 전문가입니다.
**입력 파일**: `state/<prefix>_task24.json` (scan_file_processing.py 자동스캔 결과)
**출력 파일**: `state/<prefix>_task24_llm.json` (LLM 수동분석 보완 — supplemental)
**게시 방식**: 별도 Confluence 페이지 X → `<prefix>_task24.json` finding 페이지의 `supplemental_sources`로 통합

> ⚠️ **이 JSON은 자동스캔 페이지에 통합 렌더링된다.** 독립 보고서가 아님.
> `confluence_page_map.json`의 file_handling finding 항목에 `supplemental_sources` 배열로 추가할 것.

---

### 컨텍스트
`scan_file_processing.py` 1차 자동스캔 결과에서 **파일 업로드**, **파일 다운로드**, **Path Traversal**, **LFI/RFI** 취약점의 `needs_review: true` 항목 및 자동 탐지 한계 구간(권한 검증·우회 기법·무해화)에 대해 LLM이 심층 분석합니다.

---

### 파일 탐색 전략 (토큰 최적화)

> **전체 소스코드를 탐색하지 마세요.** 아래 순서로 필요한 파일만 추적합니다.

1. `state/task_21_result.json`에서 파일 관련 API 엔드포인트를 식별
2. 각 API의 **Controller 파일**에서 파일 처리 로직 확인
3. Controller에서 호출하는 **Service** → **파일 처리 유틸/라이브러리** 추적
4. 전역 설정 확인: `web.xml` (servlet-mapping), `application.yml`, 파일 업로드 설정
5. **추가 검색**: 아래 키워드로 파일 처리 코드가 있는 파일만 추가 탐색

```
API 목록 → Controller → Service → 파일 처리 로직
                                    ├→ 업로드: MultipartFile, transferTo, 확장자/파일명 필터
                                    └→ 다운로드: FileInputStream, IOUtils, 경로 필터
```

---

### 1. 파일 업로드 진단

#### 1.1 검색 키워드

| 언어 | 키워드 |
|---|---|
| Java | `multipart`, `MultipartFile`, `transferTo`, `org.springframework.web.multipart`, `org.apache.poi`, `form-data`, `upload`, `outfile`, `java.io.File` |
| Node.js | `multer`, `formidable`, `busboy`, `multiparty`, `upload` |

#### 1.2 판정 기준

**[0순위] 인프라 아키텍처 레벨 — 최우선 점검 항목**

> 코드 레벨 방어(MIME 검증, 확장자 필터 등)보다 **저장 경로의 물리적 분리**가 더 근본적인 방어책이다.
> 저장 경로가 Web Document Root 내부이면 코드 레벨 방어를 통과한 악성 파일이 URL로 직접 실행될 수 있다.

| 저장 경로 상황 | 판정 |
|---|---|
| Web Document Root 외부 (NAS, S3, `/data/uploads/` 등) + 다운로드 전용 서블릿 경유 | **양호 (근본 방어)** |
| Web Document Root 내부 (`/webapps/upload/`, `/static/` 등) + 코드 레벨 필터만 존재 | **취약 (코드 필터 우회 시 직접 실행 가능)** |
| 저장 경로 설정 코드 미확인 | `needs_review: true` — `@Value` 경로 설정 또는 `application.yml` 확인 요청 |

**recommendation 필수 포함 문구:**
```
[아키텍처 0순위] 업로드 저장 경로를 WAS의 Web Document Root와 물리적으로 분리.
외부 NAS 또는 AWS S3 사용. 저장 경로 외부 분리 시 악성 스크립트 파일이 업로드되더라도
URL을 통한 직접 실행(Execute)이 불가하여 웹쉘 공격을 원천 차단.
다운로드는 전용 서블릿을 통한 스트림 응답(Content-Disposition: attachment)으로만 제공.
```

**양호 조건 — 코드 레벨 (아래 중 하나 이상 충족):**
- 확장자 필터 + 파일명 필터가 동시에 존재
- 고정 로직으로 업로드하며 사용자 입력값 미포함
- 고정 로직에 사용자 입력값 포함되나 필터링 후 포함
- 파일명이 UUID 등 고유값으로 자동 생성

**취약 조건:**
- 확장자 필터 / 파일명 필터가 모두 확인되지 않는 경우 → **취약**
- 고정 로직에 사용자 입력값이 포함되나 필터링 미적용 → **취약**
- 저장 경로가 Web Document Root 내부 + 코드 레벨 방어 부재 → **취약 (Critical)**

**필터 상세:**

| 필터명 | 필터 설명 |
|---|---|
| 파일명 필터 | `..`, `.`, `/`, `\`, `&` 등 경로 이동 관련 문자열 필터링 |
| 확장자 필터 | 서버 사이드 실행 가능 확장자 (jsp, php, asp, sh, exe 등) 차단 |

#### 1.3 추가 확인사항
- 에디터(WYSIWYG)의 파일 업로드 컨트롤러와 글 등록 시 파일 업로드 컨트롤러가 다를 수 있음 → 각각 확인
- 파라미터에 경로 정보가 들어가서 최종 업로드 경로를 만드는 경우 `../` 경로 조작 및 `%00` 널바이트 취약점 확인
  - Null byte injection은 Java 8 미만에서 발생

---

### 2. 파일 다운로드 진단

#### 2.1 검색 키워드

| 언어 | 키워드 |
|---|---|
| Java | `Attachment`, `IOUtils`, `IOUtils.copy`, `FileDataSource`, `ByteArrayDataSource`, `java.io.File`, `new File(`, `FileInputStream`, `FileCopyUtils.copy`, `download` |
| Node.js | `res.download`, `res.sendFile`, `fs.createReadStream`, `pipe(res)` |

> `OutputStream` 키워드는 write/flush에 의한 반복 리턴이 빈번하여 다운로드와 무관한 경우가 많으므로 제외

#### 2.2 판정 기준

**양호 조건:**
- 사용자 입력에 대한 경로 필터링 존재
- 고정 경로에서만 파일 다운로드
- DB에 저장된 파일 정보 기반으로 다운로드

**취약 조건:**
- 사용자 입력값에 대한 경로 필터링 미존재 → **취약**
- 다운로드 경로에 사용자 입력값이 포함되나 필터링 미적용 → **취약**

---

### 3. LFI / RFI (Local/Remote File Inclusion)

#### 3.1 검색 키워드

| 언어 | 키워드 |
|---|---|
| Java | `FileInputStream`, `BufferedReader`, `new File(`, `ClassLoader.getResource`, `getResourceAsStream` |
| Node.js | `fs.readFile`, `fs.readFileSync`, `fs.writeFile`, `fs.appendFile`, `fs.watchFile`, `fs.open`, `require(` (동적) |
| PHP | `include`, `require`, `include_once`, `require_once`, `fopen`, `file_get_contents` |

#### 3.2 판정 기준

**양호 조건:**
- 파일시스템 라이브러리로 내부 파일 직접 접근하는 입력값 미지원
- 경로 이동 문자(`../`, `..\\`) 필터 적용 (LFI)
- `realpath` 등으로 설정된 경로 범위 내에서만 접근 가능하도록 조치 (RFI)
- 파일 확장자 검증 적용 (LFI)

**취약 조건:**
- 파일시스템 라이브러리로 사용자 입력값 기반 내부 파일 직접 접근 지원 → **취약**

---

### 판정 기준

| 심각도 | 조건 |
|---|---|
| **Critical** | 인증 없는 업로드 API + 확장자/파일명 필터 모두 없음 (웹쉘 업로드 가능성) |
| **High** | 파일 다운로드 경로에 사용자 입력 + 필터 없음 (Path Traversal), LFI 가능 |
| **Medium** | 업로드 시 확장자 필터만 존재 (파일명 필터 없음), 부분적 경로 필터 |
| **Low** | 고정 경로 사용이나 추가 보안 권고 사항 있음 |
| **Info** | 보안 개선 권고 (UUID 파일명 미사용 등) |

---

### 출력 형식

자동스캔 결과(`<prefix>_task24.json`)에서 수동 확정이 필요한 항목만 findings로 출력합니다.
자동스캔 JSON에 이미 있는 `endpoint_diagnoses`는 포함하지 않으며, **보완 findings만** 작성합니다.

> **`affected_endpoints` 작성 규칙** — 각 finding에 영향 받는 API 목록을 구조화 배열로 명시.
> 보고서 렌더링 시 Confluence Expand 매크로 또는 `<details>` 펼치기 섹션으로 자동 출력됩니다.
> - `method`: HTTP 메서드 (POST/GET 등)
> - `path`: Request Mapping 경로 (예: `/admin/file/upload`)
> - `controller`: 클래스명.메서드명() (예: `FileAdminController.upload()`)
> - `description`: 해당 엔드포인트에서 파일 처리 취약점 발현 방식 한 줄 설명

```json
{
  "task_id": "2-4",
  "status": "completed",
  "findings": [
    {
      "id": "FILE-001",
      "title": "취약점 제목",
      "severity": "High",
      "category": "File Handling / IDOR",
      "description": "상세 설명 — 자동스캔이 탐지하지 못한 권한 검증 누락 또는 우회 기법",
      "affected_endpoints": [
        {
          "method": "POST",
          "path": "/api/upload",
          "controller": "FileController.upload()",
          "description": "MIME 타입 검증 및 확장자 화이트리스트 미적용"
        }
      ],
      "evidence": {
        "file": "src/controller/FileController.java",
        "lines": "50-65",
        "code_snippet": "취약 코드"
      },
      "cwe_id": "CWE-22",
      "owasp_category": "A01:2021 Broken Access Control",
      "diagnosis_method": "수동진단(LLM)",
      "result": "취약",
      "needs_review": false,
      "manual_review_note": "코드 직접 확인 근거",
      "recommendation": "조치 방안"
    }
  ],
  "executed_at": "",
  "claude_session": ""
}
```

**주의**: `endpoint_diagnoses` 키는 출력하지 않는다 (자동스캔 JSON과 중복).
findings 배열이 비어 있으면(`[]`) 파일을 저장하되 `supplemental_sources`에서 자동으로 무시된다.

---

### 금지사항
- 웹쉘 코드 작성 금지
- 추측 금지 (코드 근거 필수)
- 민감정보 포함 금지
- 스크립트가 이미 판정한 "양호" 항목은 재검토 불필요

---

## 수동진단 프롬프트 템플릿 (LLM 심층 분석용)

> **공통 전제**: 아래 4종 프롬프트는 자동 스크립트가 `needs_review: true`로
> 분류한 항목 또는 자동 탐지 한계 구간(비즈니스 로직·우회 기법)에 대해 사용합니다.
> `manual_review_prompt.md`의 **답변 원칙 5가지**를 동일하게 적용합니다.

---

### 프롬프트 1 — 다운로드 권한 검증 (IDOR / BOLA)

**진단 목표**: 요청자가 본인 소유의 파일만 다운로드할 수 있는지 확인.
권한 검증 없이 타인의 파일 ID/경로로 다운로드가 가능하면 **[취약: IDOR/BOLA]** 판정.

```
당신은 엔터프라이즈 환경의 취약점을 분석하는 '시니어 애플리케이션 보안 컨설턴트'입니다.
아래 코드를 분석하여 파일 다운로드 기능의 접근 제어(Authorization) 취약점을 진단해 주십시오.

### 진단 기준 (OWASP A01:2021 Broken Access Control / KISA 접근통제)
1. 세션 또는 JWT 토큰에서 추출한 현재 사용자 ID와 다운로드 대상 파일의 소유자(DB 조회)를
   명시적으로 비교하는 로직이 있는지 확인하십시오.
2. 파일 ID(Long)나 파일명(String)을 파라미터로 받을 때, 인증 없이 임의의 파일에
   접근 가능한지 (IDOR: Insecure Direct Object Reference) 확인하십시오.
3. 권한 검증이 Service 계층에 위임된 경우 해당 Service 코드도 함께 제공해 주십시오.

### 판정 기준
- 양호: 세션/토큰 소유자 == DB 파일 소유자 비교 로직 존재
- 취약: 파일 ID/경로만으로 다운로드 가능, 소유자 검증 없음 (IDOR)
- 정보: Service 위임 구조로 권한 검증 여부 코드만으로 확인 불가

### 답변 원칙
- 권한 검증 로직이 명확히 보이지 않으면 "확인 불가"로 명시하고 추가 코드를 요청하십시오.
- 판정 시 OWASP A01:2021 또는 KISA 취약점 항목 번호를 근거로 제시하십시오.

### 분석 대상 코드
- API: [여기에 API 경로 + HTTP Method 입력]
- 스크립트 판정: [needs_review 사유 입력]

[Controller 코드]
(붙여넣기)

[Service 코드]
(붙여넣기 — 있는 경우)

[Repository / DB 조회 쿼리]
(붙여넣기 — 있는 경우)
```

---

### 프롬프트 2 — 안전한 업로드 검증 우회 (이중 확장자 / Null Byte)

**진단 목표**: 스크립트가 탐지한 확장자 검증 로직이 우회 가능한 구현인지 심층 확인.
이중 확장자, Null Byte, MIME 스푸핑 등 우회 시나리오에 취약하면 **[취약: 파일 업로드 우회]** 판정.

```
당신은 엔터프라이즈 환경의 취약점을 분석하는 '시니어 애플리케이션 보안 컨설턴트'입니다.
아래 파일 업로드 코드가 다음 우회 기법에 대해 안전한지 진단해 주십시오.

### 우회 기법 진단 기준 (OWASP A03:2021 / KISA 파일 업로드 취약점)
1. **이중 확장자 우회**: `file.php.jpg` 형식의 파일명에서 마지막 확장자만 검사하는지
   확인하십시오. `getOriginalFilename()`의 마지막 `.` 이후 부분만 잘라내면 우회 불가합니다.
2. **Null Byte Injection**: `file.php%00.jpg` 형식의 파일명 처리 시 Java 8 미만 환경에서
   취약할 수 있습니다. Null Byte 필터링 또는 Java 버전을 확인하십시오.
3. **Content-Type 스푸핑**: `MultipartFile.getContentType()`은 클라이언트가 조작 가능합니다.
   서버 사이드에서 Tika 등을 사용한 실제 MIME 타입 검증이 없으면 우회 가능합니다.
4. **인프라 설정 오류**: 저장 디렉토리가 Web Root 하위에 있거나 실행 권한이 있으면
   업로드된 스크립트가 직접 실행될 수 있습니다. 저장 경로 설정 코드를 확인하십시오.

### 판정 기준
- 양호: 마지막 확장자만 검증 + 서버사이드 MIME 검증 + Web Root 외부 저장
- 취약: 위 항목 중 하나 이상 우회 가능
- 정보/추가 필요: 저장 경로 또는 인프라 설정 코드가 제공되지 않아 판단 불가

### 답변 원칙
- 코드에서 근거를 찾을 수 없는 경우 "확인 불가"로 명시하십시오.
- OWASP WSTG-UPLD-01 또는 KISA 가이드 항목을 판정 근거로 제시하십시오.

### 분석 대상 코드
- API: [여기에 API 경로 + HTTP Method 입력]
- 스크립트 판정: [has_tika_mime_check / has_ext_whitelist 값 입력]

[Controller 업로드 코드]
(붙여넣기)

[Service / 파일 저장 유틸 코드]
(붙여넣기 — 있는 경우)

[저장 경로 설정 (@Value / application.yml)]
(붙여넣기 — 있는 경우)
```

---

### 프롬프트 3 — 악성코드 탐지 / 파일 무해화 (Sanitization)

**진단 목표**: 이미지·PDF·Office 파일 등 허용된 형식으로 위장한 악성코드에 대한
무해화(Sanitization) 로직이 올바르게 구현되었는지 확인.
무해화 없이 저장·배포 시 **[취약: 악성파일 업로드]** 판정.

```
당신은 엔터프라이즈 환경의 취약점을 분석하는 '시니어 애플리케이션 보안 컨설턴트'입니다.
아래 파일 업로드 처리 코드에서 OWASP 권고에 따른 파일 무해화(Sanitization) 로직을 진단해 주십시오.

### 진단 기준 (OWASP File Upload Cheat Sheet / KISA)
1. **이미지 파일**: ImageIO.read() 후 재인코딩하여 저장하면 내포된 악성 스크립트를 제거합니다.
   단순 스트림 복사만 하는 경우 무해화 없음으로 판정합니다.
2. **PDF/Office 파일**: Apache PDFBox, Apache POI 등으로 파싱 후 재저장하지 않고
   원본 바이너리를 그대로 저장하면 악성 매크로/스크립트 포함 위험이 있습니다.
3. **압축 파일 (ZIP/TAR)**: 압축 해제 후 내부 파일에도 동일한 검증 로직이 적용되는지,
   Zip Slip 취약점(경로 탈출)에 대한 방어 코드가 있는지 확인하십시오.
4. **CDN/별도 스토리지**: S3 등 외부 스토리지에 저장 후 다운로드 URL을 제공하는 경우,
   Content-Disposition 헤더가 `attachment`로 강제 설정되었는지 확인하십시오.

### 판정 기준
- 양호: 파일 형식별 재인코딩/재파싱 후 저장, Content-Disposition: attachment 강제
- 취약: 원본 바이너리 그대로 저장 + 인라인 렌더링 허용
- 정보: 파일 처리 로직이 외부 라이브러리에 위임되어 세부 구현 확인 불가

### 답변 원칙
- 라이브러리 호출만 있고 내부 로직 코드가 없으면 "추가 정보 필요"로 명시하십시오.
- OWASP File Upload Cheat Sheet 또는 KISA 항목을 판정 근거로 제시하십시오.

### 분석 대상 코드
- API: [여기에 API 경로 + HTTP Method 입력]
- 허용 파일 형식: [예: image/jpeg, application/pdf]

[파일 저장 Service / Util 코드]
(붙여넣기)

[설정 코드 (S3 업로드, CDN URL 생성 등)]
(붙여넣기 — 있는 경우)
```

---

### 프롬프트 4 — LFI / RFI 특화 검증 (View Resolver / Whitelist 우회)

**진단 목표**: 동적 View Resolver를 통한 Template Injection 가능성과
URL Whitelist 검증 로직의 구현 결함(정규식 오류, 서브도메인 우회 등)을 심층 확인.

```
당신은 엔터프라이즈 환경의 취약점을 분석하는 '시니어 애플리케이션 보안 컨설턴트'입니다.
아래 코드를 분석하여 LFI(Local File Inclusion) 및 RFI(Remote File Inclusion) 취약점을
다음 고급 시나리오 기준으로 심층 진단해 주십시오.

### 진단 기준 1 — LFI via Dynamic View Resolver (OWASP A03:2021)
1. Spring의 InternalResourceViewResolver, FreeMarker, Thymeleaf 등에서
   사용자 입력값이 View 이름에 직접 포함되는지 확인하십시오. (Template Injection → LFI)
   - 예: `return "template/" + userInput;` → `../../etc/passwd` 우회 가능
2. `ModelAndView` 또는 `return (String)` 패턴에서 View 이름에 사용자 입력 포함 여부를 확인하십시오.
3. View Resolver 설정에 `prefix/suffix`가 고정되어 있어도 `../ ` 경로 탈출이 가능한지 확인하십시오.

### 진단 기준 2 — RFI/SSRF URL Whitelist 우회 (OWASP A10:2021 SSRF)
1. **서브도메인 우회**: Whitelist가 `trusted.com`으로 시작하는지 확인할 경우
   `trusted.com.evil.com` 형태로 우회 가능합니다. `.endsWith()` 또는 `.equals()` 검증 방식을 확인하십시오.
2. **정규식 앵커 미사용**: 정규식에 `^`와 `$` 앵커가 없으면 중간 삽입으로 우회 가능합니다.
3. **URL 인코딩 우회**: `@`, `#`, `?` 등을 활용한 URL 파싱 혼동 공격 (예: `http://trusted.com@evil.com/`)
   에 대한 파싱 정규화 여부를 확인하십시오.
4. **DNS Rebinding 가능성**: IP Whitelist가 도메인 기반이라면 DNS Rebinding 공격 가능성을 명시하십시오.

### 판정 기준
- 양호: View 이름 고정값 사용 / URL은 도메인+경로 완전 일치(equals) 검증
- 취약: 사용자 입력 View 이름 사용 / Whitelist 정규식 우회 가능
- 정보: View Resolver 설정 코드 미제공 / Whitelist 구현체 코드 미제공으로 판단 불가

### 답변 원칙
- 정규식 패턴이 제공된 경우 직접 우회 가능 여부를 검증하고 예시를 제시하십시오.
- 코드가 모호하여 판정 불가하면 필요한 추가 코드(View Resolver Bean 설정 등)를 명시 요청하십시오.
- OWASP A03:2021(LFI), A10:2021(SSRF) 또는 KISA 항목을 판정 근거로 제시하십시오.

### 분석 대상 코드
- API: [여기에 API 경로 + HTTP Method 입력]
- 스크립트 판정: [needs_review 사유 또는 RFI 취약 detail 입력]

[Controller 코드 (View Resolver 또는 외부 URL 호출)]
(붙여넣기)

[URL Whitelist 검증 로직 / 정규식]
(붙여넣기 — 있는 경우)

[View Resolver Bean 설정]
(붙여넣기 — 있는 경우)
```
