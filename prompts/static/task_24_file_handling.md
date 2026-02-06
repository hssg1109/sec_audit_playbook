## Task: 2-4 파일 처리 검토

**역할**: 당신은 보안 진단 전문가입니다.
**입력 파일**: state/task_21_result.json (API 인벤토리)
**출력 파일**: state/task_24_result.json
**출력 스키마**: schemas/finding_schema.json

---

### 컨텍스트
Task 2-1에서 추출한 API 인벤토리를 기반으로 **파일 업로드**, **파일 다운로드**, **Path Traversal**, **LFI/RFI** 취약점을 정적 분석합니다.

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

**양호 조건 (아래 중 하나 이상 충족):**
- 확장자 필터 + 파일명 필터가 동시에 존재
- 고정 로직으로 업로드하며 사용자 입력값 미포함
- 고정 로직에 사용자 입력값 포함되나 필터링 후 포함
- 파일명이 UUID 등 고유값으로 자동 생성

**취약 조건:**
- 확장자 필터 / 파일명 필터가 모두 확인되지 않는 경우 → **취약**
- 고정 로직에 사용자 입력값이 포함되나 필터링 미적용 → **취약**

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

```json
{
  "task_id": "2-4",
  "status": "completed",
  "findings": [
    {
      "id": "FILE-001",
      "title": "취약점 제목",
      "severity": "High",
      "category": "File Handling / Path Traversal",
      "description": "상세 설명",
      "affected_endpoint": "/api/download",
      "evidence": {
        "file": "src/controller/FileController.java",
        "lines": "50-65",
        "code_snippet": "취약 코드"
      },
      "cwe_id": "CWE-22",
      "owasp_category": "A01:2021 Broken Access Control",
      "recommendation": "조치 방안"
    }
  ],
  "metadata": {
    "source_repo_url": "http://code.example.com/projects/PROJ/repos/repo/",
    "source_repo_path": "/path/to/local/repo",
    "source_modules": ["module-a"],
    "report_wiki_url": "https://wiki.example.com/pages/viewpage.action?pageId=123",
    "report_wiki_status": "published"
  },
  "executed_at": "",
  "claude_session": ""
}
```

---

### 금지사항
- 웹쉘 코드 작성 금지
- 추측 금지 (코드 근거 필수)
- 민감정보 포함 금지
- API 인벤토리에 없는 파일을 임의로 탐색 금지
