# Task 2-4 — 파일처리 진단 (File Handling)

> **관련 파일**
> - 자동 스캔: `tools/scripts/scan_file_processing.py`
> - LLM 프롬프트: `skills/sec-audit-static/references/task_prompts/task_24_file_handling.md`
> **스크립트 버전**: v1.0.0 (2026-03-06)
> **최종 갱신**: 2026-03-09

---

## 진단 항목

| 카테고리 | CWE | 설명 |
|---------|-----|------|
| `[U]` 파일 업로드 | CWE-434 | UUID 난수화, Tika MIME 검증, 확장자 Whitelist, 크기 제한 |
| `[D]` 파일 다운로드/LFI | CWE-22 | HTTP 파라미터 → 파일 API Taint, Path Traversal 필터 |
| `[R]` RFI/SSRF | CWE-918 | 사용자 입력 → 외부 요청 URL Whitelist |
| `[C]` 설정 파일 | CWE-16 | max-file-size, multipart 전역 설정 |

---

## 진단 흐름

```mermaid
flowchart TD
    SRC([소스코드 + api_inventory.json]) --> SCAN

    subgraph AUTO["Phase 2 — scan_file_processing.py"]
        SCAN["소스 파일 전체 스캔"] --> U & D & R & C

        subgraph U["[U] 파일 업로드 진단"]
            U1["@PostMapping + MultipartFile 탐지"]
            U1 --> U2{"보안 검증 체크리스트"}
            U2 -->|UUID 파일명 난수화| UA["UUID.randomUUID() 탐지"]
            U2 -->|MIME 타입 검증| UB["Tika 또는 Files.probeContentType() 탐지"]
            U2 -->|확장자 Whitelist| UC["allowedExtension / .endsWith('.jpg') 탐지"]
            U2 -->|크기 제한| UD[".getSize() / MAX_FILE_SIZE 탐지"]
            UA & UB & UC & UD --> U_JUDGE{"누락 항목?"}
            U_JUDGE -->|1개 이상 누락| VUL_U["result: 취약\nneeds_review: true"]
            U_JUDGE -->|모두 존재| SAFE_U["result: 양호"]
        end

        subgraph D["[D] 다운로드/LFI 진단"]
            D1["파일 API 패턴 탐지\nFiles.readAllBytes / FileInputStream\nnew File(param) / Paths.get(param)"]
            D1 --> D2{"HTTP 파라미터 Taint?"}
            D2 -->|Taint 확인| D3{"Path Traversal 필터?"}
            D3 -->|필터 없음| VUL_D["result: 취약\nCWE-22 Path Traversal"]
            D3 -->|필터 있음| INFO_D["result: 정보\n필터 우회 가능성 수동 확인"]
            D2 -->|Taint 없음| SAFE_D["result: 양호"]
        end

        subgraph R["[R] RFI/SSRF 진단"]
            R1["외부 요청 API 탐지\nRestTemplate / WebClient\nHttpURLConnection / OkHttp"]
            R1 --> R2{"HTTP 파라미터 → URL Taint?"}
            R2 -->|Taint 확인| R3{"URL Whitelist?"}
            R3 -->|없음| VUL_R["result: 취약\nCWE-918 SSRF"]
            R3 -->|있음| INFO_R["result: 정보\nWhitelist 우회 수동 확인"]
            R2 -->|Taint 없음| SAFE_R["result: 양호"]
        end

        subgraph C["[C] 설정 파일 진단"]
            C1["application*.yml 스캔\nmax-file-size / max-request-size\nspring.servlet.multipart"]
            C1 --> C2{"제한 설정 존재?"}
            C2 -->|없음| INFO_C["result: 정보\n기본값 무제한 위험"]
            C2 -->|있음| SAFE_C["result: 양호"]
        end
    end

    AUTO --> LLM

    subgraph LLM["Phase 3 — LLM 수동분석 (task_24_file_handling.md)"]
        LA["Template 1: IDOR/BOLA 확인\n(파일 소유자 검증 로직)"]
        LB["Template 2: 업로드 Bypass 확인\n(MIME + 확장자 이중 검증)"]
        LC["Template 3: Sanitization 확인\n(파일명/경로 정규화)"]
        LD["Template 4: LFI/RFI View Resolver\n(뷰 이름에 파일 경로 삽입)"]
        LA & LB & LC & LD --> OUT["task24_llm.json"]
    end
```

---

## 업로드 보안 체크리스트

| 검증 항목 | 탐지 패턴 | 미적용 시 위험 |
|----------|-----------|---------------|
| **UUID 파일명 난수화** | `UUID.randomUUID()` | 예측 가능한 파일명으로 직접 접근 |
| **MIME 타입 검증** | `Tika`, `Files.probeContentType()` | 확장자만 변경한 악성 파일 업로드 |
| **확장자 Whitelist** | `allowedExtension`, `.endsWith('.jpg')` | 임의 확장자 업로드 (WebShell 등) |
| **파일 크기 제한** | `.getSize()`, `MAX_FILE_SIZE` | DoS 공격 (대용량 파일) |
| **저장 경로 분리** | `uploadPath`, `storageDir` | WebRoot 내 직접 실행 위험 |

---

## LLM 프롬프트 4개 템플릿

| 템플릿 | 목적 | 핵심 확인 포인트 |
|--------|------|----------------|
| T1 IDOR/BOLA | 파일 소유자 검증 | `findById` 후 `userId` 일치 확인 여부 |
| T2 Upload Bypass | MIME + 확장자 이중 검증 | `Tika.detect()` + `allowedExtension` 동시 적용 |
| T3 Sanitization | 파일명/경로 정규화 | `..`, `/`, `\` 필터링 + `normalize()` |
| T4 View Resolver LFI | 뷰 이름 경로 주입 | `return "../../etc/passwd"` 가능 여부 |

---

## 산출물 구조

### task24.json (자동스캔)

```json
{
  "task_id": "2-4",
  "findings": [
    {
      "category": "UPLOAD",
      "result": "취약",
      "severity": "Critical",
      "title": "파일 업로드 검증 미흡 (웹쉘 업로드 위험)",
      "file": "FileUploadController.java",
      "line": 42,
      "missing_checks": ["tika_mime", "ext_whitelist"],
      "needs_review": true
    }
  ],
  "config_findings": [
    {
      "category": "CONFIG",
      "result": "정보",
      "title": "multipart max-file-size 미설정"
    }
  ]
}
```

### task24_llm.json (LLM 보완)

```json
{
  "task_id": "2-4-llm",
  "findings": [
    {
      "endpoint": "POST /api/v1/files/upload",
      "template": "T2_upload_bypass",
      "result": "취약",
      "diagnosis_detail": "MIME 검증 없이 확장자만 검사 — Content-Type 조작으로 우회 가능"
    }
  ]
}
```

---

## 변경 이력

| 버전 | 날짜 | 요약 |
|------|------|------|
| v1.0.0 | 2026-03-06 | 초기 구현 — Upload/Download/LFI/RFI/Config 4카테고리 |
