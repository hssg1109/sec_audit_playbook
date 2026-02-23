# Static Audit Scripts

Canonical automation scripts (repo `tools/scripts/`):

## Core Scripts

- `parse_asset_excel.py`: asset Excel -> JSON
- `merge_results.py`: merge task results -> `final_report.json`
- `redact.py`: redact sensitive data in reports
- `validate_task_output.py`: schema validation for task outputs/reports
- `generate_finding_report.py`: generate Markdown report from findings

## Scan Scripts

- `scan_api.py` (v3.2): API endpoint inventory extraction
  - Java/Kotlin dual-mode parsing (auto-detect by file extension)
  - Java: `@GetMapping`/`@PostMapping` + return type method declarations
  - Kotlin: `fun` keyword declarations
  - Parameter parsing: `Type name` (Java) / `name: Type` (Kotlin)
  - 블록 주석 (`/* ... */`) 자동 제거: 주석 내 컨트롤러는 `commented_controllers`에 별도 기록
  - 인증 4-Level 매트릭스 + 이진 분류 (`auth_required: true/false`):
    - L1 완전 인증: `@Session(required=true, permitted=true)` → true
    - L2 기본 인증: `@Session(required=true)` 또는 bare `@Session` → true
    - L3 비인증: `@Session(required=false)` → false
    - L4 조건부 인증: `@Session(required=false, permitted=true)` → false
    - `@PreAuthorize`, `@Secured` → true
    - `--auth-annotations` 옵션으로 프로젝트별 어노테이션 추가
  - DTO 카탈로그 연동: `--dto-catalog` 옵션으로 파라미터 타입 필드 해석
  - Output: JSON with endpoints, method_stats, module_stats, security_configs, auth_stats, auth_detail_stats, commented_controllers

- `scan_dto.py` (v1.0): DTO/타입 카탈로그 추출
  - Java/Kotlin dual-mode parsing (auto-detect by file extension)
  - Java: `@Data`(Lombok), `@Entity`(JPA), nested static class, 필드 어노테이션
  - Kotlin: `data class` primary constructor, `val`/`var` 프로퍼티
  - 중첩 클래스 지원: `OuterClass.InnerClass` qualified naming
  - 상속 해석: `extends`(Java) / `:`(Kotlin) → 부모 필드 병합(inherited 마킹)
  - Output: JSON type catalog with field-level detail, type_index
  - scan_api.py와 연동: `--dto-catalog` 옵션으로 파라미터 타입 enrichment

- `scan_injection_enhanced.py` (v2.3): Endpoint-level injection diagnosis
  - Controller → Service → Repository → SQL Builder 호출 체인 자동 추적
  - Java dependency injection 지원: `@Autowired`, `@RequiredArgsConstructor`, constructor injection
  - JPA built-in method 자동 양호 판정 (`findById`, `save`, `deleteById` 등)
  - Kotlin SQL Builder 5-method detection:
    1. `${expression}` 파라미터 포함
    2. `$variable` 단순 보간
    3. 파생 변수 추적 (param → local var → SQL)
    4. `+ param +` 문자열 연결
    5. 델리게이트 함수 재귀 추적 (depth 3)
  - Global scan: OS Command Injection, SSI Injection, Kotlin SQL Builder 전역 패턴
  - Output: endpoint_diagnoses (양호/취약/정보/N/A), global_findings, summary

- `scan_injection_patterns.py` (v2.1): Pattern definitions for injection detection
  - `SQLI_VULNERABLE_PATTERNS`: MyBatis `${}`, JDBC concat, Kotlin template 등
  - `SQLI_SAFE_PATTERNS`: `#{}`, `:param`, `?` binding 등
  - `SQLI_CONCAT_PATTERNS`: Kotlin `${expr}`, `$var`, `+ var +`
  - `CMDI_*`, `SSI_*` patterns

- `extract_endpoints_rg.py`: Spring/Kotlin endpoint inventory (rg/regex, low-cost)
- `extract_endpoints_treesitter.py`: Spring/Kotlin endpoint inventory (tree-sitter, higher precision)

## Publishing Scripts

- `publish_confluence.py` (v2.0): Confluence Server/DC auto-publishing
  - Markdown → XHTML conversion (with fallback)
  - JSON → XHTML renderers:
    - `_json_to_xhtml_asset()`: task_11 asset identification
    - `_json_to_xhtml_api()`: task_21 standard API inventory
    - `_json_to_xhtml_api_inventory()`: scan_api.py output format
    - `_json_to_xhtml_vuln()`: task_22~25 standard vulnerability findings
    - `_json_to_xhtml_enhanced_injection()`: scan_injection_enhanced.py output format
    - `_json_to_xhtml_final()`: final_report.json
  - Auto-detection: `endpoint_diagnoses` key → enhanced injection, `endpoints` key → api_inventory
  - `confluence_page_map.json`으로 페이지 구조 관리

## Utility Scripts

- `migrate_test_groups.py`: internal migration utility (use only if needed)
- `rename_remove_prefix.py`: internal rename utility (use only if needed)

Use only the scripts required for the target workflow; mark optional ones explicitly.

## Notes

- Task outputs must include `metadata.source_repo_url`, `metadata.source_repo_path`, `metadata.source_modules`.
- `generate_finding_report.py` 실행 시 `--source-label` 필수.
  - Confluence(md2cf) 업로드 시 `--anchor-style md2cf` 사용.
  - Confluence 앵커 링크는 **헤더 텍스트 기반 자동 앵커**가 가장 안정적임.
    - `finding-<id>` 형태의 헤더를 출력하고, 실제 취약점 제목은 별도 텍스트로 표시.
    - 링크는 `#finding-<id>` 형태로 생성.
