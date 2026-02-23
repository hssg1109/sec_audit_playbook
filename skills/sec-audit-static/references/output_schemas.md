# Output Schemas

모든 태스크 결과는 아래 스키마를 준수해야 합니다.

## Task Output Schema (task_output_schema.json)

일반 태스크 결과용 (task_11, task_21).

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "Task Output Schema",
  "type": "object",
  "required": ["task_id", "status", "findings"],
  "properties": {
    "task_id": { "type": "string", "pattern": "^[0-9]+-[0-9]+$" },
    "status": { "type": "string", "enum": ["completed", "failed", "partial"] },
    "findings": { "type": "array", "items": { "type": "object" } },
    "executed_at": { "type": "string", "format": "date-time" },
    "claude_session": { "type": "string" },
    "notes": { "type": "string" },
    "errors": { "type": "array" },
    "metadata": { "type": "object" }
  },
  "additionalProperties": false
}
```

## Finding Schema (finding_schema.json)

취약점 발견 결과용 (task_22, task_23, task_24, task_25).

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "Security Finding Schema",
  "type": "object",
  "required": ["task_id", "status", "findings"],
  "properties": {
    "task_id": { "type": "string", "pattern": "^[0-9]+-[0-9]+$" },
    "status": { "type": "string", "enum": ["completed", "failed", "partial"] },
    "findings": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["id", "title", "severity", "category", "description"],
        "properties": {
          "id": { "type": "string", "description": "취약점 고유 ID (예: VULN-001)" },
          "title": { "type": "string" },
          "severity": { "type": "string", "enum": ["Critical", "High", "Medium", "Low", "Info"] },
          "category": { "type": "string", "description": "예: SQL Injection, XSS, File Upload" },
          "description": { "type": "string" },
          "affected_endpoint": { "type": "string" },
          "affected_file": { "type": "string" },
          "evidence": { "type": ["string", "object"] },
          "recommendation": { "type": "string" },
          "cwe_id": { "type": "string", "pattern": "^CWE-[0-9]+$" },
          "owasp_category": { "type": "string" }
        }
      }
    },
    "summary": {
      "type": "object",
      "properties": {
        "total": { "type": "integer" },
        "critical": { "type": "integer" },
        "high": { "type": "integer" },
        "medium": { "type": "integer" },
        "low": { "type": "integer" },
        "info": { "type": "integer" }
      }
    },
    "executed_at": { "type": "string", "format": "date-time" },
    "claude_session": { "type": "string" },
    "notes": { "type": "string" },
    "metadata": { "type": "object" }
  },
  "additionalProperties": false
}
```

## Enhanced Injection Output (scan_injection_enhanced.py)

endpoint별 진단 결과 확장 포맷. `endpoint_diagnoses` 키로 자동 식별.

필수 필드: `task_id`, `status`, `scan_metadata`, `endpoint_diagnoses`, `global_findings`, `summary`
