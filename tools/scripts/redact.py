#!/usr/bin/env python3
"""
민감정보 자동 마스킹 스크립트
ai/REDACTION_RULES.md에 정의된 규칙에 따라 민감정보를 마스킹합니다.

사용법:
    python redact.py <input_file> [--output <output_file>]
    python redact.py state/task_21_result.json
    python redact.py state/task_21_result.json --output state/task_21_redacted.json
"""

import re
import json
import sys
import argparse
from pathlib import Path

# 마스킹 패턴 정의
REDACTION_PATTERNS = [
    # IPv4 주소
    {
        "name": "IPv4",
        "pattern": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
        "replacement": "[REDACTED_IP]",
        "counter": True,
    },
    # 이메일 주소
    {
        "name": "Email",
        "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "replacement": "[REDACTED_EMAIL]",
        "counter": True,
    },
    # API 키
    {
        "name": "API Key",
        "pattern": r"\b(sk|pk|api)[_-][A-Za-z0-9]{20,}\b",
        "replacement": "[REDACTED_API_KEY]",
        "counter": False,
    },
    # JWT 토큰
    {
        "name": "JWT",
        "pattern": r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
        "replacement": "[REDACTED_TOKEN]",
        "counter": False,
    },
    # 한국 전화번호
    {
        "name": "Korean Phone",
        "pattern": r"\b01[016789]-?\d{3,4}-?\d{4}\b",
        "replacement": "[REDACTED_PHONE]",
        "counter": True,
    },
    # 비밀번호 패턴 (key=value 형태)
    {
        "name": "Password",
        "pattern": r'(?i)(password|passwd|pwd|secret|token)\s*[=:]\s*["\']?[^\s"\']+["\']?',
        "replacement": r"\1=[REDACTED_PASSWORD]",
        "counter": False,
    },
    # AWS Access Key
    {
        "name": "AWS Key",
        "pattern": r"\bAKIA[0-9A-Z]{16}\b",
        "replacement": "[REDACTED_AWS_KEY]",
        "counter": False,
    },
    # 주민등록번호
    {
        "name": "Korean SSN",
        "pattern": r"\b\d{6}-[1-4]\d{6}\b",
        "replacement": "[REDACTED_SSN]",
        "counter": False,
    },
]


def redact_text(text: str) -> tuple[str, dict]:
    """텍스트에서 민감정보를 마스킹합니다."""
    stats = {}
    counter_map = {}

    for rule in REDACTION_PATTERNS:
        name = rule["name"]
        pattern = re.compile(rule["pattern"])
        matches = pattern.findall(text)
        stats[name] = len(matches)

        if rule.get("counter"):
            # 고유 값별로 번호 부여 (같은 IP는 같은 번호)
            unique_values = list(dict.fromkeys(matches))
            for idx, val in enumerate(unique_values, 1):
                replacement = rule["replacement"].replace("]", f"_{idx}]")
                text = text.replace(val, replacement)
        else:
            text = pattern.sub(rule["replacement"], text)

    return text, stats


def redact_file(input_path: str, output_path: str = None) -> dict:
    """파일의 민감정보를 마스킹합니다."""
    input_file = Path(input_path)

    if not input_file.exists():
        print(f"Error: 파일을 찾을 수 없습니다: {input_path}")
        sys.exit(1)

    content = input_file.read_text(encoding="utf-8")

    # JSON 파일인 경우 구조 유지하며 마스킹
    if input_file.suffix == ".json":
        try:
            data = json.loads(content)
            redacted_str = json.dumps(data, ensure_ascii=False, indent=2)
            redacted_str, stats = redact_text(redacted_str)
            result = json.loads(redacted_str)
            output_content = json.dumps(result, ensure_ascii=False, indent=2)
        except json.JSONDecodeError:
            output_content, stats = redact_text(content)
    else:
        output_content, stats = redact_text(content)

    # 출력
    if output_path:
        out_file = Path(output_path)
        out_file.write_text(output_content, encoding="utf-8")
        print(f"마스킹 완료: {output_path}")
    else:
        # 원본 파일 덮어쓰기
        input_file.write_text(output_content, encoding="utf-8")
        print(f"마스킹 완료: {input_path} (원본 덮어쓰기)")

    # 통계 출력
    total = sum(stats.values())
    print(f"\n마스킹 통계 (총 {total}건):")
    for name, count in stats.items():
        if count > 0:
            print(f"  - {name}: {count}건")

    return stats


def main():
    parser = argparse.ArgumentParser(description="민감정보 자동 마스킹 도구")
    parser.add_argument("input", help="입력 파일 경로")
    parser.add_argument("--output", "-o", help="출력 파일 경로 (미지정 시 원본 덮어쓰기)")
    args = parser.parse_args()

    redact_file(args.input, args.output)


if __name__ == "__main__":
    main()
