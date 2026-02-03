#!/usr/bin/env python3
"""
작업 결과 JSON 스키마 검증 스크립트
schemas/ 폴더의 스키마를 기반으로 작업 결과를 자동 검증합니다.

사용법:
    python validate_task_output.py <result_file> [--schema <schema_file>]
    python validate_task_output.py state/task_21_result.json
    python validate_task_output.py state/task_22_result.json --schema schemas/finding_schema.json
"""

import json
import sys
import argparse
from pathlib import Path


def validate_required_fields(data: dict, schema: dict) -> list[str]:
    """필수 필드 존재 여부를 검증합니다."""
    errors = []
    required = schema.get("required", [])
    for field in required:
        if field not in data:
            errors.append(f"필수 필드 누락: '{field}'")
    return errors


def validate_field_type(value, expected_type: str) -> bool:
    """필드 타입을 검증합니다."""
    type_map = {
        "string": str,
        "integer": int,
        "number": (int, float),
        "boolean": bool,
        "array": list,
        "object": dict,
    }
    expected = type_map.get(expected_type)
    if expected is None:
        return True
    return isinstance(value, expected)


def validate_enum(value, enum_values: list) -> bool:
    """열거형 값을 검증합니다."""
    return value in enum_values


def validate_data(data: dict, schema: dict) -> list[str]:
    """데이터를 스키마에 따라 검증합니다."""
    errors = []

    # 필수 필드 검증
    errors.extend(validate_required_fields(data, schema))

    # 속성별 검증
    properties = schema.get("properties", {})
    for field, field_schema in properties.items():
        if field not in data:
            continue

        value = data[field]

        # 타입 검증
        expected_type = field_schema.get("type")
        if expected_type and not validate_field_type(value, expected_type):
            errors.append(
                f"타입 불일치: '{field}' - 기대: {expected_type}, 실제: {type(value).__name__}"
            )

        # 열거형 검증
        enum_values = field_schema.get("enum")
        if enum_values and not validate_enum(value, enum_values):
            errors.append(
                f"유효하지 않은 값: '{field}' = '{value}' (허용: {enum_values})"
            )

        # 패턴 검증
        pattern = field_schema.get("pattern")
        if pattern and isinstance(value, str):
            import re
            if not re.match(pattern, value):
                errors.append(
                    f"패턴 불일치: '{field}' = '{value}' (패턴: {pattern})"
                )

        # 배열 항목 검증
        if expected_type == "array" and isinstance(value, list):
            items_schema = field_schema.get("items", {})
            if items_schema.get("required"):
                for idx, item in enumerate(value):
                    if isinstance(item, dict):
                        for req_field in items_schema["required"]:
                            if req_field not in item:
                                errors.append(
                                    f"배열 항목[{idx}] 필수 필드 누락: '{req_field}'"
                                )

    # 추가 속성 검증
    if schema.get("additionalProperties") is False:
        allowed = set(properties.keys())
        actual = set(data.keys())
        extra = actual - allowed
        if extra:
            errors.append(f"허용되지 않은 필드: {extra}")

    return errors


def main():
    parser = argparse.ArgumentParser(description="작업 결과 JSON 스키마 검증 도구")
    parser.add_argument("result_file", help="검증할 결과 파일 경로")
    parser.add_argument(
        "--schema", "-s",
        help="스키마 파일 경로 (미지정 시 자동 감지)",
        default=None,
    )
    args = parser.parse_args()

    result_path = Path(args.result_file)
    if not result_path.exists():
        print(f"Error: 파일을 찾을 수 없습니다: {args.result_file}")
        sys.exit(1)

    # 결과 파일 로드
    try:
        with open(result_path, encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error: JSON 파싱 실패: {e}")
        sys.exit(1)

    # 스키마 파일 결정
    if args.schema:
        schema_path = Path(args.schema)
    else:
        # task_id 기반 자동 감지
        base_dir = Path(__file__).resolve().parent.parent.parent
        task_id = data.get("task_id", "")
        # finding_schema를 사용하는 태스크 목록 (취약점 발견 결과)
        finding_tasks = {"2-2", "2-3", "2-4", "2-5"}
        if task_id in finding_tasks:
            schema_path = base_dir / "schemas" / "finding_schema.json"
        else:
            schema_path = base_dir / "schemas" / "task_output_schema.json"

    if not schema_path.exists():
        print(f"Error: 스키마 파일을 찾을 수 없습니다: {schema_path}")
        sys.exit(1)

    # 스키마 로드
    with open(schema_path, encoding="utf-8") as f:
        schema = json.load(f)

    # 검증 실행
    print(f"검증 대상: {args.result_file}")
    print(f"스키마: {schema_path}")
    print("-" * 50)

    errors = validate_data(data, schema)

    if errors:
        print(f"검증 실패 ({len(errors)}건의 오류):")
        for err in errors:
            print(f"  - {err}")
        sys.exit(1)
    else:
        print("검증 통과: 모든 필드가 스키마를 준수합니다.")
        sys.exit(0)


if __name__ == "__main__":
    main()
