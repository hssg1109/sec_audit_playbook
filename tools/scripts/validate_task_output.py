#!/usr/bin/env python3
import json, sys, pathlib
from jsonschema import Draft202012Validator

BASE = pathlib.Path(__file__).resolve().parents[2]
SCHEMA_PATH = BASE / 'schemas' / 'task_output_schema.json'

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Usage: validate_task_output.py <task_result.json>')
        sys.exit(2)
    data = json.loads(pathlib.Path(sys.argv[1]).read_text())
    schema = json.loads(SCHEMA_PATH.read_text())
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(data), key=lambda e: e.path)
    if errors:
        for e in errors:
            print(f'Validation error at {list(e.path)}: {e.message}')
        sys.exit(1)
    print('OK')
