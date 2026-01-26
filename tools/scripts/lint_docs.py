#!/usr/bin/env python3
import sys, pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
DOCS = ROOT / 'docs'

fail = False
for path in DOCS.rglob('*.md'):
    if path.read_text().strip() == '':
        print(f'Empty doc: {path}')
        fail = True

if fail:
    sys.exit(1)
print('OK')
