#!/usr/bin/env python3
import re, sys

REDACT_PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AKIA***************"),
    (re.compile(r"(?i)password\s*[:=]\s*[^\s]+"), "password=REDACTED"),
    (re.compile(r"(?i)token\s*[:=]\s*[^\s]+"), "token=REDACTED"),
]

def redact(text):
    for pattern, replacement in REDACT_PATTERNS:
        text = pattern.sub(replacement, text)
    return text

if __name__ == "__main__":
    data = sys.stdin.read()
    sys.stdout.write(redact(data))
