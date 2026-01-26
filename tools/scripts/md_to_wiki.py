#!/usr/bin/env python3
import sys

if __name__ == '__main__':
    text = sys.stdin.read()
    text = text.replace('# ', '= ').replace('## ', '== ').replace('### ', '=== ')
    sys.stdout.write(text)
