#!/usr/bin/env python3
import json, sys, pathlib

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print('Usage: merge_results.py <out.json> <in1.json> <in2.json> ...')
        sys.exit(2)
    out = {"tasks": []}
    for p in sys.argv[2:]:
        out["tasks"].append(json.loads(pathlib.Path(p).read_text()))
    pathlib.Path(sys.argv[1]).write_text(json.dumps(out, indent=2))
