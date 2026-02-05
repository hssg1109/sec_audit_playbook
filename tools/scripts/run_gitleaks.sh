#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 --repo /path/to/repo [--out state/seed_gitleaks.json]"
}

REPO=""
OUT="state/seed_gitleaks.json"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo) REPO="$2"; shift 2;;
    --out) OUT="$2"; shift 2;;
    *) usage; exit 1;;
  esac
done

if [[ -z "$REPO" ]]; then
  usage; exit 1
fi

if ! command -v gitleaks >/dev/null 2>&1; then
  echo "gitleaks not found in PATH. Install it first (brew install gitleaks)" >&2
  exit 2
fi

mkdir -p "$(dirname "$OUT")"

# --no-git scans working tree as-is. --redact hides secrets in report.
# --exit-code 0 keeps automation running even if findings exist.
gitleaks detect --source "$REPO" --report-format json --report-path "$OUT" --no-git --redact --exit-code 0

echo "Gitleaks report written to $OUT"
