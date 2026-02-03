#!/usr/bin/env python3
"""
Confluence 페이지 제목에서 '[AI보안진단] ' prefix를 일괄 제거하는 스크립트.

Usage:
    python tools/scripts/rename_remove_prefix.py --dry-run
    python tools/scripts/rename_remove_prefix.py
"""
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
import base64

PREFIXES_TO_REMOVE = ["[AI보안진단] ", "[AI보안진단]"]

# ---------------------------------------------------------------------------
# reuse .env loader / config / auth from publish_confluence.py
# ---------------------------------------------------------------------------

def load_env(path=".env"):
    if not os.path.isfile(path):
        return
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
                value = value[1:-1]
            os.environ.setdefault(key, value)


def get_config():
    return {
        "base_url": os.environ.get("CONFLUENCE_BASE_URL", "").rstrip("/"),
        "space_key": os.environ.get("CONFLUENCE_SPACE_KEY", ""),
        "parent_id": os.environ.get("CONFLUENCE_PARENT_ID", ""),
        "user": os.environ.get("CONFLUENCE_USER", ""),
        "token": os.environ.get("CONFLUENCE_TOKEN", ""),
    }


def build_auth_header(cfg):
    if cfg["user"]:
        cred = base64.b64encode(f"{cfg['user']}:{cfg['token']}".encode()).decode()
        return {"Authorization": f"Basic {cred}"}
    return {"Authorization": f"Bearer {cfg['token']}"}


def confluence_api(cfg, method, path, body=None):
    url = f"{cfg['base_url']}{path}"
    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "Accept": "application/json",
    }
    headers.update(build_auth_header(cfg))
    data = json.dumps(body).encode("utf-8") if body else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read()
            if not raw:
                return None
            return json.loads(raw)
    except urllib.error.HTTPError as exc:
        err_body = exc.read().decode("utf-8", errors="replace")
        print(f"[ERROR] {method} {url} -> {exc.code}", file=sys.stderr)
        print(f"        {err_body[:500]}", file=sys.stderr)
        raise SystemExit(1) from exc


def get_all_descendants(cfg, parent_id):
    """루트 페이지 아래 모든 하위 페이지를 가져온다."""
    pages = []
    start = 0
    limit = 50
    while True:
        params = urllib.parse.urlencode({
            "expand": "version",
            "start": start,
            "limit": limit,
        })
        path = f"/rest/api/content/{parent_id}/child/page?{params}"
        result = confluence_api(cfg, "GET", path)
        if not result or not result.get("results"):
            break
        for page in result["results"]:
            pages.append({
                "id": page["id"],
                "title": page["title"],
                "version": page["version"]["number"],
            })
            # 재귀적으로 하위 페이지도 가져옴
            children = get_all_descendants(cfg, page["id"])
            pages.extend(children)
        if result.get("size", 0) < limit:
            break
        start += limit
    return pages


def strip_prefix(title):
    """제목에서 prefix를 제거한다."""
    for pfx in PREFIXES_TO_REMOVE:
        if title.startswith(pfx):
            return title[len(pfx):]
    return None  # prefix 없음


def rename_page(cfg, page_id, new_title, version):
    """페이지 제목만 변경한다 (본문은 유지)."""
    payload = {
        "type": "page",
        "title": new_title,
        "version": {"number": version + 1},
    }
    confluence_api(cfg, "PUT", f"/rest/api/content/{page_id}", payload)


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Confluence 페이지 제목에서 '[AI보안진단]' prefix 일괄 제거")
    parser.add_argument("--dry-run", action="store_true",
                        help="실제 변경 없이 대상 페이지만 출력")
    args = parser.parse_args()

    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.abspath(os.path.join(script_dir, "..", ".."))
    load_env(os.path.join(repo_root, ".env"))

    cfg = get_config()
    parent_id = cfg["parent_id"]

    print(f"Root page ID: {parent_id}")
    print(f"Fetching all descendant pages...")

    pages = get_all_descendants(cfg, parent_id)
    print(f"Found {len(pages)} descendant page(s)\n")

    renamed = 0
    skipped = 0

    for page in pages:
        new_title = strip_prefix(page["title"])
        if new_title is None:
            skipped += 1
            continue

        print(f"  [{page['id']:>10s}] \"{page['title']}\"")
        print(f"         ->  \"{new_title}\"")

        if not args.dry_run:
            try:
                rename_page(cfg, page["id"], new_title, page["version"])
                print(f"         OK (v{page['version']} -> v{page['version']+1})")
            except SystemExit:
                print(f"         !! FAILED")
        else:
            print(f"         (dry-run: skipped)")
        renamed += 1

    print(f"\nDone. {renamed} renamed, {skipped} unchanged (no prefix).")


if __name__ == "__main__":
    main()
