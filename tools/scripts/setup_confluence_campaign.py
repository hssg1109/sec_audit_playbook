#!/usr/bin/env python3
"""
Confluence 캠페인 페이지 계층 생성 스크립트.

주어진 루트 페이지 아래 계층적 페이지 구조를 자동으로 생성하고,
최하위 페이지 ID를 .env의 CONFLUENCE_PARENT_ID에 기록한다.

Usage:
    # 기본 — '2026 playbook 정기진단/OCB' 계층 생성 후 .env 갱신
    python tools/scripts/setup_confluence_campaign.py \\
        --root-page-id 722832415 \\
        --path "2026 playbook 정기진단/OCB" \\
        --update-env

    # 확인만 (API 호출 없음)
    python tools/scripts/setup_confluence_campaign.py \\
        --root-page-id 722832415 \\
        --path "2026 playbook 정기진단/OCB" \\
        --dry-run

    # ID만 출력 (스크립트 연동용)
    python tools/scripts/setup_confluence_campaign.py \\
        --root-page-id 722832415 \\
        --path "2026 playbook 정기진단/OCB" \\
        --print-id
"""
import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from html import escape as html_escape

# ---------------------------------------------------------------------------
# .env loader / updater
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


def update_env_key(env_path, key, new_value):
    """Update or append a KEY=VALUE line in .env file."""
    if not os.path.isfile(env_path):
        with open(env_path, "w", encoding="utf-8") as fh:
            fh.write(f"{key}={new_value}\n")
        return

    lines = open(env_path, encoding="utf-8").readlines()
    pattern = re.compile(r"^" + re.escape(key) + r"\s*=")
    updated = False
    new_lines = []
    for line in lines:
        if pattern.match(line):
            new_lines.append(f"{key}={new_value}\n")
            updated = True
        else:
            new_lines.append(line)
    if not updated:
        new_lines.append(f"{key}={new_value}\n")
    with open(env_path, "w", encoding="utf-8") as fh:
        fh.writelines(new_lines)

# ---------------------------------------------------------------------------
# Auth / HTTP
# ---------------------------------------------------------------------------

def build_auth_header(cfg):
    if cfg.get("user"):
        import base64
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
            body_bytes = resp.read()
            if not body_bytes:
                return None
            return json.loads(body_bytes)
    except urllib.error.HTTPError as exc:
        body_bytes = exc.read()
        try:
            detail = json.loads(body_bytes)
            msg = detail.get("message", body_bytes.decode("utf-8", "replace"))
        except Exception:
            msg = body_bytes.decode("utf-8", "replace")
        print(f"[ERROR] {method} {url} → HTTP {exc.code}: {msg}", file=sys.stderr)
        sys.exit(1)

# ---------------------------------------------------------------------------
# Page operations
# ---------------------------------------------------------------------------

def find_child_page_by_title(cfg, parent_id, title):
    """Find a direct child page of *parent_id* with the given *title*.

    Uses children API so only pages directly under the parent are searched,
    avoiding collisions with same-title pages elsewhere in the space.
    Returns {'id': ..., 'version': N} or None.
    """
    limit = 50
    start = 0
    while True:
        params = urllib.parse.urlencode({
            "expand": "version",
            "limit": limit,
            "start": start,
        })
        result = confluence_api(
            cfg, "GET",
            f"/rest/api/content/{parent_id}/child/page?{params}"
        )
        if not result or not result.get("results"):
            break
        for page in result["results"]:
            if page["title"] == title:
                return {"id": page["id"], "version": page["version"]["number"]}
        # pagination
        size = result.get("size", 0)
        if size < limit:
            break
        start += limit
    return None


def get_page_info(cfg, page_id):
    """Return page info dict from Confluence."""
    params = urllib.parse.urlencode({"expand": "version,space"})
    return confluence_api(cfg, "GET", f"/rest/api/content/{page_id}?{params}")


def create_page(cfg, space_key, title, parent_id, body_xhtml=""):
    """Create a page under parent_id and return its ID."""
    if not body_xhtml:
        body_xhtml = (
            f"<p>이 페이지는 <strong>{html_escape(title)}</strong>의 하위 문서를 "
            f"모아놓은 상위 페이지입니다.</p>"
            f'<ac:structured-macro ac:name="children">'
            f'<ac:parameter ac:name="sort">title</ac:parameter>'
            f'</ac:structured-macro>'
        )
    payload = {
        "type": "page",
        "title": title,
        "space": {"key": space_key},
        "ancestors": [{"id": str(parent_id)}],
        "body": {
            "storage": {
                "value": body_xhtml,
                "representation": "storage",
            }
        },
    }
    result = confluence_api(cfg, "POST", "/rest/api/content", payload)
    return result["id"]


def ensure_page(cfg, space_key, title, parent_id, dry_run=False):
    """Find (as direct child of parent_id) or create a page with *title*.

    Returns (page_id, action) where action is 'found', 'created', or 'dry-run'.
    Searches only direct children of parent_id to avoid cross-space collision.
    """
    existing = find_child_page_by_title(cfg, parent_id, title)
    if existing:
        return existing["id"], "found"
    if dry_run:
        return None, "dry-run"
    page_id = create_page(cfg, space_key, title, parent_id)
    return page_id, "created"

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Confluence 캠페인 페이지 계층 생성 및 .env CONFLUENCE_PARENT_ID 갱신."
    )
    parser.add_argument(
        "--root-page-id", required=True,
        help="최상위 기준 페이지 ID (예: 722832415).",
    )
    parser.add_argument(
        "--path", required=True,
        help="슬래시 구분 페이지 계층 (예: '2026 playbook 정기진단/OCB').",
    )
    parser.add_argument(
        "--update-env", action="store_true",
        help="최하위 페이지 ID를 .env의 CONFLUENCE_PARENT_ID에 기록.",
    )
    parser.add_argument(
        "--print-id", action="store_true",
        help="최하위 페이지 ID만 stdout에 출력 (스크립트 연동용).",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="API 호출 없이 실행 계획만 표시.",
    )
    parser.add_argument(
        "--base-dir", default=None,
        help="저장소 루트 경로 (기본: 스크립트 기준 ../../).",
    )
    args = parser.parse_args()

    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.abspath(os.path.join(script_dir, "..", ".."))
    base_dir = args.base_dir or repo_root
    env_path = os.path.join(base_dir, ".env")

    load_env(env_path)

    base_url = os.environ.get("CONFLUENCE_BASE_URL", "").rstrip("/")
    space_key = os.environ.get("CONFLUENCE_SPACE_KEY", "")
    token = os.environ.get("CONFLUENCE_TOKEN", "")
    user = os.environ.get("CONFLUENCE_USER", "")

    if not args.dry_run:
        missing = []
        if not base_url:
            missing.append("CONFLUENCE_BASE_URL")
        if not space_key:
            missing.append("CONFLUENCE_SPACE_KEY")
        if not token:
            missing.append("CONFLUENCE_TOKEN")
        if missing:
            print(f"[ERROR] .env에 다음 변수가 없습니다: {', '.join(missing)}", file=sys.stderr)
            sys.exit(1)

    cfg = {
        "base_url": base_url,
        "space_key": space_key,
        "token": token,
        "user": user,
    }

    # Parse hierarchy path
    titles = [t.strip() for t in args.path.split("/") if t.strip()]
    if not titles:
        print("[ERROR] --path가 비어 있습니다.", file=sys.stderr)
        sys.exit(1)

    root_page_id = args.root_page_id

    print(f"{'[DRY-RUN] ' if args.dry_run else ''}Confluence 캠페인 계층 생성")
    print(f"  루트 페이지 ID : {root_page_id}")
    print(f"  Space Key     : {space_key or '(dry-run)' }")
    print(f"  생성 경로      : {' / '.join(titles)}")
    print("-" * 60)

    # Verify root page exists
    if not args.dry_run:
        root_info = get_page_info(cfg, root_page_id)
        if not root_info:
            print(f"[ERROR] 루트 페이지 {root_page_id}를 찾을 수 없습니다.", file=sys.stderr)
            sys.exit(1)
        root_title = root_info.get("title", root_page_id)
        root_space = root_info.get("space", {}).get("key", space_key)
        # Use the space from the root page if not explicitly set
        if not space_key:
            cfg["space_key"] = root_space
            space_key = root_space
        print(f"  루트 페이지    : '{root_title}' (id={root_page_id}, space={root_space})")
    else:
        print(f"  루트 페이지    : id={root_page_id} (dry-run, 미확인)")

    print()

    current_parent_id = root_page_id
    deepest_id = root_page_id

    for i, title in enumerate(titles, 1):
        prefix_str = "  " * (i - 1) + ("└─ " if i > 1 else "")
        if args.dry_run:
            print(f"  {prefix_str}[dry-run] '{title}' (would find-or-create under {current_parent_id})")
            current_parent_id = f"(id of '{title}')"
        else:
            page_id, action = ensure_page(cfg, cfg["space_key"], title, current_parent_id)
            url = f"{base_url}/pages/viewpage.action?pageId={page_id}"
            print(f"  {prefix_str}[{action:8s}] '{title}' → id={page_id}")
            print(f"  {'':12s}  URL: {url}")
            current_parent_id = page_id
            deepest_id = page_id

    print()

    if not args.dry_run:
        print(f"최하위 페이지 ID (CONFLUENCE_PARENT_ID): {deepest_id}")

        if args.update_env:
            update_env_key(env_path, "CONFLUENCE_PARENT_ID", deepest_id)
            print(f"✅  .env CONFLUENCE_PARENT_ID={deepest_id} 갱신 완료")

        if args.print_id:
            # Print only the ID for subprocess consumption
            print(deepest_id)
    else:
        print("[dry-run] 실제 API 호출 없이 종료.")
        print("          실제 생성하려면 --dry-run 없이 다시 실행하세요.")


if __name__ == "__main__":
    main()
