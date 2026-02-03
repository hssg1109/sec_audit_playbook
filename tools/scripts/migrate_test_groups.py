#!/usr/bin/env python3
"""
테스트 그룹을 '테스트 목록' 페이지 아래로 이동하는 마이그레이션 스크립트.

1. 루트 아래에 '테스트 목록' 페이지 생성
2. 'OCB-IAM 간편인증 진단' -> '테스트1 - OCB-IAM 간편인증 진단' 으로 이름 변경 & 이동
3. '테스트2 - SKP PlayBook 취약 게시판 진단' -> '테스트 목록' 아래로 이동

Usage:
    python tools/scripts/migrate_test_groups.py --dry-run
    python tools/scripts/migrate_test_groups.py
"""
import base64
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from html import escape as html_escape


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
            return json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        err_body = exc.read().decode("utf-8", errors="replace")
        print(f"[ERROR] {method} {url} -> {exc.code}", file=sys.stderr)
        print(f"        {err_body[:500]}", file=sys.stderr)
        raise SystemExit(1) from exc


def find_page_by_title(cfg, title):
    params = urllib.parse.urlencode({
        "title": title,
        "spaceKey": cfg["space_key"],
        "expand": "version",
    })
    result = confluence_api(cfg, "GET", f"/rest/api/content?{params}")
    if result and result.get("results"):
        page = result["results"][0]
        return {"id": page["id"], "version": page["version"]["number"]}
    return None


def create_page(cfg, title, body_xhtml, parent_id):
    payload = {
        "type": "page",
        "title": title,
        "space": {"key": cfg["space_key"]},
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


def update_page(cfg, page_id, title, version, parent_id=None):
    """제목 변경 및/또는 부모 페이지 이동 (본문 유지)."""
    payload = {
        "type": "page",
        "title": title,
        "version": {"number": version + 1},
    }
    if parent_id is not None:
        payload["ancestors"] = [{"id": str(parent_id)}]
    confluence_api(cfg, "PUT", f"/rest/api/content/{page_id}", payload)


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="테스트 그룹을 '테스트 목록' 페이지 아래로 마이그레이션")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.abspath(os.path.join(script_dir, "..", ".."))
    load_env(os.path.join(repo_root, ".env"))
    cfg = get_config()
    root_id = cfg["parent_id"]

    # --- Step 1: '테스트 목록' 페이지 생성 (또는 기존 확인) ---
    test_list_title = "테스트 목록"
    print(f"[1/3] '{test_list_title}' 페이지 확인/생성...")

    existing = find_page_by_title(cfg, test_list_title)
    if existing:
        test_list_id = existing["id"]
        print(f"      이미 존재함 (id: {test_list_id})")
    elif args.dry_run:
        test_list_id = "NEW"
        print(f"      (dry-run) 생성 예정 - 부모: {root_id}")
    else:
        body = (
            f"<p>보안 진단 테스트 결과를 모아놓은 페이지입니다.</p>"
            f'<ac:structured-macro ac:name="children">'
            f'<ac:parameter ac:name="sort">title</ac:parameter>'
            f'</ac:structured-macro>'
        )
        test_list_id = create_page(cfg, test_list_title, body, root_id)
        print(f"      생성 완료 (id: {test_list_id})")

    # --- Step 2: 'OCB-IAM 간편인증 진단' -> '테스트1 - OCB-IAM 간편인증 진단' + 이동 ---
    old_name_1 = "OCB-IAM 간편인증 진단"
    new_name_1 = "테스트1 - OCB-IAM 간편인증 진단"
    print(f"\n[2/3] '{old_name_1}' -> '{new_name_1}' (이동: 테스트 목록 아래)")

    page1 = find_page_by_title(cfg, old_name_1)
    if not page1:
        # 이미 이름이 변경되었을 수 있음
        page1 = find_page_by_title(cfg, new_name_1)
        if page1:
            print(f"      이미 이름 변경됨 (id: {page1['id']}), 이동만 수행")
            if not args.dry_run:
                update_page(cfg, page1["id"], new_name_1, page1["version"],
                            parent_id=test_list_id)
                print(f"      이동 완료")
            else:
                print(f"      (dry-run) 이동 예정")
        else:
            print(f"      !! 페이지를 찾을 수 없음: '{old_name_1}' 또는 '{new_name_1}'")
    else:
        if args.dry_run:
            print(f"      (dry-run) id: {page1['id']} 이름 변경 + 이동 예정")
        else:
            update_page(cfg, page1["id"], new_name_1, page1["version"],
                        parent_id=test_list_id)
            print(f"      완료 (id: {page1['id']}, v{page1['version']} -> v{page1['version']+1})")

    # --- Step 3: '테스트2 - SKP PlayBook 취약 게시판 진단' 이동 ---
    name_2 = "테스트2 - SKP PlayBook 취약 게시판 진단"
    print(f"\n[3/3] '{name_2}' -> 테스트 목록 아래로 이동")

    page2 = find_page_by_title(cfg, name_2)
    if not page2:
        print(f"      !! 페이지를 찾을 수 없음: '{name_2}'")
    elif args.dry_run:
        print(f"      (dry-run) id: {page2['id']} 이동 예정")
    else:
        update_page(cfg, page2["id"], name_2, page2["version"],
                    parent_id=test_list_id)
        print(f"      완료 (id: {page2['id']}, v{page2['version']} -> v{page2['version']+1})")

    print("\n마이그레이션 완료.")


if __name__ == "__main__":
    main()
