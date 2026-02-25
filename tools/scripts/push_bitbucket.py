#!/usr/bin/env python3
"""
Bitbucket Push Automation Script
=================================
정책(SCM-2026-001)에 따라 skills/와 tools/만 Bitbucket에 push한다.
매 push마다 이전 커밋 위에 증분 커밋을 쌓아 히스토리를 보존한다.

사용법:
  # 직접 main push (1인 운영 / 긴급 배포)
  python push_bitbucket.py --token <TOKEN>

  # develop 브랜치로 push + PR 생성 (팀 운영)
  python push_bitbucket.py --token <TOKEN> --pr

  # 커밋 메시지 지정
  python push_bitbucket.py --token <TOKEN> --message "feat: 인젝션 진단 기준 추가"

  # dry-run (push 없이 확인만)
  python push_bitbucket.py --token <TOKEN> --dry-run

  # 히스토리 초기화 후 재시작 (force push)
  python push_bitbucket.py --token <TOKEN> --reset-history

환경변수:
  BITBUCKET_TOKEN  - HTTP Access Token (--token 대신 사용 가능)



사용법 (tag 포함):
  # push 후 v4.5.2 태그 생성 (RELEASENOTE.md에서 릴리즈 노트 자동 추출)
  python push_bitbucket.py --token <TOKEN> --tag v4.5.2

  # 릴리즈 노트 직접 지정
  python push_bitbucket.py --token <TOKEN> --tag v4.5.2 --release-notes "버그 수정"
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import urllib.error
from datetime import datetime

# ── 설정 ────────────────────────────────────────────────
BITBUCKET_URL = "http://code.skplanet.com"
PROJECT_KEY = "VULCHK"
REPO_SLUG = "audit_result"
REMOTE_NAME = "bitbucket"
REMOTE_HTTP = f"{BITBUCKET_URL}/scm/{PROJECT_KEY}/{REPO_SLUG}.git"
API_BASE = f"{BITBUCKET_URL}/rest/api/1.0/projects/{PROJECT_KEY}/repos/{REPO_SLUG}"

# Bitbucket에 포함할 디렉토리
INCLUDE_PATHS = ["skills", "tools"]

# Bitbucket에 포함할 루트 단일 파일
INCLUDE_FILES = ["RELEASENOTE.md", "TODO.md"]

# WSL2 환경에서는 powershell.exe를 통해 push (사내망 접근)
USE_POWERSHELL = True

# 로컬 repo에 이전 Bitbucket 커밋을 기억하는 ref (히스토리 보존용)
BB_HISTORY_REF = "refs/bb-push/main"


def run(cmd, capture=True, check=True, cwd=None, shell=True):
    """Run a shell command. cmd이 list이면 shell=False로 직접 실행."""
    result = subprocess.run(
        cmd, shell=shell, capture_output=capture, text=True,
        encoding="utf-8", errors="replace", cwd=cwd
    )
    if check and result.returncode != 0:
        print(f"[ERROR] {cmd}\n{result.stderr}", file=sys.stderr)
        sys.exit(1)
    return result


def get_repo_root():
    """Get the git repository root directory."""
    result = run("git rev-parse --show-toplevel")
    return result.stdout.strip()


def parse_release_notes(repo_root, version):
    """RELEASENOTE.md에서 특정 버전의 릴리즈 노트 섹션을 추출.

    ## [v4.5.2] - 2026-02-25 형식의 헤더를 찾아 다음 ## 헤더 전까지 반환.
    버전을 찾지 못하면 빈 문자열 반환.
    """
    note_path = os.path.join(repo_root, "RELEASENOTE.md")
    if not os.path.isfile(note_path):
        return ""
    with open(note_path, encoding="utf-8") as f:
        content = f.read()
    # ## [v4.5.2] 또는 ## [4.5.2] 형식 모두 허용
    ver_escaped = re.escape(version.lstrip("v"))
    pattern = rf"## \[v?{ver_escaped}\][^\n]*\n(.*?)(?=\n## \[|\Z)"
    m = re.search(pattern, content, re.DOTALL)
    return m.group(1).strip() if m else ""


def create_bitbucket_tag(token, tag_name, commit_hash, release_notes):
    """Bitbucket Server REST API로 annotated tag 생성.

    json.dumps() 기본값(ensure_ascii=True)으로 모든 비-ASCII를 \\uXXXX 이스케이프하여
    PowerShell 인코딩 문제 없이 인라인 전달 (create_pull_request 와 동일 패턴).
    """
    tag_message = f"Release {tag_name}\n\n{release_notes}" if release_notes \
        else f"Release {tag_name}"

    tag_data = {
        "name": tag_name,
        "startPoint": commit_hash,
        "message": tag_message,
        "type": "ANNOTATED",
    }
    url = f"{API_BASE}/tags"
    # 단따옴표 이스케이프 (PowerShell 인라인 문자열 안전)
    body_str = json.dumps(tag_data).replace("'", "''")

    if USE_POWERSHELL:
        # shell=False + list 방식: 백틱/달러 등 특수문자가 sh에서 해석되지 않도록
        ps_cmd = (
            f"Invoke-RestMethod -Uri '{url}' "
            f"-Method POST "
            f"-ContentType 'application/json' "
            f"-Headers @{{'Authorization'='Bearer {token}'}} "
            f"-Body '{body_str}'"
        )
        result = run(['powershell.exe', '-Command', ps_cmd], shell=False, check=False)
        if result.returncode == 0:
            print(f"  [TAG] {tag_name} 생성 완료")
            return True
        else:
            print(f"  [ERROR] Tag 생성 실패:\n{result.stderr}", file=sys.stderr)
            return False
    else:
        data = json.dumps(tag_data, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(
            url, data=data, method="POST",
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "Authorization": f"Bearer {token}",
            },
        )
        try:
            resp = urllib.request.urlopen(req, timeout=15)
            tag_result = json.loads(resp.read())
            print(f"  [TAG] {tag_name} 생성 완료: "
                  f"{tag_result.get('displayId', tag_name)}")
            return True
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace") if e.fp else ""
            print(f"  [ERROR] Tag 생성 실패 ({e.code}): {body}", file=sys.stderr)
            return False


def generate_readme(repo_root):
    """Generate Bitbucket README.md from policy report or template."""
    source = os.path.join(repo_root, "docs", "정책보고서.md")
    if os.path.exists(source):
        with open(source, "r", encoding="utf-8") as f:
            content = f.read()
        header = (
            "# AI-SEC-OPS Playbook — Team Shared Assets\n\n"
            "> 이 저장소는 보안진단 자동화 프로젝트의 **팀 공유 자산**(skills/, tools/)을 관리합니다.\n"
            "> 전체 프로젝트 워크스페이스는 별도 GitHub 저장소에서 관리됩니다.\n\n"
            "---\n\n"
        )
        return header + content
    else:
        return (
            "# AI-SEC-OPS Playbook — Team Shared Assets\n\n"
            "- `skills/` — 진단 기준, 정책, 스키마, 프롬프트, 탐지 룰\n"
            "- `tools/` — 실행 스크립트, 자동화 도구\n"
        )


def create_incremental_commit(repo_root, message):
    """이전 Bitbucket 커밋 위에 증분 커밋을 생성.

    BB_HISTORY_REF 가 존재하면 그 커밋을 부모로 삼아 새 커밋을 쌓는다.
    존재하지 않으면(첫 push 또는 --reset-history) orphan 커밋으로 시작한다.

    Returns:
        (tmpdir, commit_hash)  — 변경사항 없으면 commit_hash=None
    """
    tmpdir = tempfile.mkdtemp(prefix="bb_push_")
    try:
        # 이전 history ref 확인
        result = run(f"git rev-parse {BB_HISTORY_REF}", cwd=repo_root, check=False)
        has_history = result.returncode == 0
        prev_hash = result.stdout.strip() if has_history else None

        print(f"[1/4] {'이전 커밋 이어받기' if has_history else 'orphan 커밋 준비 (첫 push)'} ...")
        run("git init", cwd=tmpdir)
        run("git config user.email 'push_bitbucket@automation'", cwd=tmpdir)
        run("git config user.name 'push_bitbucket'", cwd=tmpdir)

        if has_history:
            # 이전 커밋을 tmpdir 로 가져와 체크아웃
            run(
                f"git fetch {repo_root} {BB_HISTORY_REF}:refs/heads/main",
                cwd=tmpdir,
            )
            run("git checkout main", cwd=tmpdir)

        # 2. 대상 파일 복사 (기존 내용 교체)
        print("[2/4] skills/, tools/ 및 루트 문서 복사...")
        for path in INCLUDE_PATHS:
            dst = os.path.join(tmpdir, path)
            if os.path.exists(dst):
                shutil.rmtree(dst)
            src = os.path.join(repo_root, path)
            if os.path.isdir(src):
                shutil.copytree(src, dst)
            else:
                print(f"  [WARN] {path} 경로가 존재하지 않습니다.", file=sys.stderr)

        for fname in INCLUDE_FILES:
            src = os.path.join(repo_root, fname)
            if os.path.isfile(src):
                shutil.copy2(src, os.path.join(tmpdir, fname))
            else:
                print(f"  [WARN] {fname} 파일이 존재하지 않습니다.", file=sys.stderr)

        # 3. README.md 생성
        print("[3/4] README.md 생성...")
        readme_content = generate_readme(repo_root)
        with open(os.path.join(tmpdir, "README.md"), "w", encoding="utf-8") as f:
            f.write(readme_content)

        # 4. 변경 여부 확인 후 커밋
        print("[4/4] 커밋 생성...")
        run("git add -A", cwd=tmpdir)
        status = run("git status --porcelain", cwd=tmpdir)
        if not status.stdout.strip():
            print("  [SKIP] 변경사항 없음 — 커밋 생략")
            return tmpdir, None

        run(f'git commit -m "{message}"', cwd=tmpdir)
        result = run("git rev-parse HEAD", cwd=tmpdir)
        commit_hash = result.stdout.strip()
        parent_info = f"parent: {prev_hash[:8]}" if prev_hash else "orphan"
        print(f"  commit: {commit_hash[:8]} ({parent_info})")

        return tmpdir, commit_hash
    except Exception:
        shutil.rmtree(tmpdir, ignore_errors=True)
        raise


def push_to_bitbucket(token, tmpdir, remote_branch, force=False):
    """Push to Bitbucket. WSL2에서는 PowerShell 경유.

    성공 시 BB_HISTORY_REF 를 새 커밋 해시로 업데이트한다.
    """
    force_flag = "--force" if force else ""
    repo_root = get_repo_root()

    print(f"[PUSH] HEAD → {remote_branch} @ {REMOTE_HTTP}")

    # 임시 디렉토리의 커밋을 원본 repo로 fetch
    run(f"git fetch {tmpdir} HEAD:refs/heads/__bb_push_ref__", cwd=repo_root)

    if USE_POWERSHELL:
        repo_root_win = repo_root.replace("/mnt/g", "G:")
        cmd = (
            f'powershell.exe -Command "'
            f"cd '{repo_root_win}'; "
            f"git -c http.extraHeader='Authorization: Bearer {token}' "
            f"push {REMOTE_NAME} __bb_push_ref__:{remote_branch} {force_flag}"
            f'"'
        )
    else:
        cmd = (
            f"git -c http.extraHeader='Authorization: Bearer {token}' "
            f"push {REMOTE_NAME} __bb_push_ref__:{remote_branch} {force_flag}"
        )

    result = run(cmd, check=False, cwd=repo_root)

    # 성공 시 BB_HISTORY_REF 업데이트 (다음 push 때 부모로 사용)
    if result.returncode == 0:
        pushed_hash = run(
            "git rev-parse refs/heads/__bb_push_ref__", cwd=repo_root
        ).stdout.strip()
        run(f"git update-ref {BB_HISTORY_REF} {pushed_hash}", cwd=repo_root)
        print(f"  history ref 갱신: {BB_HISTORY_REF} → {pushed_hash[:8]}")

    # 임시 ref 정리
    run("git update-ref -d refs/heads/__bb_push_ref__", cwd=repo_root, check=False)

    if result.returncode != 0:
        print(f"[ERROR] Push 실패:\n{result.stderr}", file=sys.stderr)
        return False

    print(result.stderr)
    return True


def create_pull_request(token, source_branch, target_branch="main", title=None, description=None):
    """Bitbucket Server REST API를 통해 PR 생성."""
    if title is None:
        title = f"[자동] skills/tools 업데이트 ({datetime.now().strftime('%Y-%m-%d')})"
    if description is None:
        description = (
            "## 변경 사항\n"
            "- skills/ 또는 tools/ 디렉토리 업데이트\n\n"
            "## 확인 사항\n"
            "- [ ] skills 진단 기준 변경 시 tools 스크립트도 동기화되었는가?\n"
            "- [ ] Self-Contained 원칙이 유지되는가?\n"
        )

    pr_data = {
        "title": title,
        "description": description,
        "fromRef": {
            "id": f"refs/heads/{source_branch}",
            "repository": {
                "slug": REPO_SLUG,
                "project": {"key": PROJECT_KEY}
            }
        },
        "toRef": {
            "id": f"refs/heads/{target_branch}",
            "repository": {
                "slug": REPO_SLUG,
                "project": {"key": PROJECT_KEY}
            }
        }
    }

    url = f"{API_BASE}/pull-requests"

    if USE_POWERSHELL:
        cmd = (
            f'powershell.exe -Command "'
            f"Invoke-RestMethod -Uri '{url}' "
            f"-Method POST "
            f"-ContentType 'application/json' "
            f"-Headers @{{'Authorization'='Bearer {token}'}} "
            f"-Body '{json.dumps(pr_data)}'"
            f'"'
        )
        result = run(cmd, check=False)
        if result.returncode == 0:
            print(f"[PR] 생성 완료")
            print(result.stdout)
            return True
        else:
            print(f"[ERROR] PR 생성 실패:\n{result.stderr}", file=sys.stderr)
            return False
    else:
        data = json.dumps(pr_data).encode("utf-8")
        req = urllib.request.Request(
            url, data=data, method="POST",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {token}",
            }
        )
        try:
            resp = urllib.request.urlopen(req, timeout=15)
            pr_result = json.loads(resp.read())
            pr_url = pr_result.get("links", {}).get("self", [{}])[0].get("href", "")
            print(f"[PR] 생성 완료: {pr_url}")
            return True
        except urllib.error.HTTPError as e:
            body = e.read().decode() if e.fp else ""
            print(f"[ERROR] PR 생성 실패 ({e.code}): {body}", file=sys.stderr)
            return False


def show_diff_summary(repo_root):
    """Push할 파일 목록 요약 출력."""
    print("\n== Bitbucket Push 대상 ==")
    for path in INCLUDE_PATHS:
        full = os.path.join(repo_root, path)
        if os.path.isdir(full):
            count = sum(1 for _ in _walk_files(full))
            print(f"  {path}/ : {count} files")
        else:
            print(f"  {path}/ : [NOT FOUND]")
    for fname in INCLUDE_FILES:
        full = os.path.join(repo_root, fname)
        status = "OK" if os.path.isfile(full) else "NOT FOUND"
        print(f"  {fname} : {status}")
    print(f"  README.md : 정책보고서 기반 자동 생성")

    # 이전 히스토리 ref 상태 표시
    repo_root_abs = get_repo_root()
    result = run(f"git rev-parse {BB_HISTORY_REF}", cwd=repo_root_abs, check=False)
    if result.returncode == 0:
        print(f"  이전 push: {result.stdout.strip()[:8]} ({BB_HISTORY_REF})")
    else:
        print(f"  이전 push: 없음 (첫 push — orphan 커밋)")
    print()


def _walk_files(directory):
    """Walk directory yielding file paths."""
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d != '__pycache__']
        for f in files:
            yield os.path.join(root, f)


def main():
    parser = argparse.ArgumentParser(
        description="Bitbucket push automation (skills/ + tools/ only, incremental commits)"
    )
    parser.add_argument(
        "--token", "-t",
        default=os.environ.get("BITBUCKET_TOKEN"),
        help="Bitbucket HTTP Access Token (or set BITBUCKET_TOKEN env)"
    )
    parser.add_argument(
        "--pr", action="store_true",
        help="develop 브랜치로 push 후 PR 생성 (기본: main 직접 push)"
    )
    parser.add_argument(
        "--message", "-m",
        default=None,
        help="커밋 메시지 (기본: 자동 생성)"
    )
    parser.add_argument(
        "--pr-title",
        default=None,
        help="PR 제목 (--pr 사용 시)"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Push 없이 대상 파일만 확인"
    )
    parser.add_argument(
        "--no-powershell", action="store_true",
        help="PowerShell 우회 비활성화 (비-WSL2 환경)"
    )
    parser.add_argument(
        "--reset-history", action="store_true",
        help="로컬 히스토리 ref 초기화 후 orphan 커밋으로 재시작 (force push)"
    )
    parser.add_argument(
        "--tag", "-T",
        default=None,
        metavar="VERSION",
        help="push 후 Bitbucket annotated tag 생성 (예: v4.5.2). "
             "RELEASENOTE.md에서 해당 버전 릴리즈 노트를 자동 추출."
    )
    parser.add_argument(
        "--release-notes",
        default=None,
        metavar="TEXT",
        help="tag 릴리즈 노트 직접 지정 (기본: RELEASENOTE.md 자동 추출)"
    )
    args = parser.parse_args()

    if not args.token:
        print("[ERROR] --token 또는 BITBUCKET_TOKEN 환경변수가 필요합니다.", file=sys.stderr)
        sys.exit(1)

    global USE_POWERSHELL
    if args.no_powershell:
        USE_POWERSHELL = False

    repo_root = get_repo_root()

    # remote 확인/추가
    result = run("git remote -v", cwd=repo_root, check=False)
    if REMOTE_NAME not in result.stdout:
        run(f"git remote add {REMOTE_NAME} {REMOTE_HTTP}", cwd=repo_root)

    # --reset-history: 이전 히스토리 ref 삭제 → orphan으로 재시작
    if args.reset_history:
        run(f"git update-ref -d {BB_HISTORY_REF}", cwd=repo_root, check=False)
        print(f"[RESET] {BB_HISTORY_REF} 삭제 — orphan 커밋으로 재시작합니다.")

    # 대상 파일 확인
    show_diff_summary(repo_root)

    if args.dry_run:
        print("[DRY-RUN] 완료. 실제 push는 수행하지 않습니다.")
        return

    # 커밋 메시지
    if args.message:
        message = args.message
    else:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
        message = f"update: skills/tools 동기화 ({timestamp})"

    # 증분 커밋 생성
    tmpdir, commit_hash = create_incremental_commit(repo_root, message)

    try:
        if commit_hash is None:
            print("\n[INFO] 변경사항 없음 — push를 건너뜁니다.")
            return

        force = args.reset_history  # reset 시에만 force push

        if args.pr:
            print("\n== PR 모드 ==")
            ok = push_to_bitbucket(args.token, tmpdir, "develop", force=force)
            if ok:
                create_pull_request(
                    args.token,
                    source_branch="develop",
                    target_branch="main",
                    title=args.pr_title or message,
                )
        else:
            print("\n== Direct Push 모드 ==")
            ok = push_to_bitbucket(args.token, tmpdir, "main", force=force)

        if ok:
            print(f"\n[DONE] Bitbucket push 완료!")
            print(f"  URL: {BITBUCKET_URL}/projects/{PROJECT_KEY}/repos/{REPO_SLUG}/browse")

            # --tag: push 성공 후 annotated tag 생성
            if args.tag:
                pushed_hash = run(
                    f"git rev-parse {BB_HISTORY_REF}", cwd=repo_root
                ).stdout.strip()
                notes = args.release_notes or parse_release_notes(repo_root, args.tag)
                if not notes:
                    print(f"  [WARN] RELEASENOTE.md에서 {args.tag} 섹션을 찾지 못했습니다. "
                          f"tag 메시지 없이 생성합니다.", file=sys.stderr)
                print(f"\n== Tag 생성: {args.tag} ==")
                create_bitbucket_tag(args.token, args.tag, pushed_hash, notes)
                print(f"  Tags: {BITBUCKET_URL}/projects/{PROJECT_KEY}"
                      f"/repos/{REPO_SLUG}/tags")
        else:
            print("\n[FAIL] Push 실패. 네트워크 및 토큰을 확인하세요.", file=sys.stderr)
            sys.exit(1)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    main()
