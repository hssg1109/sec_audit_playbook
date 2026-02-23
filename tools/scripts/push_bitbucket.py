#!/usr/bin/env python3
"""
Bitbucket Push Automation Script
=================================
정책(SCM-2026-001)에 따라 skills/와 tools/만 Bitbucket에 push한다.

사용법:
  # 직접 main push (1인 운영 / 긴급 배포)
  python push_bitbucket.py --token <TOKEN>

  # develop 브랜치로 push + PR 생성 (팀 운영)
  python push_bitbucket.py --token <TOKEN> --pr

  # 커밋 메시지 지정
  python push_bitbucket.py --token <TOKEN> --message "feat: 인젝션 진단 기준 추가"

  # dry-run (push 없이 확인만)
  python push_bitbucket.py --token <TOKEN> --dry-run

환경변수:
  BITBUCKET_TOKEN  - HTTP Access Token (--token 대신 사용 가능)
"""

import argparse
import json
import os
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

# Bitbucket에 포함할 디렉토리/파일
INCLUDE_PATHS = ["skills", "tools"]

# WSL2 환경에서는 powershell.exe를 통해 push (사내망 접근)
USE_POWERSHELL = True


def run(cmd, capture=True, check=True, cwd=None):
    """Run a shell command."""
    result = subprocess.run(
        cmd, shell=True, capture_output=capture, text=True, cwd=cwd
    )
    if check and result.returncode != 0:
        print(f"[ERROR] {cmd}\n{result.stderr}", file=sys.stderr)
        sys.exit(1)
    return result


def get_repo_root():
    """Get the git repository root directory."""
    result = run("git rev-parse --show-toplevel")
    return result.stdout.strip()


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


def create_orphan_commit(repo_root, message):
    """별도 임시 디렉토리에서 orphan 커밋을 생성하여 원본 워크트리를 보호."""
    tmpdir = tempfile.mkdtemp(prefix="bb_push_")
    try:
        # 1. 임시 디렉토리에 bare-style git init
        print("[1/4] 임시 디렉토리에서 orphan 커밋 준비...")
        run("git init", cwd=tmpdir)
        run("git config user.email 'push_bitbucket@automation'", cwd=tmpdir)
        run("git config user.name 'push_bitbucket'", cwd=tmpdir)

        # 2. 대상 파일 복사
        print("[2/4] skills/, tools/ 복사...")
        for path in INCLUDE_PATHS:
            src = os.path.join(repo_root, path)
            dst = os.path.join(tmpdir, path)
            if os.path.isdir(src):
                shutil.copytree(src, dst)
            else:
                print(f"  [WARN] {path} 경로가 존재하지 않습니다.", file=sys.stderr)

        # 3. README.md 생성
        print("[3/4] README.md 생성...")
        readme_content = generate_readme(repo_root)
        with open(os.path.join(tmpdir, "README.md"), "w", encoding="utf-8") as f:
            f.write(readme_content)

        # 4. 커밋
        print("[4/4] 커밋 생성...")
        run("git add -A", cwd=tmpdir)
        run(f'git commit -m "{message}"', cwd=tmpdir)

        result = run("git rev-parse HEAD", cwd=tmpdir)
        commit_hash = result.stdout.strip()
        print(f"  commit: {commit_hash[:8]}")

        return tmpdir, commit_hash
    except Exception:
        shutil.rmtree(tmpdir, ignore_errors=True)
        raise


def push_to_bitbucket(token, tmpdir, remote_branch, force=False):
    """Push to Bitbucket. WSL2에서는 PowerShell 경유."""
    force_flag = "--force" if force else ""

    # remote 설정
    run(f"git remote add origin {REMOTE_HTTP}", cwd=tmpdir, check=False)

    if USE_POWERSHELL:
        # WSL2: tmpdir를 Windows 경로로 변환
        # /tmp/... 는 WSL 내부 경로이므로 \\wsl$\ 경로 사용
        win_tmpdir = tmpdir.replace("/tmp/", "\\\\wsl$\\Ubuntu\\tmp\\")
        cmd = (
            f'powershell.exe -Command "'
            f"cd '{win_tmpdir}'; "
            f"git -c http.extraHeader='Authorization: Bearer {token}' "
            f"push origin HEAD:{remote_branch} {force_flag}"
            f'"'
        )
    else:
        cmd = (
            f"git -c http.extraHeader='Authorization: Bearer {token}' "
            f"push origin HEAD:{remote_branch} {force_flag}"
        )

    print(f"[PUSH] HEAD → {remote_branch} @ {REMOTE_HTTP}")

    # WSL tmpdir는 powershell에서 접근 어려울 수 있으므로 직접 push도 시도
    # 먼저 원본 repo에서 fetch하여 push하는 방식 사용
    repo_root = get_repo_root()

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
    print(f"  README.md : 정책보고서 기반 자동 생성")
    print()


def _walk_files(directory):
    """Walk directory yielding file paths."""
    for root, dirs, files in os.walk(directory):
        # __pycache__ 등 제외
        dirs[:] = [d for d in dirs if d != '__pycache__']
        for f in files:
            yield os.path.join(root, f)


def main():
    parser = argparse.ArgumentParser(
        description="Bitbucket push automation (skills/ + tools/ only)"
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

    # 임시 디렉토리에서 orphan 커밋 생성 (원본 워크트리 보호)
    tmpdir, commit_hash = create_orphan_commit(repo_root, message)

    try:
        if args.pr:
            print("\n== PR 모드 ==")
            ok = push_to_bitbucket(args.token, tmpdir, "develop", force=True)
            if ok:
                create_pull_request(
                    args.token,
                    source_branch="develop",
                    target_branch="main",
                    title=args.pr_title or message,
                )
        else:
            print("\n== Direct Push 모드 ==")
            ok = push_to_bitbucket(args.token, tmpdir, "main", force=True)

        if ok:
            print(f"\n[DONE] Bitbucket push 완료!")
            print(f"  URL: {BITBUCKET_URL}/projects/{PROJECT_KEY}/repos/{REPO_SLUG}/browse")
        else:
            print("\n[FAIL] Push 실패. 네트워크 및 토큰을 확인하세요.", file=sys.stderr)
            sys.exit(1)
    finally:
        # 임시 디렉토리 정리
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    main()
