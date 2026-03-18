#!/usr/bin/env python3
"""
fetch_bitbucket.py — Bitbucket 소스코드 자동 clone/pull (T-09)
=================================================================
지정한 프로젝트/repo를 Bitbucket에서 clone하여 testbed/ 에 배치합니다.
WSL2 환경에서 PowerShell 경유로 사내망에 접근합니다.

디렉토리 명명 규칙:
  testbed/{project}/{slug}@{branch}@{commit7}/
  예) testbed/ocbsugar/ocb-sugar@master@f96d622/

사용법:
  # 프로젝트 전체 clone
  python3 fetch_bitbucket.py --project OCBSUGAR

  # 특정 repo만
  python3 fetch_bitbucket.py --project OCBSUGAR --repo ocb-sugar

  # 복수 프로젝트
  python3 fetch_bitbucket.py --project OCBSUGAR --project OCBCOMM

  # 브랜치 지정
  python3 fetch_bitbucket.py --project OCBSUGAR --branch master

  # 접근 가능한 프로젝트/repo 목록만 출력
  python3 fetch_bitbucket.py --list-projects
  python3 fetch_bitbucket.py --project OCBSUGAR --list-repos

  # dry-run (clone 없이 대상 목록만 출력)
  python3 fetch_bitbucket.py --project OCBSUGAR --dry-run

환경변수 (.env):
  CUSTOMER_BB_TOKEN  — 고객 repo 읽기 전용 HTTP Access Token
  BITBUCKET_URL      — 기본값: http://code.skplanet.com
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

# ── 설정 ────────────────────────────────────────────────────────────────────
BITBUCKET_URL = "http://code.skplanet.com"
TESTBED_DIR = Path(__file__).resolve().parents[2] / "testbed"
STATE_DIR = Path(__file__).resolve().parents[2] / "state"
ENV_FILE = Path(__file__).resolve().parents[2] / ".env"

# WSL2 환경에서 PowerShell 경유 (사내망 접근)
USE_POWERSHELL = True


# ── 인증 ─────────────────────────────────────────────────────────────────────

def load_token() -> str:
    """CUSTOMER_BB_TOKEN을 .env 또는 환경변수에서 로드."""
    # 환경변수 우선
    token = os.environ.get("CUSTOMER_BB_TOKEN", "")
    if token:
        return token
    # .env 파일
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text().splitlines():
            line = line.strip()
            if line.startswith("CUSTOMER_BB_TOKEN="):
                token = line.split("=", 1)[1].strip()
                if token:
                    print(f"[INFO] CUSTOMER_BB_TOKEN을 .env에서 로드했습니다.")
                    return token
    return ""


# ── Bitbucket REST API (PowerShell 경유) ─────────────────────────────────────

def _ps_api_call(url: str, token: str) -> dict | None:
    """PowerShell Invoke-RestMethod로 Bitbucket API 호출. JSON dict 반환."""
    script = (
        "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
        "$headers = @{ 'Authorization' = 'Bearer " + token + "'; 'Accept' = 'application/json' }; "
        "$r = Invoke-RestMethod -Uri '" + url + "' -Headers $headers -Method GET; "
        "$r | ConvertTo-Json -Depth 10"
    )
    result = subprocess.run(
        ["powershell.exe", "-Command", script],
        capture_output=True, text=True, encoding="utf-8", errors="replace"
    )
    if result.returncode != 0 or not result.stdout.strip():
        print(f"  [ERROR] API 호출 실패: {url}")
        if result.stderr:
            print(f"  {result.stderr[:200]}")
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as e:
        print(f"  [ERROR] JSON 파싱 실패: {e}")
        return None


def list_projects(token: str) -> list[dict]:
    """접근 가능한 프로젝트 목록 반환."""
    all_projects = []
    start = 0
    while True:
        url = f"{BITBUCKET_URL}/rest/api/1.0/projects?limit=100&start={start}"
        data = _ps_api_call(url, token)
        if not data:
            break
        values = data.get("values", [])
        all_projects.extend(values)
        if data.get("isLastPage", True):
            break
        start += len(values)
    return all_projects


def list_repos(project_key: str, token: str) -> list[dict]:
    """프로젝트 내 repo 목록 반환. clone URL 포함."""
    all_repos = []
    start = 0
    while True:
        url = f"{BITBUCKET_URL}/rest/api/1.0/projects/{project_key}/repos?limit=100&start={start}"
        data = _ps_api_call(url, token)
        if not data:
            break
        values = data.get("values", [])
        all_repos.extend(values)
        if data.get("isLastPage", True):
            break
        start += len(values)
    return all_repos


def get_repo_info(project_key: str, repo_slug: str, token: str) -> dict | None:
    """특정 repo 정보 반환."""
    url = f"{BITBUCKET_URL}/rest/api/1.0/projects/{project_key}/repos/{repo_slug}"
    return _ps_api_call(url, token)


def get_default_branch(project_key: str, repo_slug: str, token: str) -> str:
    """repo의 기본 브랜치명 반환."""
    url = f"{BITBUCKET_URL}/rest/api/1.0/projects/{project_key}/repos/{repo_slug}/branches/default"
    data = _ps_api_call(url, token)
    if data:
        return data.get("displayId", "master")
    return "master"


def _extract_http_clone_url(repo: dict) -> str:
    """repo 정보에서 credential-free HTTP clone URL 추출."""
    for link in repo.get("links", {}).get("clone", []):
        if link.get("name") == "http":
            href = link["href"]
            # embedded credential 제거 (http://user@host → http://host)
            if "@" in href:
                proto_end = href.index("://") + 3
                at_pos = href.index("@", proto_end)
                href = href[:proto_end] + href[at_pos + 1:]
            return href
    return ""


# ── Git Clone / Pull (PowerShell 경유) ───────────────────────────────────────

def _wsl_to_unc(path: Path) -> str:
    """WSL 경로를 Windows UNC 경로로 변환."""
    return "//wsl.localhost/Ubuntu" + str(path).replace("\\", "/")


def _git_ps(script: str) -> subprocess.CompletedProcess:
    """PowerShell 경유 git 명령 실행."""
    return subprocess.run(
        ["powershell.exe", "-Command", script],
        capture_output=True, text=True, encoding="utf-8", errors="replace"
    )


def clone_repo(clone_url: str, dest: Path, token: str,
               branch: str = "master", depth: int | None = None) -> bool:
    """PowerShell 경유 신규 git clone. dest는 존재하지 않아야 함."""
    unc_dest = _wsl_to_unc(dest)
    git_header = f"http.extraHeader=Authorization: Bearer {token}"
    depth_arg = f"--depth {depth}" if depth else ""
    print(f"  [CLONE] {clone_url}  →  {dest.name}")
    script = (
        f"git -c '{git_header}' clone "
        f"--branch {branch} {depth_arg} "
        f"'{clone_url}' '{unc_dest}' 2>&1"
    )
    result = _git_ps(script)
    if result.returncode != 0:
        if dest.exists() and (dest / ".git").exists():
            return True  # PowerShell이 비정상 코드 반환해도 성공인 경우
        print(f"  [ERROR] clone 실패")
        if result.stderr:
            print(f"  {result.stderr[:300]}")
        return False
    return True


def pull_repo(dest: Path, token: str, branch: str = "master") -> bool:
    """PowerShell 경유 git pull."""
    unc_dest = _wsl_to_unc(dest)
    git_header = f"http.extraHeader=Authorization: Bearer {token}"
    print(f"  [PULL]  {dest.name}  (branch: {branch})")
    script = (
        f"git -c '{git_header}' "
        f"-C '{unc_dest}' pull origin {branch} 2>&1"
    )
    result = _git_ps(script)
    if result.returncode != 0:
        print(f"  [ERROR] pull 실패")
        if result.stderr:
            print(f"  {result.stderr[:300]}")
        return False
    return True


def get_commit_hash(dest: Path) -> str:
    """로컬 repo의 HEAD 커밋 해시(7자) 반환."""
    try:
        result = subprocess.run(
            ["git", "-C", str(dest), "rev-parse", "--short=7", "HEAD"],
            capture_output=True, text=True
        )
        return result.stdout.strip()
    except Exception:
        return "unknown"


def get_branch_name(dest: Path) -> str:
    """로컬 repo의 현재 브랜치명 반환."""
    try:
        result = subprocess.run(
            ["git", "-C", str(dest), "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True, text=True
        )
        return result.stdout.strip() or "unknown"
    except Exception:
        return "unknown"


def get_top_contributors(dest: Path, top_n: int = 5) -> list[str]:
    """커밋 수 기준 상위 기여자 이름 목록 (머지 커밋 제외)."""
    try:
        result = subprocess.run(
            ["git", "-C", str(dest), "log", "--format=%an", "--no-merges"],
            capture_output=True, text=True
        )
        from collections import Counter
        names = [ln.strip() for ln in result.stdout.splitlines() if ln.strip()]
        return [name for name, _ in Counter(names).most_common(top_n)]
    except Exception:
        return []


def write_fetch_meta(dest: Path, branch: str, commit: str,
                     clone_url: str, contributors: list[str]) -> None:
    """진단 도구가 참조할 .fetch_meta.json을 repo 루트에 기록."""
    meta = {
        "branch": branch,
        "commit": commit,
        "clone_url": clone_url,
        "fetched_at": datetime.now().isoformat(),
        "contributors": contributors,
    }
    (dest / ".fetch_meta.json").write_text(
        json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def versioned_dir_name(slug: str, branch: str, commit: str) -> str:
    """디렉토리 명명 규칙: {slug}@{branch}@{commit7}"""
    # 브랜치명에서 '/' 등 파일시스템 비허용 문자 치환
    safe_branch = branch.replace("/", "_").replace("\\", "_")
    return f"{slug}@{safe_branch}@{commit}"


def _find_existing_versioned_dir(parent: Path, slug: str, branch: str) -> Path | None:
    """
    {slug}@{branch}@* 패턴으로 기존 clone 디렉토리 탐색.
    여러 개 존재하면 가장 최근 수정된 것 반환.
    """
    safe_branch = branch.replace("/", "_").replace("\\", "_")
    prefix = f"{slug}@{safe_branch}@"
    candidates = [d for d in parent.iterdir() if d.is_dir() and d.name.startswith(prefix)]
    if not candidates:
        return None
    return max(candidates, key=lambda d: d.stat().st_mtime)


# ── 메인 로직 ────────────────────────────────────────────────────────────────

def fetch_repos(
    project_keys: list[str],
    repo_filter: list[str] | None,
    branch: str | None,
    token: str,
    dry_run: bool = False,
    prefix: str = "",
    shallow: bool = False,
) -> list[dict]:
    """
    지정 프로젝트의 repo들을 testbed/ 로 clone/pull.
    manifest 항목 리스트 반환.
    """
    manifest_entries = []
    TESTBED_DIR.mkdir(exist_ok=True)

    for project_key in project_keys:
        print(f"\n{'='*50}")
        print(f"  Project: {project_key}")
        print(f"{'='*50}")

        repos = list_repos(project_key, token)
        if not repos:
            print(f"  [WARN] {project_key}: 접근 가능한 repo 없음 또는 API 오류")
            continue

        # repo 필터 적용
        if repo_filter:
            repos = [r for r in repos if r["slug"] in repo_filter]
            if not repos:
                print(f"  [WARN] 필터 조건에 맞는 repo 없음: {repo_filter}")
                continue

        for repo in repos:
            slug = repo["slug"]
            clone_url = _extract_http_clone_url(repo)
            if not clone_url:
                print(f"  [SKIP] {slug}: HTTP clone URL 없음")
                continue

            # 브랜치 결정
            target_branch = branch or get_default_branch(project_key, slug, token)

            parent_dir = TESTBED_DIR / project_key.lower()
            parent_dir.mkdir(parents=True, exist_ok=True)

            print(f"\n  Repo: {slug} (branch: {target_branch})")
            print(f"  URL:  {clone_url}")

            if dry_run:
                planned = parent_dir / versioned_dir_name(slug, target_branch, "<commit>")
                print(f"  Dest: {planned}  [DRY-RUN]")
                manifest_entries.append({
                    "project": project_key,
                    "repo": slug,
                    "branch": target_branch,
                    "clone_url": clone_url,
                    "local_path": str(planned),
                    "commit": "dry-run",
                    "status": "dry-run",
                })
                continue

            # 기존 versioned 디렉토리 탐색
            existing = _find_existing_versioned_dir(parent_dir, slug, target_branch)

            if existing:
                # 기존 디렉토리 pull → commit 변경 시 rename
                old_commit = get_commit_hash(existing)
                ok = pull_repo(existing, token, branch=target_branch)
                new_commit = get_commit_hash(existing) if ok else old_commit
                dest = existing
                if ok and new_commit != old_commit:
                    new_dest = parent_dir / versioned_dir_name(slug, target_branch, new_commit)
                    shutil.move(str(existing), str(new_dest))
                    dest = new_dest
                    print(f"  [RENAME] {existing.name} → {new_dest.name}")
                commit = new_commit if ok else "error"
            else:
                # 신규 clone → tmp → rename
                tmp_dest = parent_dir / f"{slug}_fetching"
                if tmp_dest.exists():
                    shutil.rmtree(tmp_dest)
                ok = clone_repo(clone_url, tmp_dest, token,
                                branch=target_branch,
                                depth=1 if shallow else None)
                if ok:
                    commit = get_commit_hash(tmp_dest)
                    dest = parent_dir / versioned_dir_name(slug, target_branch, commit)
                    tmp_dest.rename(dest)
                else:
                    commit = "error"
                    dest = tmp_dest  # 실패 디렉토리 그대로 유지

            status = "ok" if ok else "error"
            print(f"  Dest: {dest}")

            # 기여자 정보 수집 + 메타파일 기록
            contributors: list[str] = []
            if ok:
                contributors = get_top_contributors(dest)
                write_fetch_meta(dest, target_branch, commit, clone_url, contributors)
                if contributors:
                    print(f"  담당자(기여자): {', '.join(contributors)}")

            manifest_entries.append({
                "project": project_key,
                "repo": slug,
                "branch": target_branch,
                "clone_url": clone_url,
                "local_path": str(dest),
                "commit": commit,
                "contributors": contributors,
                "status": status,
                "fetched_at": datetime.now().isoformat(),
            })

            if ok:
                print(f"  ✓ {status} (branch: {target_branch}, commit: {commit})")
            else:
                print(f"  ✗ {status}")

    return manifest_entries


def save_manifest(entries: list[dict], prefix: str) -> Path:
    """state/<prefix>_fetch_manifest.json 저장."""
    STATE_DIR.mkdir(exist_ok=True)
    fname = f"{prefix}_fetch_manifest.json" if prefix else "fetch_manifest.json"
    out = STATE_DIR / fname
    manifest = {
        "generated_at": datetime.now().isoformat(),
        "total": len(entries),
        "ok": sum(1 for e in entries if e.get("status") == "ok"),
        "error": sum(1 for e in entries if e.get("status") == "error"),
        "repos": entries,
    }
    out.write_text(json.dumps(manifest, ensure_ascii=False, indent=2))
    print(f"\n[manifest] {out}")
    return out


# ── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Bitbucket repo 자동 clone → testbed/ 배치 (T-09)"
    )
    parser.add_argument(
        "--project", "-p",
        action="append", dest="projects", metavar="PROJECT_KEY",
        help="Bitbucket 프로젝트 키 (복수 지정 가능, 예: --project OCBSUGAR --project OCBCOMM)",
    )
    parser.add_argument(
        "--repo", "-r",
        action="append", dest="repos", metavar="REPO_SLUG",
        help="특정 repo만 clone (미지정 시 프로젝트 전체)",
    )
    parser.add_argument(
        "--branch", "-b",
        default=None,
        help="clone할 브랜치 (미지정 시 각 repo 기본 브랜치)",
    )
    parser.add_argument(
        "--prefix",
        default="",
        help="manifest 파일명 prefix (예: ocb_q1)",
    )
    parser.add_argument(
        "--shallow",
        action="store_true",
        help="--depth 1 shallow clone (빠른 다운로드)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="clone 없이 대상 목록만 출력",
    )
    parser.add_argument(
        "--list-projects",
        action="store_true",
        help="접근 가능한 프로젝트 목록 출력 후 종료",
    )
    parser.add_argument(
        "--list-repos",
        action="store_true",
        help="지정 프로젝트의 repo 목록 출력 후 종료",
    )
    parser.add_argument(
        "--token",
        default=None,
        help="HTTP Access Token (미지정 시 .env의 CUSTOMER_BB_TOKEN 사용)",
    )
    args = parser.parse_args()

    # 토큰 로드
    token = args.token or load_token()
    if not token:
        print("[ERROR] CUSTOMER_BB_TOKEN이 설정되지 않았습니다.")
        print("  .env에 CUSTOMER_BB_TOKEN=<토큰> 을 추가하거나 --token 옵션을 사용하세요.")
        sys.exit(1)

    # --list-projects
    if args.list_projects:
        print("접근 가능한 Bitbucket 프로젝트:")
        projects = list_projects(token)
        if not projects:
            print("  (없음 또는 API 오류)")
        for p in projects:
            print(f"  {p['key']:20s}  {p['name']}")
        return

    if not args.projects:
        parser.error("--project 를 하나 이상 지정하세요. (예: --project OCBSUGAR)")

    # --list-repos
    if args.list_repos:
        for proj in args.projects:
            print(f"\nProject: {proj}")
            repos = list_repos(proj, token)
            if not repos:
                print("  (없음 또는 API 오류)")
                continue
            for r in repos:
                url = _extract_http_clone_url(r)
                print(f"  {r['slug']:40s}  {url}")
        return

    # clone/pull 실행
    entries = fetch_repos(
        project_keys=args.projects,
        repo_filter=args.repos,
        branch=args.branch,
        token=token,
        dry_run=args.dry_run,
        prefix=args.prefix,
        shallow=args.shallow,
    )

    if entries:
        manifest_path = save_manifest(entries, args.prefix)
        ok = sum(1 for e in entries if e.get("status") == "ok")
        err = sum(1 for e in entries if e.get("status") == "error")
        dry = sum(1 for e in entries if e.get("status") == "dry-run")
        print(f"\n완료: 성공 {ok}개 / 실패 {err}개" + (f" / dry-run {dry}개" if dry else ""))
        if err:
            sys.exit(1)
    else:
        print("\n처리된 repo 없음.")


if __name__ == "__main__":
    main()
