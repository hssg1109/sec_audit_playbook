#!/usr/bin/env python3
"""
Fortify SSC High/Critical Findings Fetcher

SSC에서 특정 프로젝트 버전의 High/Critical 취약점을 수집합니다.

사용법:
    python3 fetch_ssc.py --project "프로젝트명" [--version "버전명"] -o state/<prefix>_ssc_findings.json
    python3 fetch_ssc.py --list-projects       # 접근 가능한 프로젝트 목록
    python3 fetch_ssc.py --version-id 12345    # 버전 ID 직접 지정

인증 (.env):
    SSC_BASE_URL=https://ssc.skplanet.com/ssc
    SSC_TOKEN=<CIToken>              # 우선 사용
    SSC_USERNAME=<AD계정>             # fallback
    SSC_PASSWORD=<AD비밀번호>

토큰 발급:
    - 웹 UI: {SSC_BASE_URL}/html/ssc/profile → Token Management
    - API: python3 fetch_ssc.py --generate-token
"""

import argparse
import json
import os
import sys
import time
import urllib.request
import urllib.error
import urllib.parse
import base64
import ssl
from pathlib import Path
from datetime import datetime

# ─────────────────────────────────────────────
# SSC API 클라이언트
# ─────────────────────────────────────────────

class SSCClient:
    # Fortify 우선순위 (friority) 레벨
    HIGH_CRITICAL = {"Critical", "High"}

    # friority → severity 점수 매핑 (표시용)
    FRIORITY_SEVERITY = {
        "Critical": "Critical",
        "High":     "High",
        "Medium":   "Medium",
        "Low":      "Low",
    }

    def __init__(self, base_url: str, token: str | None = None,
                 username: str | None = None, password: str | None = None,
                 env_path: Path | None = None):
        self.base_url = base_url.rstrip("/")
        self.api_base = f"{self.base_url}/api/v1"
        self.token = token
        self.username = username
        self.password = password
        self.env_path = env_path  # .env 갱신용
        # SSL 인증서 검증 우회 (사내 인증서)
        self._ssl_ctx = ssl.create_default_context()
        self._ssl_ctx.check_hostname = False
        self._ssl_ctx.verify_mode = ssl.CERT_NONE

        if not self.token and username and password:
            self.token = self._obtain_token(save_to_env=True)

    def _obtain_token(self, save_to_env: bool = True) -> str:
        """username/password → UnifiedLoginToken 발급 후 .env 갱신"""
        print("[SSC] UnifiedLoginToken 발급 중...", file=sys.stderr)
        creds = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
        payload = json.dumps({
            "type": "UnifiedLoginToken",
            "description": "playbook-sec-audit"
        }).encode()
        req = urllib.request.Request(
            f"{self.api_base}/tokens",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Basic {creds}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, context=self._ssl_ctx) as resp:
                data = json.loads(resp.read())
                token = data["data"]["token"]
                expires = data["data"].get("terminalDate", "unknown")
                print(f"[SSC] 토큰 발급 완료 (만료: {expires})", file=sys.stderr)
                if save_to_env and self.env_path:
                    _update_env_token(self.env_path, token)
                return token
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace")
            raise RuntimeError(f"SSC 토큰 발급 실패 [{e.code}]: {body}") from e

    def _refresh_token(self):
        """토큰 만료 시 자동 재발급 (username/password 필수)"""
        if not (self.username and self.password):
            raise RuntimeError(
                "SSC 토큰 만료. .env에 SSC_USERNAME / SSC_PASSWORD를 추가하면 자동 재발급됩니다."
            )
        print("[SSC] 토큰 만료 감지 → 자동 재발급...", file=sys.stderr)
        self.token = self._obtain_token(save_to_env=True)

    def _get(self, path: str, params: dict | None = None, _retry: bool = True) -> dict:
        """GET 요청. 401/403 시 토큰 재발급 후 1회 재시도."""
        url = f"{self.api_base}{path}"
        if params:
            url += "?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(
            url,
            headers={"Authorization": f"FortifyToken {self.token}"},
        )
        try:
            with urllib.request.urlopen(req, context=self._ssl_ctx) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            if e.code in (401, 403) and _retry:
                self._refresh_token()
                return self._get(path, params, _retry=False)
            body = e.read().decode(errors="replace")
            raise RuntimeError(f"SSC API 오류 [{e.code}] {path}: {body}") from e

    def _get_paged(self, path: str, params: dict | None = None,
                   page_size: int = 200) -> list:
        """페이지네이션 처리 전체 수집"""
        params = dict(params or {})
        params["limit"] = page_size
        params["start"] = 0
        results = []
        while True:
            data = self._get(path, params)
            items = data.get("data", [])
            results.extend(items)
            total = data.get("count", len(items))
            params["start"] += len(items)
            if params["start"] >= total or not items:
                break
            time.sleep(0.2)
        return results

    # ── 프로젝트/버전 탐색 ──────────────────────────

    def list_projects(self, limit: int = 200) -> list:
        """접근 가능한 프로젝트 목록"""
        return self._get_paged("/projects", {"limit": limit})

    def find_project_versions(self, project_name: str,
                               version_name: str | None = None) -> list:
        """프로젝트명으로 버전 목록 검색"""
        q = f'project.name:"{project_name}"'
        if version_name:
            q += f'+name:"{version_name}"'
        return self._get_paged("/projectVersions", {"q": q})

    def get_project_version(self, version_id: int) -> dict:
        """버전 ID로 상세 정보 조회"""
        return self._get(f"/projectVersions/{version_id}")["data"]

    def get_filter_sets(self, version_id: int) -> list:
        """필터셋 목록 (기본 필터셋 ID 획득용)"""
        return self._get(f"/projectVersions/{version_id}/filterSets")["data"]

    # ── 이슈 수집 ────────────────────────────────────

    def get_issues(self, version_id: int,
                   filterset_id: str | None = None) -> list:
        """
        버전의 전체 이슈 수집 (페이지네이션).
        fields: LLM 검증에 필요한 핵심 필드만 요청.
        """
        params: dict = {
            "fields": (
                "issueInstanceId,issueName,severity,kingdom,likelihood,"
                "impact,primaryLocation,fullFileName,lineNumber,analyzer,"
                "friority,enginePriority,displayEngineType,issueStatus,"
                "reviewed,suppressed,hidden,audited,hasComments,"
                "scanStatus,foundDate,confidence"
            ),
        }
        if filterset_id:
            params["filterset"] = filterset_id
        return self._get_paged(f"/projectVersions/{version_id}/issues", params)

    def get_issue_detail(self, version_id: int, issue_id: str) -> dict:
        """단건 이슈 상세 (trace 포함)"""
        return self._get(f"/projectVersions/{version_id}/issues/{issue_id}")["data"]

    def get_issue_summary(self, version_id: int,
                           filterset_id: str | None = None) -> list:
        """카테고리별 이슈 요약 통계"""
        params: dict = {"groupingtype": "friority"}
        if filterset_id:
            params["filterSet"] = filterset_id
        return self._get(f"/projectVersions/{version_id}/issueSummaries", params)["data"]

    def get_artifacts(self, version_id: int) -> list:
        """스캔 아티팩트 목록 (스캔 날짜·커밋 메타데이터 확인용)"""
        return self._get_paged(
            f"/projectVersions/{version_id}/artifacts",
            {"embed": "scans"},
        )


# ─────────────────────────────────────────────
# 유틸
# ─────────────────────────────────────────────

ENV_PATH = Path(__file__).parent.parent.parent / ".env"


def load_env() -> dict:
    """프로젝트 루트 .env 로드"""
    env: dict = {}
    if ENV_PATH.exists():
        for line in ENV_PATH.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                env[k.strip()] = v.strip().strip('"').strip("'")
    # OS 환경변수 우선
    for key in ("SSC_BASE_URL", "SSC_TOKEN", "SSC_USERNAME", "SSC_PASSWORD"):
        if key in os.environ:
            env[key] = os.environ[key]
    return env


def _update_env_token(env_path: Path, new_token: str):
    """SSC_TOKEN 값을 .env에서 갱신 (없으면 추가)"""
    if not env_path.exists():
        env_path.write_text(f"SSC_TOKEN={new_token}\n", encoding="utf-8")
        print(f"[SSC] .env 생성 후 토큰 저장 완료", file=sys.stderr)
        return
    lines = env_path.read_text(encoding="utf-8").splitlines(keepends=True)
    updated = False
    new_lines = []
    for line in lines:
        if line.startswith("SSC_TOKEN="):
            new_lines.append(f"SSC_TOKEN={new_token}\n")
            updated = True
        else:
            new_lines.append(line)
    if not updated:
        new_lines.append(f"SSC_TOKEN={new_token}\n")
    env_path.write_text("".join(new_lines), encoding="utf-8")
    print(f"[SSC] .env SSC_TOKEN 갱신 완료", file=sys.stderr)


def parse_testbed_path(testbed_path: str) -> dict:
    """
    testbed 경로에서 repo · branch · commit 추출.
    네이밍 규칙: <repo>@<branch>@<short-commit>
    예: testbed/ocbwebview/ocb-webview-api@master@886aad0
    """
    dirname = Path(testbed_path).resolve().name
    parts = dirname.split("@")
    if len(parts) >= 3:
        return {"repo": parts[0], "branch": parts[1], "commit": parts[2]}
    if len(parts) == 2:
        return {"repo": parts[0], "branch": parts[1], "commit": None}
    return {"repo": dirname, "branch": None, "commit": None}


def extract_scan_commit(artifacts: list) -> str | None:
    """
    아티팩트 목록에서 가장 최근 스캔의 커밋 해시 추출.
    SSC FPR 아티팩트는 'scans' embed에 commitId / buildId / sourceVersion 등을 노출하기도 함.
    """
    for art in artifacts:
        scans = art.get("_embed", {}).get("scans", []) or art.get("scans", [])
        for scan in scans:
            for key in ("commitId", "buildId", "sourceVersion", "revision"):
                val = scan.get(key)
                if val and isinstance(val, str) and len(val) >= 7:
                    return val.strip()
    return None


def compare_branch_commit(
    ssc_version_name: str,
    ssc_commit: str | None,
    testbed_branch: str | None,
    testbed_commit: str | None,
) -> dict:
    """
    SSC 스캔 대상과 testbed 소스코드의 브랜치·커밋 일치 여부 판정.

    반환:
        status: "MATCH" | "MISMATCH" | "PARTIAL" | "UNKNOWN"
        detail: 판정 근거 문자열
    """
    def norm(s: str) -> str:
        return (s or "").lower().replace("-", "_").replace("/", "_")

    result = {
        "ssc_version_name":  ssc_version_name,
        "ssc_commit":        ssc_commit,
        "testbed_branch":    testbed_branch,
        "testbed_commit":    testbed_commit,
        "status":            "UNKNOWN",
        "detail":            "",
        "stale_risk":        "알 수 없음",
    }

    # 커밋 해시 비교 (가장 신뢰도 높음)
    if ssc_commit and testbed_commit:
        ssc_c = norm(ssc_commit)
        tb_c  = norm(testbed_commit)
        if ssc_c.startswith(tb_c) or tb_c.startswith(ssc_c):
            result.update({"status": "MATCH",
                           "detail": f"커밋 해시 일치: SSC={ssc_commit}, testbed={testbed_commit}",
                           "stale_risk": "낮음"})
        else:
            result.update({"status": "MISMATCH",
                           "detail": f"커밋 해시 불일치: SSC={ssc_commit}, testbed={testbed_commit}",
                           "stale_risk": "높음 — SSC 스캔 시점과 소스 버전이 다름. stale finding 다수 예상."})
        return result

    # 커밋 없으면 버전명 vs 브랜치명 비교
    if ssc_version_name and testbed_branch:
        ssc_v = norm(ssc_version_name)
        tb_b  = norm(testbed_branch)
        if ssc_v == tb_b or ssc_v in tb_b or tb_b in ssc_v:
            result.update({"status": "PARTIAL",
                           "detail": f"버전명/브랜치명 유사 일치: SSC version='{ssc_version_name}', testbed branch='{testbed_branch}'. 커밋 수준 검증 불가.",
                           "stale_risk": "중간 — 브랜치 일치하나 커밋 미확인. 코드 변경 시 stale 가능."})
        else:
            result.update({"status": "MISMATCH",
                           "detail": f"버전명/브랜치명 불일치: SSC version='{ssc_version_name}', testbed branch='{testbed_branch}'",
                           "stale_risk": "높음 — 브랜치가 다를 경우 finding 대부분이 현재 코드와 무관할 수 있음."})
        return result

    result.update({"detail": "SSC 스캔 커밋 정보 없음. SSC 버전명과 testbed 경로를 수동 비교하세요.",
                   "stale_risk": "알 수 없음"})
    return result


def normalize_path(raw: str) -> str:
    """SSC 경로를 상대 경로로 정규화 (탐색 용이성)"""
    # e.g. "src/main/java/com/example/Foo.java:42" → 그대로 반환
    return raw or ""


def build_finding(issue: dict, version_meta: dict) -> dict:
    """SSC 이슈 → 정합성 검증용 finding 구조로 변환"""
    # fullFileName: 전체 경로 (e.g. "shared/src/main/java/.../Foo.java")
    # primaryLocation: 클래스명 or 파일명만 (표시용)
    full_path = issue.get("fullFileName") or issue.get("primaryLocation", "")
    line_no = issue.get("lineNumber")

    return {
        "ssc_issue_id":     issue.get("issueInstanceId", ""),
        "issue_name":       issue.get("issueName", ""),
        "friority":         issue.get("friority", ""),
        "severity":         issue.get("severity"),
        "likelihood":       issue.get("likelihood"),
        "impact":           issue.get("impact"),
        "confidence":       issue.get("confidence"),
        "kingdom":          issue.get("kingdom", ""),
        "analyzer":         issue.get("analyzer", ""),
        "primary_location": issue.get("primaryLocation", ""),  # 클래스명
        "full_file_path":   normalize_path(full_path),         # 전체 경로 (소스 탐색용)
        "line_number":      line_no,
        "issue_status":     issue.get("issueStatus", ""),
        "scan_status":      issue.get("scanStatus", ""),
        "found_date":       issue.get("foundDate", ""),
        "reviewed":         issue.get("reviewed"),   # None | True | False
        "suppressed":       issue.get("suppressed", False),
        "audited":          issue.get("audited", False),
        "has_comments":     issue.get("hasComments", False),
        # 검증 결과 (LLM이 채움)
        "verification": {
            "result":        None,   # "취약" | "양호(FP)" | "검토필요"
            "judgment":      None,   # 판정 근거 요약
            "code_evidence": None,   # 관련 코드 스니펫
            "recommendation": None,  # 조치 방안 (취약인 경우)
        },
        "project_version": {
            "id":      version_meta.get("id"),
            "name":    version_meta.get("name"),
            "project": version_meta.get("project", {}).get("name"),
        },
    }


# ─────────────────────────────────────────────
# 메인
# ─────────────────────────────────────────────

def cmd_list_projects(client: SSCClient):
    """접근 가능한 프로젝트 목록 출력"""
    projects = client.list_projects()
    print(f"\n[SSC] 접근 가능한 프로젝트 ({len(projects)}개)\n")
    for p in sorted(projects, key=lambda x: x.get("name", "")):
        print(f"  {p.get('id'):>6}  {p.get('name','')}")
    print()


def cmd_generate_token(client: SSCClient):
    """토큰 발급 후 출력 (.env 추가 안내)"""
    # client 생성 시 이미 token을 발급받음
    if client.token:
        print(f"\n[SSC] 발급된 토큰:\n\nSSC_TOKEN={client.token}\n")
        print(".env 파일에 위 행을 추가하세요.")
    else:
        print("[SSC] 토큰 발급 실패: SSC_USERNAME / SSC_PASSWORD 확인 필요")


def cmd_fetch(client: SSCClient, args) -> dict:
    """High/Critical findings 수집 → JSON 반환"""

    # 1) 버전 특정
    if args.version_id:
        version_meta = client.get_project_version(args.version_id)
        version_id = args.version_id
    else:
        versions = client.find_project_versions(args.project, args.version)
        if not versions:
            raise RuntimeError(
                f"프로젝트를 찾을 수 없습니다: '{args.project}'"
                + (f" (버전: '{args.version}')" if args.version else "")
                + "\n  --list-projects 로 전체 목록을 확인하세요."
            )
        if len(versions) > 1 and not args.version:
            print(f"[SSC] 여러 버전이 있습니다. 최신 버전을 사용합니다:", file=sys.stderr)
            for v in versions:
                proj = v.get("project", {}).get("name", "")
                print(f"       id={v['id']}  {proj} / {v['name']}", file=sys.stderr)
        version_meta = versions[0]
        version_id = version_meta["id"]

    proj_name = version_meta.get("project", {}).get("name", "unknown")
    ver_name  = version_meta.get("name", "unknown")
    print(f"[SSC] 대상: {proj_name} / {ver_name} (id={version_id})", file=sys.stderr)

    # 2) 필터셋 조회 (기본 필터셋 사용)
    filterset_id = None
    try:
        filtersets = client.get_filter_sets(version_id)
        default_fs = next((f for f in filtersets if f.get("defaultFilterSet")), None)
        filterset_id = default_fs["guid"] if default_fs else None
        fs_name = default_fs["title"] if default_fs else "N/A"
        print(f"[SSC] 필터셋: {fs_name} ({filterset_id})", file=sys.stderr)
    except Exception as e:
        print(f"[SSC] 필터셋 조회 실패 (무시): {e}", file=sys.stderr)

    # 3) 스캔 아티팩트 메타데이터 수집 (브랜치/커밋 정보)
    artifacts = []
    ssc_commit = None
    try:
        artifacts = client.get_artifacts(version_id)
        ssc_commit = extract_scan_commit(artifacts)
        if ssc_commit:
            print(f"[SSC] 스캔 커밋: {ssc_commit}", file=sys.stderr)
        else:
            print(f"[SSC] 스캔 커밋 정보 없음 (SSC 설정에 따라 미제공될 수 있음)", file=sys.stderr)
    except Exception as e:
        print(f"[SSC] 아티팩트 조회 실패 (무시): {e}", file=sys.stderr)

    # 3-a) testbed 경로와 브랜치/커밋 비교
    branch_match = None
    if getattr(args, "testbed", None):
        tb = parse_testbed_path(args.testbed)
        print(f"[SSC] testbed: branch={tb['branch']}, commit={tb['commit']}", file=sys.stderr)
        branch_match = compare_branch_commit(
            ssc_version_name=ver_name,
            ssc_commit=ssc_commit,
            testbed_branch=tb.get("branch"),
            testbed_commit=tb.get("commit"),
        )
        status_icon = {"MATCH": "✅", "PARTIAL": "⚠️", "MISMATCH": "❌", "UNKNOWN": "❓"}.get(
            branch_match["status"], "❓"
        )
        print(
            f"[SSC] 브랜치 일치 검증: {status_icon} {branch_match['status']} — {branch_match['detail']}",
            file=sys.stderr,
        )
        if branch_match["status"] == "MISMATCH":
            print(
                f"[SSC] ⚠️  stale 위험: {branch_match['stale_risk']}",
                file=sys.stderr,
            )

    # 4) 이슈 요약 (통계용)
    summary_raw = []
    try:
        summary_raw = client.get_issue_summary(version_id, filterset_id)
    except Exception as e:
        print(f"[SSC] 이슈 요약 조회 실패 (무시): {e}", file=sys.stderr)

    # 5) 전체 이슈 수집
    print(f"[SSC] 이슈 수집 중...", file=sys.stderr)
    all_issues = client.get_issues(version_id, filterset_id)
    print(f"[SSC] 전체 이슈: {len(all_issues)}건", file=sys.stderr)

    # 6) High/Critical 필터링 (suppressed 제외)
    target = [
        i for i in all_issues
        if i.get("friority") in SSCClient.HIGH_CRITICAL
        and not i.get("suppressed", False)
    ]
    print(f"[SSC] High/Critical (비억제): {len(target)}건", file=sys.stderr)

    # 7) finding 구조로 변환
    findings = [build_finding(i, version_meta) for i in target]

    # 8) 결과 JSON 구성
    friority_counts: dict = {}
    for f in findings:
        k = f["friority"]
        friority_counts[k] = friority_counts.get(k, 0) + 1

    result = {
        "metadata": {
            "generated_at":   datetime.now().isoformat(),
            "ssc_base_url":   client.base_url,
            "project_name":   proj_name,
            "version_name":   ver_name,
            "version_id":     version_id,
            "filterset_id":   filterset_id,
            "ssc_scan_commit": ssc_commit,
            "branch_match":   branch_match,   # None if --testbed not specified
        },
        "summary": {
            "total_issues_in_version": len(all_issues),
            "suppressed_in_version":   sum(1 for i in all_issues if i.get("suppressed")),
            "high_critical_count":     len(findings),
            "by_friority":             friority_counts,
            "by_kingdom":              _count_by(findings, "kingdom"),
            "by_issue_name":           _count_by(findings, "issue_name"),
        },
        "version_summary_by_friority": summary_raw,
        "findings": findings,
    }
    return result


def _count_by(findings: list, key: str) -> dict:
    counts: dict = {}
    for f in findings:
        k = f.get(key, "unknown") or "unknown"
        counts[k] = counts.get(k, 0) + 1
    return dict(sorted(counts.items(), key=lambda x: -x[1]))


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Fortify SSC High/Critical findings 수집",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--project",      metavar="NAME",  help="SSC 프로젝트명")
    parser.add_argument("--version",      metavar="NAME",  help="버전명 (생략 시 첫 번째)")
    parser.add_argument("--version-id",   metavar="ID",    type=int,
                        help="버전 ID 직접 지정 (--project 대신)")
    parser.add_argument("--testbed",      metavar="PATH",
                        help="testbed 소스코드 디렉토리 경로 (브랜치/커밋 일치 검증용)\n"
                             "  예: testbed/ocbwebview/ocb-webview-api@master@886aad0\n"
                             "  경로명의 @branch@commit 패턴으로 SSC 스캔 버전과 비교합니다.")
    parser.add_argument("--list-projects", action="store_true",
                        help="접근 가능한 프로젝트 목록 출력")
    parser.add_argument("--generate-token", action="store_true",
                        help="username/password로 토큰 발급 (.env SSC_USERNAME/SSC_PASSWORD 필요)")
    parser.add_argument("-o", "--output",  metavar="FILE",
                        help="출력 JSON 파일 경로 (미지정 시 stdout)")
    parser.add_argument("--pretty",       action="store_true", default=True,
                        help="들여쓰기 출력 (기본 on)")
    args = parser.parse_args()

    # 환경변수 로드
    env = load_env()
    base_url  = env.get("SSC_BASE_URL", "https://ssc.skplanet.com/ssc")
    token     = env.get("SSC_TOKEN")
    username  = env.get("SSC_USERNAME")
    password  = env.get("SSC_PASSWORD")

    if not token and not (username and password):
        print(
            "[오류] SSC 인증 정보 없음.\n"
            "  .env에 SSC_TOKEN 또는 SSC_USERNAME+SSC_PASSWORD를 추가하세요.\n"
            "  토큰 발급: python3 fetch_ssc.py --generate-token",
            file=sys.stderr,
        )
        sys.exit(1)

    client = SSCClient(base_url, token=token, username=username, password=password,
                       env_path=ENV_PATH)

    if args.list_projects:
        cmd_list_projects(client)
        return

    if args.generate_token:
        cmd_generate_token(client)
        return

    if not args.project and not args.version_id:
        parser.error("--project 또는 --version-id 가 필요합니다.")

    result = cmd_fetch(client, args)

    indent = 2 if args.pretty else None
    output_str = json.dumps(result, ensure_ascii=False, indent=indent)

    if args.output:
        Path(args.output).write_text(output_str, encoding="utf-8")
        print(f"[SSC] 저장 완료: {args.output} ({len(result['findings'])}건)", file=sys.stderr)
    else:
        print(output_str)


if __name__ == "__main__":
    main()
