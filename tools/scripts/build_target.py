#!/usr/bin/env python3
"""
build_target.py — /sec-audit-static 사전 빌드 실행 + 아티팩트 매니페스트 생성

목적:
  1. Joern 바이트코드 분석용 JAR/WAR 아티팩트 확보
  2. SCA(Software Composition Analysis)용 dependency report 생성
  3. 빌드 실패 시 소스 분석 fallback 자동 처리

사용법:
    python3 build_target.py \\
        --source-dir testbed/gws/oki-be/oki-admin-rest-api \\
        --build-cmd "./gradlew :application:oki-admin-rest-api:build -x test" \\
        --jdk 17 \\
        --output state/gws_oki_admin_build_manifest.json

    # 빌드 없이 아티팩트 탐색만
    python3 build_target.py \\
        --source-dir testbed/gws/oki-be/oki-admin-rest-api \\
        --scan-only \\
        --output state/gws_oki_admin_build_manifest.json

    # 내부 의존성 자동 해소 (Composite Build) 활성화
    python3 build_target.py \\
        --source-dir testbed/ocbwebview/ocb-webview-api@master@886aad0 \\
        --build-cmd "./gradlew build -x test" \\
        --jdk 17 --resolve-deps \\
        --output state/ocbwebview_api_build_manifest.json

출력 (build_manifest.json):
    {
      "build_success": true,
      "build_tool": "gradle",
      "jdk_version": "17",
      "java_home": "/usr/lib/jvm/java-17-openjdk-amd64",
      "artifacts": [{"type": "jar", "path": "...", "size_mb": 12.3}],
      "dependency_report": "path/to/dep-report.txt",
      "source_dir": "...",
      "build_cmd": "...",
      "build_log": "state/build_<prefix>.log",
      "fallback_source_only": false,
      "built_at": "2026-03-19T..."
    }
"""

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path


# ─────────────────────────────────────────────────────────────────
# 1. JDK 버전 감지 / JAVA_HOME 설정
# ─────────────────────────────────────────────────────────────────

# JDK 후보 경로 패턴 (버전 번호를 키로 치환)
_JDK_CANDIDATE_PATTERNS = [
    "/usr/lib/jvm/java-{v}-openjdk-amd64",
    "/usr/lib/jvm/java-{v}-openjdk",
    "/usr/lib/jvm/temurin-{v}",
    "/usr/lib/jvm/adoptopenjdk-{v}-hotspot-amd64",
    "/usr/local/lib/jvm/java-{v}",
    "/opt/java/{v}",
]


def find_java_home(jdk_version: int | str) -> str | None:
    """지정 JDK 버전의 JAVA_HOME 경로를 탐색한다.

    탐색 순서:
    1. 고정 경로 패턴
    2. SDKMAN (~/.sdkman/candidates/java/)
    3. update-alternatives (Debian/Ubuntu)
    4. `which java` + 심볼릭 링크 해석
    """
    v = str(jdk_version)

    # 1. 고정 경로 패턴
    for pattern in _JDK_CANDIDATE_PATTERNS:
        candidate = Path(pattern.format(v=v))
        if candidate.exists() and (candidate / "bin" / "java").exists():
            return str(candidate)

    # 2. SDKMAN
    sdkman_base = Path.home() / ".sdkman" / "candidates" / "java"
    if sdkman_base.exists():
        for d in sorted(sdkman_base.iterdir(), reverse=True):
            if d.name.startswith(f"{v}.") or d.name.startswith(f"{v}-"):
                if (d / "bin" / "java").exists():
                    return str(d)

    # 3. update-alternatives
    try:
        out = subprocess.check_output(
            ["update-alternatives", "--list", "java"], stderr=subprocess.DEVNULL, text=True
        )
        for line in out.strip().splitlines():
            line = line.strip()
            if f"-{v}-" in line or f"/{v}/" in line:
                jh = line.replace("/bin/java", "").rstrip("/")
                if Path(jh).exists():
                    return jh
    except (FileNotFoundError, subprocess.CalledProcessError):
        pass

    # 4. 현재 java가 해당 버전인지 확인
    try:
        out = subprocess.check_output(
            ["java", "-version"], stderr=subprocess.STDOUT, text=True
        )
        if f' {v}.' in out or f'"17"' in out or f'version "{v}' in out:
            java_path = subprocess.check_output(["which", "java"], text=True).strip()
            real = Path(java_path).resolve()
            jh = str(real.parent.parent)
            if Path(jh).exists():
                return jh
    except (FileNotFoundError, subprocess.CalledProcessError):
        pass

    return None


# ─────────────────────────────────────────────────────────────────
# 2. 빌드 도구 자동 감지
# ─────────────────────────────────────────────────────────────────

def detect_build_tool(source_dir: Path) -> str:
    """소스 디렉토리에서 빌드 도구를 자동 감지한다."""
    if (source_dir / "pom.xml").exists():
        return "maven"
    if (source_dir / "build.gradle").exists() or (source_dir / "build.gradle.kts").exists():
        return "gradle"
    if (source_dir / "package.json").exists():
        return "npm"
    if (source_dir / "requirements.txt").exists() or (source_dir / "pyproject.toml").exists():
        return "pip"
    if list(source_dir.glob("*.php")) or (source_dir / "composer.json").exists():
        return "php"
    if (source_dir / "Makefile").exists():
        return "make"
    return "unknown"


# ─────────────────────────────────────────────────────────────────
# 3. 빌드 실행
# ─────────────────────────────────────────────────────────────────

def run_build(
    source_dir: Path,
    build_cmd: str,
    jdk_version: int | str | None,
    timeout: int = 600,
    dry_run: bool = False,
    log_path: Path | None = None,
) -> dict:
    """빌드 명령을 실행하고 결과를 반환한다.

    Returns:
        {
          "success": bool,
          "returncode": int,
          "duration_sec": float,
          "log_path": str | None,
          "error": str | None,
          "java_home": str | None,
        }
    """
    env = os.environ.copy()
    java_home = None

    # JAVA_HOME 설정
    if jdk_version is not None:
        java_home = find_java_home(jdk_version)
        if java_home:
            env["JAVA_HOME"] = java_home
            env["PATH"] = f"{java_home}/bin:{env.get('PATH', '')}"
            print(f"  JAVA_HOME={java_home}")
        else:
            print(f"  ⚠️  JDK {jdk_version} 경로를 찾지 못했습니다. 시스템 기본 JDK 사용.")

    if dry_run:
        print(f"  [dry-run] 빌드 명령: {build_cmd}")
        return {
            "success": True,
            "returncode": 0,
            "duration_sec": 0.0,
            "log_path": None,
            "error": None,
            "java_home": java_home,
            "dry_run": True,
        }

    # build_cmd에서 앞부분의 'java_home N;' 패턴 제거 (이미 위에서 처리)
    clean_cmd = re.sub(r'^\s*java_home\s+\d+\s*;\s*', '', build_cmd).strip()

    print(f"  실행: {clean_cmd}")
    start_time = datetime.now()

    log_fh = None
    if log_path:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_fh = open(log_path, "w", encoding="utf-8")

    try:
        proc = subprocess.run(
            clean_cmd,
            shell=True,
            cwd=str(source_dir),
            env=env,
            stdout=log_fh or subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            text=True,
        )
        duration = (datetime.now() - start_time).total_seconds()
        success = proc.returncode == 0

        if not log_fh and proc.stdout:
            tail = "\n".join(proc.stdout.splitlines()[-20:])
            print(f"  빌드 출력 (마지막 20줄):\n{tail}")

        return {
            "success": success,
            "returncode": proc.returncode,
            "duration_sec": round(duration, 1),
            "log_path": str(log_path) if log_path else None,
            "error": None if success else f"returncode={proc.returncode}",
            "java_home": java_home,
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "returncode": -1,
            "duration_sec": timeout,
            "log_path": str(log_path) if log_path else None,
            "error": f"빌드 타임아웃 ({timeout}초 초과)",
            "java_home": java_home,
        }
    except Exception as e:
        return {
            "success": False,
            "returncode": -1,
            "duration_sec": 0.0,
            "log_path": str(log_path) if log_path else None,
            "error": str(e),
            "java_home": java_home,
        }
    finally:
        if log_fh:
            log_fh.close()


# ─────────────────────────────────────────────────────────────────
# 4. 아티팩트 탐색
# ─────────────────────────────────────────────────────────────────

def find_artifacts(source_dir: Path, build_tool: str) -> list[dict]:
    """빌드 후 생성된 JAR/WAR/패키지를 탐색한다."""
    artifacts = []
    search_root = source_dir

    if build_tool in ("gradle", "maven"):
        # build/libs/*.jar, target/*.jar/war 탐색 (node_modules 등 제외)
        for pattern in ("**/*.jar", "**/*.war"):
            for p in search_root.glob(pattern):
                # 제외: test, sources, javadoc, plain
                stem = p.stem.lower()
                if any(x in stem for x in ("-sources", "-javadoc", "-tests", "-plain", "-original")):
                    continue
                # 제외: .gradle 캐시 디렉토리
                if ".gradle" in p.parts or "node_modules" in p.parts:
                    continue
                size_mb = round(p.stat().st_size / (1024 * 1024), 2)
                artifacts.append({
                    "type": p.suffix.lstrip("."),
                    "path": str(p),
                    "size_mb": size_mb,
                })
    elif build_tool == "npm":
        # dist/, build/, .next/ 등 번들 디렉토리
        for d in ("dist", "build", ".next", "out"):
            candidate = search_root / d
            if candidate.exists():
                artifacts.append({
                    "type": "bundle",
                    "path": str(candidate),
                    "size_mb": None,
                })
    elif build_tool == "pip":
        # .egg-info, site-packages 등
        for p in search_root.glob("**/*.egg-info"):
            artifacts.append({"type": "egg-info", "path": str(p), "size_mb": None})
    elif build_tool in ("php", "unknown"):
        # 빌드 없음 — 소스 디렉토리 자체가 아티팩트
        artifacts.append({
            "type": "source",
            "path": str(source_dir),
            "size_mb": None,
        })

    # 크기 기준 내림차순 정렬 (None은 뒤로)
    artifacts.sort(key=lambda a: (a["size_mb"] is None, -(a["size_mb"] or 0)))
    return artifacts


# ─────────────────────────────────────────────────────────────────
# 5. Dependency 보고서 생성 (SCA용)
# ─────────────────────────────────────────────────────────────────

def generate_dependency_report(
    source_dir: Path,
    build_tool: str,
    java_home: str | None,
    output_dir: Path,
    timeout: int = 120,
) -> str | None:
    """빌드 도구별 dependency tree를 생성하고 파일 경로를 반환한다."""
    env = os.environ.copy()
    if java_home:
        env["JAVA_HOME"] = java_home
        env["PATH"] = f"{java_home}/bin:{env.get('PATH', '')}"

    out_file = output_dir / "dependency_tree.txt"

    cmd_map = {
        "gradle": "./gradlew dependencies --configuration runtimeClasspath",
        "maven": "mvn dependency:tree -DoutputFile=dependency_tree.txt -Doutput.scope=runtime",
        "npm":   "npm list --all --json",
        "pip":   "pip freeze",
    }
    cmd = cmd_map.get(build_tool)
    if not cmd:
        return None

    try:
        result = subprocess.run(
            cmd, shell=True, cwd=str(source_dir), env=env,
            capture_output=True, text=True, timeout=timeout,
        )
        content = result.stdout or ""
        if content:
            out_file.parent.mkdir(parents=True, exist_ok=True)
            out_file.write_text(content, encoding="utf-8")
            return str(out_file)
    except Exception as e:
        print(f"  ⚠️  Dependency report 생성 실패: {e}")

    return None


# ─────────────────────────────────────────────────────────────────
# 6. 아티팩트 중 Joern 분석에 적합한 주 JAR 선택
# ─────────────────────────────────────────────────────────────────

def pick_primary_jar(artifacts: list[dict]) -> str | None:
    """아티팩트 목록에서 Joern 분석용 주 JAR/WAR를 선택한다.

    선택 기준:
    1. WAR 파일 우선 (서블릿 컨테이너 전체 포함)
    2. 가장 큰 JAR (Boot fat-jar일 가능성 높음)
    3. 이름에 'plain'이 없는 것
    """
    jars = [a for a in artifacts if a["type"] in ("jar", "war")]
    if not jars:
        return None
    # WAR 우선
    wars = [a for a in jars if a["type"] == "war"]
    if wars:
        return wars[0]["path"]
    # 가장 큰 JAR
    return jars[0]["path"]


# ─────────────────────────────────────────────────────────────────
# 7. 매니페스트 저장
# ─────────────────────────────────────────────────────────────────

def save_manifest(manifest: dict, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
    print(f"\n빌드 매니페스트 저장: {output_path}")


# ─────────────────────────────────────────────────────────────────
# 7-B. 내부 의존성 자동 해소 (Composite Build — Method B)
# ─────────────────────────────────────────────────────────────────

# 사내 패키지 prefix → Bitbucket {project, repos} 매핑 테이블
# repo 이름이 여러 개인 경우 첫 번째부터 순서대로 시도
_INTERNAL_PKG_REPO_MAP: dict[str, dict] = {
    "com.skp.ocb.webview":   {"project": "OCBWEBVIEW", "repos": ["ocb-webview-api", "ocb-webview-common"]},
    "com.skp.ocb.community": {"project": "OCBWEBVIEW", "repos": ["ocb-community-api"]},
    "com.skp.ocb.ogeul":     {"project": "OCBWEBVIEW", "repos": ["ocb-ogeul-admin-frontend"]},
    "com.skp.ocb.back":      {"project": "OCB_BACK_END", "repos": ["ocb-backend", "ocb-common"]},
    "com.skp.ocb.game":      {"project": "OCB-GAME", "repos": ["ocb-game-api"]},
    "com.skp.ocb.thp":       {"project": "OCB-THP", "repos": ["ocb-thp-api"]},
    "com.skp.ocb.kick":      {"project": "OKICK", "repos": ["okick-api"]},
    "com.skp.ocb.pass":      {"project": "OCBPASS", "repos": ["ocbpass-api"]},
    "com.skp.gws":           {"project": "GWS", "repos": ["oki-be", "oki-admin-rest-api"]},
    "com.skp.oz":            {"project": "OCBWEBVIEW", "repos": ["oz-module", "oz-common"]},
    "com.skp":               {"project": "OCB_BACK_END", "repos": ["ocb-common"]},  # fallback
}

# 클론 루트
_DEP_CLONE_ROOT = Path("/tmp/playbook_deps")


def _load_bb_token() -> str | None:
    """`.env`에서 CUSTOMER_BB_TOKEN 로드. 없으면 환경변수 확인."""
    token = os.environ.get("CUSTOMER_BB_TOKEN")
    if token:
        return token
    env_file = Path(".env")
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line.startswith("CUSTOMER_BB_TOKEN=") and not line.startswith("#"):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    return None


def _parse_missing_internal_packages(log_path: Path) -> list[str]:
    """빌드 로그에서 누락된 내부 패키지 prefix 목록 추출.

    예: "error: package com.skp.oz.viewer does not exist"
        → "com.skp.oz.viewer"
    """
    if not log_path or not Path(log_path).exists():
        return []

    content = Path(log_path).read_text(encoding="utf-8", errors="ignore")
    # Java 컴파일 에러 패턴
    patterns = [
        r"error: package (com\.skp\.\S+) does not exist",
        r"error: cannot find symbol.*\n.*location.*class (com\.skp\.\S+)",
        r"Could not resolve (com\.skp[^:\s]+):",
        r"Unresolved reference: (com\.skp\S+)",   # Kotlin
    ]
    found: set[str] = set()
    for pat in patterns:
        for m in re.finditer(pat, content, re.MULTILINE):
            found.add(m.group(1))
    return sorted(found)


def _match_repo_for_package(pkg: str) -> tuple[str, str] | None:
    """패키지명에서 가장 긴 prefix 매치 → (project, repo) 반환."""
    best_prefix = ""
    best_entry = None
    for prefix, entry in _INTERNAL_PKG_REPO_MAP.items():
        if pkg.startswith(prefix) and len(prefix) > len(best_prefix):
            best_prefix = prefix
            best_entry = entry
    if best_entry is None:
        return None
    project = best_entry["project"]
    repo = best_entry["repos"][0]
    return (project, repo)


def _clone_repo(project: str, repo: str, token: str, clone_root: Path) -> Path | None:
    """Bitbucket HTTP OAuth2 토큰으로 repo 클론. 이미 있으면 재사용."""
    dest = clone_root / repo
    if dest.exists():
        print(f"    재사용: {dest} (이미 클론됨)")
        return dest

    clone_root.mkdir(parents=True, exist_ok=True)
    bb_base = os.environ.get("CUSTOMER_BB_BASE", "http://code.skplanet.com")
    url = f"{bb_base}/scm/{project}/{repo}.git"
    # token을 URL에 포함 (Basic auth — oauth2:<token>)
    auth_url = url.replace("http://", f"http://oauth2:{token}@")

    print(f"    클론: {url} → {dest}")
    try:
        result = subprocess.run(
            ["git", "clone", "--depth=1", auth_url, str(dest)],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode == 0:
            return dest
        print(f"    ⚠️  클론 실패: {result.stderr.strip()[:200]}")
    except Exception as e:
        print(f"    ⚠️  클론 예외: {e}")
    return None


def _inject_composite_builds(settings_file: Path, include_dirs: list[Path]) -> bytes:
    """settings.gradle 또는 settings.gradle.kts에 includeBuild() 구문 추가.

    Returns: 원본 내용 (복원용)
    """
    original = settings_file.read_bytes()
    additions: list[str] = []

    is_kts = settings_file.suffix == ".kts"
    for d in include_dirs:
        if is_kts:
            additions.append(f'includeBuild("{d}")')
        else:
            additions.append(f'includeBuild "{d}"')

    if not additions:
        return original

    separator = "\n// [build_target.py] 내부 의존성 Composite Build 자동 주입\n"
    patch = separator + "\n".join(additions) + "\n"
    settings_file.write_bytes(original + patch.encode())
    return original


def resolve_internal_dependencies_and_rebuild(
    source_dir: Path,
    build_cmd: str,
    build_result: dict,
    jdk_version: int | str | None,
    timeout: int = 600,
    clone_root: Path = _DEP_CLONE_ROOT,
) -> dict:
    """빌드 실패 후 내부 패키지 누락 감지 → Composite Build로 재시도.

    Method B (Composite Build):
      1. 빌드 로그 파싱 → 누락된 com.skp.* 패키지 추출
      2. 패키지 prefix → Bitbucket repo 매핑
      3. 각 repo를 /tmp/playbook_deps/<repo>에 --depth=1 클론
      4. settings.gradle에 includeBuild() 자동 주입
      5. 빌드 재시도
      6. settings.gradle 원상복원

    Returns dict:
      {
        "attempted": bool,          # 누락 패키지가 있어 시도했는지
        "success": bool,            # 재빌드 성공 여부
        "cloned_repos": list[str],  # 클론된 repo 목록
        "skipped_pkgs": list[str],  # 매핑 미발견 패키지
        "rebuild_result": dict,     # run_build() 결과
        "fallback_source_only": bool,
      }
    """
    result: dict = {
        "attempted": False,
        "success": False,
        "cloned_repos": [],
        "skipped_pkgs": [],
        "rebuild_result": {},
        "fallback_source_only": True,
    }

    log_path = build_result.get("log_path")
    if not log_path:
        print("  [Composite Build] 빌드 로그 없음 — 건너뜀")
        return result

    # Step 1: 누락 패키지 파싱
    missing_pkgs = _parse_missing_internal_packages(Path(log_path))
    if not missing_pkgs:
        print("  [Composite Build] 내부 패키지 누락 없음 — 건너뜀")
        return result

    print(f"\n[Composite Build] 누락 내부 패키지 {len(missing_pkgs)}건 감지:")
    for pkg in missing_pkgs:
        print(f"    {pkg}")

    # Step 2: 토큰 로드
    token = _load_bb_token()
    if not token:
        print("  ⚠️  CUSTOMER_BB_TOKEN 없음 — Composite Build 건너뜀")
        return result

    result["attempted"] = True

    # Step 3: repo 클론 (중복 제거)
    seen_repos: set[str] = set()
    include_dirs: list[Path] = []

    for pkg in missing_pkgs:
        match = _match_repo_for_package(pkg)
        if match is None:
            print(f"    매핑 없음: {pkg}")
            result["skipped_pkgs"].append(pkg)
            continue
        project, repo = match
        if repo in seen_repos:
            continue
        seen_repos.add(repo)
        cloned = _clone_repo(project, repo, token, clone_root)
        if cloned:
            include_dirs.append(cloned)
            result["cloned_repos"].append(repo)
        else:
            result["skipped_pkgs"].append(pkg)

    if not include_dirs:
        print("  ⚠️  클론된 repo 없음 — Composite Build 중단")
        return result

    # Step 4: settings.gradle 탐색 & 주입
    settings_candidates = [
        source_dir / "settings.gradle.kts",
        source_dir / "settings.gradle",
    ]
    settings_file = next((f for f in settings_candidates if f.exists()), None)

    if settings_file is None:
        print("  ⚠️  settings.gradle 없음 — Composite Build 중단")
        return result

    original_content = _inject_composite_builds(settings_file, include_dirs)
    print(f"  includeBuild 주입 → {settings_file} ({len(include_dirs)}개 repo)")

    # Step 5: 재빌드
    try:
        print(f"  [재빌드 시도]")
        rebuild = run_build(
            source_dir=source_dir,
            build_cmd=build_cmd,
            jdk_version=jdk_version,
            timeout=timeout,
            dry_run=False,
            log_path=Path(log_path).with_name(Path(log_path).stem + "_retry.log"),
        )
        result["rebuild_result"] = rebuild
        result["success"] = rebuild["success"]
        result["fallback_source_only"] = not rebuild["success"]

        if rebuild["success"]:
            print(f"  ✅ 재빌드 성공 ({rebuild['duration_sec']}초)")
        else:
            print(f"  ❌ 재빌드 실패: {rebuild['error']}")
    finally:
        # Step 6: settings.gradle 복원 (항상)
        settings_file.write_bytes(original_content)
        print(f"  settings.gradle 복원 완료")

    return result


# ─────────────────────────────────────────────────────────────────
# 8. 메인 로직
# ─────────────────────────────────────────────────────────────────

def build_and_manifest(
    source_dir: Path,
    build_cmd: str | None,
    jdk_version: int | str | None,
    output_path: Path,
    state_dir: Path,
    scan_only: bool = False,
    dry_run: bool = False,
    timeout: int = 600,
    dep_report: bool = False,
    resolve_deps: bool = False,
) -> dict:
    """빌드 실행 → 아티팩트 탐색 → 매니페스트 반환"""

    print(f"\n=== build_target.py ===")
    print(f"소스: {source_dir}")

    build_tool = detect_build_tool(source_dir)
    print(f"빌드 도구 감지: {build_tool}")

    build_result: dict = {
        "success": True, "returncode": 0, "duration_sec": 0.0,
        "log_path": None, "error": None, "java_home": None, "skipped": True,
    }
    composite_build_result: dict = {}

    # 빌드 실행 (scan_only=False 이고 build_cmd가 있을 때)
    if not scan_only and build_cmd and build_tool not in ("php", "unknown"):
        prefix = output_path.stem.replace("_build_manifest", "")
        log_path = state_dir / f"build_{prefix}.log"
        print(f"\n[빌드 실행]")
        build_result = run_build(
            source_dir=source_dir,
            build_cmd=build_cmd,
            jdk_version=jdk_version,
            timeout=timeout,
            dry_run=dry_run,
            log_path=log_path,
        )
        build_result.pop("skipped", None)

        if build_result["success"]:
            print(f"  ✅ 빌드 성공 ({build_result['duration_sec']}초)")
        else:
            print(f"  ❌ 빌드 실패: {build_result['error']}")
            # --resolve-deps: 내부 의존성 누락 시 Composite Build 자동 재시도
            if resolve_deps and not dry_run:
                print(f"  → --resolve-deps: 내부 의존성 해소 후 재빌드 시도")
                composite_build_result = resolve_internal_dependencies_and_rebuild(
                    source_dir=source_dir,
                    build_cmd=build_cmd,
                    build_result=build_result,
                    jdk_version=jdk_version,
                    timeout=timeout,
                )
                if composite_build_result.get("success"):
                    # 재빌드 성공 → build_result 갱신
                    build_result = composite_build_result["rebuild_result"]
                    print(f"  ✅ Composite Build 재빌드 성공")
                else:
                    print(f"  → fallback: 소스 분석 모드로 계속 진행")
            else:
                print(f"  → fallback: 소스 분석 모드로 계속 진행")
    elif build_tool in ("php", "unknown"):
        print(f"  빌드 불필요 ({build_tool}) — 소스 분석 모드")
    elif scan_only:
        print(f"  --scan-only: 빌드 생략, 기존 아티팩트 탐색만 수행")
    else:
        print(f"  --build-cmd 없음: 기존 아티팩트 탐색만 수행")

    # 아티팩트 탐색
    print(f"\n[아티팩트 탐색]")
    artifacts = find_artifacts(source_dir, build_tool)
    if artifacts:
        for a in artifacts:
            size_str = f"{a['size_mb']} MB" if a.get("size_mb") is not None else "N/A"
            print(f"  {a['type'].upper()}: {a['path']} ({size_str})")
    else:
        print(f"  아티팩트 없음 — 소스 분석 fallback")

    primary_jar = pick_primary_jar(artifacts)
    if primary_jar:
        print(f"  → Joern 분석 대상: {primary_jar}")

    # Dependency report (선택)
    dep_report_path = None
    if dep_report and build_result.get("success", False):
        print(f"\n[Dependency Report 생성]")
        dep_report_path = generate_dependency_report(
            source_dir=source_dir,
            build_tool=build_tool,
            java_home=build_result.get("java_home"),
            output_dir=state_dir,
        )
        if dep_report_path:
            print(f"  → {dep_report_path}")

    # 매니페스트 조립
    manifest = {
        "build_success": build_result["success"],
        "build_skipped": bool(build_result.get("skipped") or scan_only),
        "build_tool": build_tool,
        "jdk_version": str(jdk_version) if jdk_version is not None else None,
        "java_home": build_result.get("java_home"),
        "artifacts": artifacts,
        "primary_jar": primary_jar,
        "dependency_report": dep_report_path,
        "source_dir": str(source_dir),
        "build_cmd": build_cmd,
        "build_log": build_result.get("log_path"),
        "build_duration_sec": build_result.get("duration_sec", 0.0),
        "build_error": build_result.get("error"),
        "fallback_source_only": not bool(primary_jar),
        "built_at": datetime.now().isoformat(),
    }
    if composite_build_result:
        manifest["composite_build"] = {
            "attempted": composite_build_result.get("attempted", False),
            "success": composite_build_result.get("success", False),
            "cloned_repos": composite_build_result.get("cloned_repos", []),
            "skipped_pkgs": composite_build_result.get("skipped_pkgs", []),
        }

    return manifest


# ─────────────────────────────────────────────────────────────────
# 9. CLI 진입점
# ─────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="sec-audit-static 사전 빌드 실행 + 아티팩트 매니페스트 생성"
    )
    parser.add_argument("--source-dir", "-s", required=True,
                        help="빌드 대상 소스코드 디렉토리")
    parser.add_argument("--build-cmd", "-b", default=None,
                        help="빌드 명령 (예: './gradlew build -x test'). "
                             "앞의 'java_home N;' 접두사는 자동 제거됨")
    parser.add_argument("--jdk", "-j", default=None, type=str,
                        help="사용할 JDK 버전 (예: 8, 11, 17, 21)")
    parser.add_argument("--output", "-o", required=True,
                        help="출력 매니페스트 JSON 경로 (예: state/proj_build_manifest.json)")
    parser.add_argument("--state-dir", default="state",
                        help="state 디렉토리 (빌드 로그 등 저장, 기본: state/)")
    parser.add_argument("--timeout", "-t", default=600, type=int,
                        help="빌드 타임아웃 초 (기본: 600)")
    parser.add_argument("--scan-only", action="store_true",
                        help="빌드 실행 없이 기존 아티팩트 탐색만 수행")
    parser.add_argument("--dep-report", action="store_true",
                        help="SCA용 dependency tree 생성 (빌드 성공 시)")
    parser.add_argument("--dry-run", action="store_true",
                        help="빌드 명령을 실제 실행하지 않고 출력만")
    parser.add_argument("--resolve-deps", action="store_true",
                        help="빌드 실패 시 누락 내부 패키지를 Bitbucket에서 자동 클론 후 "
                             "Composite Build로 재빌드 (CUSTOMER_BB_TOKEN 필요)")

    args = parser.parse_args()

    source_dir = Path(args.source_dir)
    if not source_dir.exists():
        print(f"Error: 소스 디렉토리를 찾을 수 없습니다: {source_dir}")
        sys.exit(1)

    output_path = Path(args.output)
    state_dir = Path(args.state_dir)

    manifest = build_and_manifest(
        source_dir=source_dir,
        build_cmd=args.build_cmd,
        jdk_version=args.jdk,
        output_path=output_path,
        state_dir=state_dir,
        scan_only=args.scan_only,
        dry_run=args.dry_run,
        timeout=args.timeout,
        dep_report=args.dep_report,
        resolve_deps=args.resolve_deps,
    )

    save_manifest(manifest, output_path)

    # 종료 코드: 빌드 실패여도 fallback 가능이면 0
    if not manifest["build_success"] and not manifest["build_skipped"]:
        if not manifest["fallback_source_only"]:
            sys.exit(0)   # 아티팩트 없어도 소스 분석은 가능 → 정상 종료
        # build_cmd가 있었는데 빌드 실패 + 아티팩트 없음
        print("⚠️  빌드 실패, 소스 분석 fallback으로 진행됩니다.")
    sys.exit(0)


if __name__ == "__main__":
    main()
