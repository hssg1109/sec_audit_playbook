#!/usr/bin/env python3
"""
Confluence Server/DC 자동 게시 스크립트.

docs/*.md 문서와 state/ 진단 결과 JSON을 Confluence에 자동 게시한다.
표준 라이브러리만 사용하며, markdown 패키지는 선택적(optional)이다.

Usage:
    python tools/scripts/publish_confluence.py --dry-run
    python tools/scripts/publish_confluence.py
    python tools/scripts/publish_confluence.py --filter docs/00_overview.md
    python tools/scripts/publish_confluence.py --map tools/confluence_page_map.json
"""
import argparse
import base64
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from html import escape as html_escape

# ---------------------------------------------------------------------------
# .env loader
# ---------------------------------------------------------------------------

def load_env(path=".env"):
    """Parse a .env file (KEY=VALUE lines) into os.environ."""
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
            # strip surrounding quotes
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
                value = value[1:-1]
            os.environ.setdefault(key, value)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def get_config():
    """Load configuration from environment variables and validate."""
    cfg = {
        "base_url": os.environ.get("CONFLUENCE_BASE_URL", "").rstrip("/"),
        "space_key": os.environ.get("CONFLUENCE_SPACE_KEY", ""),
        "parent_id": os.environ.get("CONFLUENCE_PARENT_ID", ""),
        "user": os.environ.get("CONFLUENCE_USER", ""),
        "token": os.environ.get("CONFLUENCE_TOKEN", ""),
    }
    missing = [k for k in ("base_url", "space_key", "parent_id", "token") if not cfg[k]]
    if missing:
        print(f"[ERROR] Missing required environment variables: "
              f"{', '.join('CONFLUENCE_' + k.upper() for k in missing)}", file=sys.stderr)
        print("       Copy .env.example to .env and fill in the values.", file=sys.stderr)
        sys.exit(1)
    return cfg

# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

def build_auth_header(cfg):
    """Return Authorization header dict.

    If CONFLUENCE_USER is set  -> Basic base64(user:token)
    Otherwise                  -> Bearer token (PAT)
    """
    if cfg["user"]:
        cred = base64.b64encode(f"{cfg['user']}:{cfg['token']}".encode()).decode()
        return {"Authorization": f"Basic {cred}"}
    return {"Authorization": f"Bearer {cfg['token']}"}

# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------

def confluence_api(cfg, method, path, body=None):
    """urllib-based HTTP wrapper for Confluence REST API.

    Returns parsed JSON response or None for 204/empty bodies.
    Raises SystemExit on HTTP errors.
    """
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
    except urllib.error.URLError as exc:
        print(f"[ERROR] Cannot reach {url}: {exc.reason}", file=sys.stderr)
        raise SystemExit(1) from exc

# ---------------------------------------------------------------------------
# Confluence CRUD
# ---------------------------------------------------------------------------

def find_page_by_title(cfg, title):
    """Search for an existing page by exact title in the configured space.

    Returns {"id": ..., "version": {"number": N}} or None.
    """
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
    """Create a new Confluence page under *parent_id*."""
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


def update_page(cfg, page_id, title, body_xhtml, version, parent_id=None):
    """Update an existing Confluence page (version + 1).

    If *parent_id* is given the page is moved under that parent.
    """
    payload = {
        "type": "page",
        "title": title,
        "version": {"number": version + 1},
        "body": {
            "storage": {
                "value": body_xhtml,
                "representation": "storage",
            }
        },
    }
    if parent_id is not None:
        payload["ancestors"] = [{"id": str(parent_id)}]
    confluence_api(cfg, "PUT", f"/rest/api/content/{page_id}", payload)
    return page_id


def publish_page(cfg, title, body_xhtml, parent_id):
    """Idempotent publish: create if new, update (and move) if exists."""
    existing = find_page_by_title(cfg, title)
    if existing:
        update_page(cfg, existing["id"], title, body_xhtml,
                    existing["version"], parent_id=parent_id)
        return existing["id"], "updated"
    page_id = create_page(cfg, title, body_xhtml, parent_id)
    return page_id, "created"

# ---------------------------------------------------------------------------
# Markdown -> XHTML
# ---------------------------------------------------------------------------

def _md_to_xhtml_lib(md_text):
    """Convert Markdown to XHTML using the markdown package."""
    import markdown  # noqa: F811
    return markdown.markdown(
        md_text,
        extensions=["tables", "fenced_code"],
        output_format="xhtml",
    )


def _md_to_xhtml_fallback(md_text):
    """Regex-based Markdown to XHTML fallback (no external deps)."""
    lines = md_text.split("\n")
    html_parts = []
    in_code_block = False
    code_lang = ""
    code_lines = []
    table_rows = []

    def flush_table():
        if not table_rows:
            return ""
        out = ['<table><tbody>']
        for i, row in enumerate(table_rows):
            tag = "th" if i == 0 else "td"
            cells = [c.strip() for c in row.split("|")]
            cells = [c for c in cells if c]
            out.append("<tr>" + "".join(f"<{tag}>{html_escape(c)}</{tag}>" for c in cells) + "</tr>")
        out.append("</tbody></table>")
        table_rows.clear()
        return "\n".join(out)

    for line in lines:
        # Confluence anchor token: [[ANCHOR:name]]
        if line.startswith("[[ANCHOR:") and line.endswith("]]"):
            name = line[len("[[ANCHOR:"):-2]
            name = html_escape(name)
            html_parts.append(
                f'<ac:structured-macro ac:name="anchor">'
                f'<ac:parameter ac:name="name">{name}</ac:parameter>'
                f'</ac:structured-macro>'
            )
            continue
        # fenced code block
        m_fence = re.match(r'^```(\w*)$', line)
        if m_fence:
            if in_code_block:
                html_parts.append(_code_macro("\n".join(code_lines), code_lang))
                code_lines = []
                in_code_block = False
            else:
                html_parts.append(flush_table())
                in_code_block = True
                code_lang = m_fence.group(1) or "text"
            continue
        if in_code_block:
            code_lines.append(line)
            continue

        # table row
        if "|" in line:
            stripped = line.strip()
            if re.match(r'^[\|\s\-:]+$', stripped):
                continue  # separator row
            table_rows.append(stripped)
            continue
        else:
            html_parts.append(flush_table())

        # headings
        m_h = re.match(r'^(#{1,6})\s+(.*)', line)
        if m_h:
            level = len(m_h.group(1))
            text = m_h.group(2)
            html_parts.append(f"<h{level}>{html_escape(text)}</h{level}>")
            continue

        # blank line
        if not line.strip():
            html_parts.append("")
            continue

        # inline formatting then wrap in <p>
        text = html_escape(line)
        text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
        text = re.sub(r'\*(.+?)\*', r'<em>\1</em>', text)
        text = re.sub(r'`(.+?)`', r'<code>\1</code>', text)
        html_parts.append(f"<p>{text}</p>")

    html_parts.append(flush_table())
    return "\n".join(html_parts)


def md_to_xhtml(md_text):
    """Convert Markdown text to XHTML, preferring the markdown package."""
    def _preprocess_anchors(text: str) -> str:
        # Convert <a id="name"></a> to token so both paths can render to Confluence anchor macro.
        def repl(match):
            name = match.group(1)
            return f"[[ANCHOR:{name}]]"
        return re.sub(r'<a\\s+id=["\\\']([^"\\\']+)["\\\']\\s*></a>', repl, text)

    def _postprocess_anchors(xhtml: str) -> str:
        def repl(match):
            name = html_escape(match.group(1))
            return (
                f'<ac:structured-macro ac:name="anchor">'
                f'<ac:parameter ac:name="name">{name}</ac:parameter>'
                f'</ac:structured-macro>'
            )
        return re.sub(r'\[\[ANCHOR:([^\]]+)\]\]', repl, xhtml)

    md_text = _preprocess_anchors(md_text)
    try:
        return _postprocess_anchors(_md_to_xhtml_lib(md_text))
    except ImportError:
        return _postprocess_anchors(_md_to_xhtml_fallback(md_text))

# ---------------------------------------------------------------------------
# JSON -> XHTML helpers
# ---------------------------------------------------------------------------

def _code_macro(code_text, lang="text"):
    """Wrap code in Confluence code macro (Storage Format)."""
    return (
        f'<ac:structured-macro ac:name="code">'
        f'<ac:parameter ac:name="language">{html_escape(lang)}</ac:parameter>'
        f'<ac:plain-text-body><![CDATA[{code_text}]]></ac:plain-text-body>'
        f'</ac:structured-macro>'
    )


def _severity_badge(severity):
    """Return Confluence status macro for severity level."""
    color_map = {
        "Critical": "Red",
        "High": "Red",
        "Medium": "Yellow",
        "Low": "Blue",
        "Info": "Grey",
    }
    color = color_map.get(severity, "Grey")
    return (
        f'<ac:structured-macro ac:name="status">'
        f'<ac:parameter ac:name="colour">{color}</ac:parameter>'
        f'<ac:parameter ac:name="title">{html_escape(severity)}</ac:parameter>'
        f'</ac:structured-macro>'
    )


def _table(headers, rows):
    """Build an XHTML table from headers and rows."""
    parts = ["<table><thead><tr>"]
    for h in headers:
        parts.append(f"<th>{h}</th>")
    parts.append("</tr></thead><tbody>")
    for row in rows:
        parts.append("<tr>")
        for cell in row:
            parts.append(f"<td>{cell}</td>")
        parts.append("</tr>")
    parts.append("</tbody></table>")
    return "".join(parts)

# ---------------------------------------------------------------------------
# JSON -> XHTML by type
# ---------------------------------------------------------------------------

def _json_to_xhtml_asset(data):
    """Convert task_11 (asset identification) JSON to XHTML."""
    parts = [f"<h2>자산 식별 결과 (Task {html_escape(str(data.get('task_id', '')))})</h2>"]

    findings = data.get("findings", [])
    if findings:
        headers = ["서비스 그룹", "자산명", "환경", "도메인", "기술 스택", "용도", "노출", "인증"]
        rows = []
        for f in findings:
            tech = ", ".join(f.get("tech_stack", [])) if isinstance(f.get("tech_stack"), list) else ""
            rows.append([
                html_escape(str(f.get("service_group", ""))),
                html_escape(str(f.get("asset_name", ""))),
                html_escape(str(f.get("environment", ""))),
                html_escape(str(f.get("domain", ""))),
                html_escape(tech),
                html_escape(str(f.get("purpose", ""))),
                html_escape(str(f.get("exposure", ""))),
                html_escape(str(f.get("has_auth", ""))),
            ])
        parts.append(_table(headers, rows))

    # detailed info for first asset (with full tech details)
    for f in findings:
        if f.get("security_components"):
            parts.append(f"<h3>보안 컴포넌트 ({html_escape(str(f.get('asset_name', '')))} - {html_escape(str(f.get('environment', '')))})</h3>")
            parts.append("<ul>")
            for comp in f["security_components"]:
                parts.append(f"<li>{html_escape(comp)}</li>")
            parts.append("</ul>")
        if f.get("external_services"):
            parts.append(f"<h3>외부 서비스 연동</h3>")
            parts.append("<ul>")
            for svc in f["external_services"]:
                parts.append(f"<li>{html_escape(svc)}</li>")
            parts.append("</ul>")

    meta = data.get("metadata", {})
    if meta:
        parts.append("<h3>메타데이터</h3>")
        parts.append(f"<p>출처: {html_escape(str(meta.get('source_file', '')))}</p>")
        parts.append(f"<p>전체 자산 수: {meta.get('total_assets', 0)}</p>")

    return "\n".join(parts)


def _json_to_xhtml_api(data):
    """Convert API inventory JSON to XHTML.

    Supports both:
    - task_21 standard format (findings key)
    - scan_api.py v3.0 format (endpoints key + auth_stats + resolved_fields)
    """
    # --- scan_api.py v3.0 format (endpoints key) ---
    if "endpoints" in data:
        return _json_to_xhtml_api_inventory(data)

    # --- task_21 standard format (findings key) ---
    task_id = html_escape(str(data.get("task_id", "")))
    target = html_escape(str(data.get("target", "")))
    parts = [f"<h2>API 인벤토리 (Task {task_id})</h2>"]
    if target:
        parts.append(f"<p><strong>대상:</strong> {target}</p>")

    # scan scope
    scope = data.get("scan_scope", {})
    if scope:
        parts.append("<h3>스캔 범위</h3>")
        sc_headers = ["항목", "값"]
        sc_rows = []
        if scope.get("framework"):
            sc_rows.append(["프레임워크", html_escape(str(scope["framework"]))])
        if scope.get("db_access"):
            db_list = scope["db_access"]
            if isinstance(db_list, list):
                sc_rows.append(["DB 접근 방식", html_escape(", ".join(db_list))])
            else:
                sc_rows.append(["DB 접근 방식", html_escape(str(db_list))])
        for key, label in [("controllers_scanned", "Controller"),
                           ("services_scanned", "Service"),
                           ("repositories_scanned", "Repository"),
                           ("mybatis_mappers_scanned", "MyBatis Mapper")]:
            if key in scope:
                sc_rows.append([label, str(scope[key])])
        if sc_rows:
            parts.append(_table(sc_headers, sc_rows))

    # summary
    summary = data.get("summary", {})
    if summary:
        parts.append("<h3>요약</h3>")
        total = summary.get("total_endpoints", 0)
        parts.append(f"<p>전체 엔드포인트: <strong>{total}</strong></p>")
        by_ctrl = summary.get("by_controller", {})
        if by_ctrl:
            c_headers = ["Controller", "엔드포인트 수"]
            c_rows = []
            for ctrl_name, count in by_ctrl.items():
                # support both int and dict formats
                cnt = count if isinstance(count, int) else count.get("total", 0)
                c_rows.append([html_escape(ctrl_name), str(cnt)])
            parts.append(_table(c_headers, c_rows))
        by_method = summary.get("by_method", {})
        if by_method:
            m_headers = ["HTTP Method", "건수"]
            m_rows = [[html_escape(str(k)), str(v)] for k, v in by_method.items()]
            parts.append(_table(m_headers, m_rows))
        auth_req = summary.get("auth_required_count")
        auth_not = summary.get("auth_not_required_count")
        if auth_req is not None:
            parts.append(f"<p>인증 필요: {auth_req} / 인증 불필요: {auth_not}</p>")

    # endpoint list table
    findings = data.get("findings", [])
    if findings:
        parts.append("<h3>API 엔드포인트 목록</h3>")
        headers = ["Method", "API", "인증", "핸들러", "설명"]
        rows = []
        for f in findings:
            auth_str = "필수" if f.get("auth_required") else "-"
            rows.append([
                f"<code>{html_escape(str(f.get('method', '')))}</code>",
                f"<code>{html_escape(str(f.get('api', '')))}</code>",
                html_escape(auth_str),
                f"<code>{html_escape(str(f.get('handler', '')))}</code>",
                html_escape(str(f.get("description", ""))),
            ])
        parts.append(_table(headers, rows))

    # detailed endpoint info - only for endpoints with parameters
    has_params = [f for f in findings if f.get("parameters")]
    if has_params:
        parts.append("<h2>엔드포인트 상세 (파라미터 보유)</h2>")
        for f in has_params:
            api = html_escape(str(f.get("api", "")))
            method = html_escape(str(f.get("method", "")))
            handler = html_escape(str(f.get("handler", "")))
            desc = html_escape(str(f.get("description", "")))
            file_loc = html_escape(str(f.get("file", "")))

            parts.append(f"<h3><code>{method} {api}</code></h3>")
            parts.append(f"<p><strong>핸들러:</strong> <code>{handler}</code> "
                         f"(<code>{file_loc}</code>)</p>")
            parts.append(f"<p>{desc}</p>")

            resp_type = f.get("response_type", "")
            if resp_type:
                parts.append(f"<p><strong>응답:</strong> {html_escape(str(resp_type))}</p>")

            params = f.get("parameters", [])
            if params:
                p_headers = ["파라미터", "타입", "출처", "기본값"]
                p_rows = []
                for p in params:
                    default = p.get("default")
                    default_str = html_escape(str(default)) if default is not None else "-"
                    p_rows.append([
                        f"<code>{html_escape(str(p.get('name', '')))}</code>",
                        f"<code>{html_escape(str(p.get('type', '')))}</code>",
                        html_escape(str(p.get("source", ""))),
                        default_str,
                    ])
                parts.append(_table(p_headers, p_rows))

    # legacy metadata support
    meta = data.get("metadata", {})
    if meta:
        parts.append("<h3>메타데이터</h3>")
        if meta.get("framework"):
            parts.append(f"<p>프레임워크: {html_escape(str(meta['framework']))}</p>")
        if meta.get("endpoint_count"):
            parts.append(f"<p>엔드포인트 수: {meta['endpoint_count']}</p>")
        if meta.get("auth_mechanism"):
            parts.append(f"<p>인증 방식: {html_escape(str(meta['auth_mechanism']))}</p>")

    return "\n".join(parts)


def _json_to_xhtml_api_inventory(data):
    """Convert scan_api.py v3.0 output (endpoints key) to XHTML.

    Renders: summary stats, auth classification, endpoint table with
    auth detail, and per-endpoint parameter detail with DTO resolved fields.
    """
    source_dir = html_escape(str(data.get("source_dir", "")))
    total_ep = data.get("total_endpoints", 0)
    total_ctrl = data.get("total_controllers", 0)
    total_files = data.get("total_files_scanned", 0)

    parts = ["<h2>API 인벤토리</h2>"]
    parts.append(f"<p><strong>소스:</strong> <code>{source_dir}</code></p>")

    # --- 요약 통계 ---
    parts.append("<h3>스캔 요약</h3>")
    sum_rows = [
        ["스캔 파일", str(total_files)],
        ["컨트롤러", str(total_ctrl)],
        ["엔드포인트", f"<strong>{total_ep}</strong>"],
    ]
    parts.append(_table(["항목", "값"], sum_rows))

    # HTTP 메서드별
    method_stats = data.get("method_stats", {})
    if method_stats:
        parts.append("<h3>HTTP 메서드별</h3>")
        m_rows = [[f"<code>{html_escape(k)}</code>", str(v)]
                   for k, v in sorted(method_stats.items())]
        parts.append(_table(["메서드", "건수"], m_rows))

    # 인증 분류 (이진)
    auth_stats = data.get("auth_stats", {})
    if auth_stats:
        parts.append("<h3>인증 분류</h3>")
        auth_req = auth_stats.get("auth_required", 0)
        auth_not = auth_stats.get("auth_not_required", 0)
        a_rows = [
            [_severity_badge("High").replace("High", "인증 필요"), f"<strong>{auth_req}</strong>"],
            [_severity_badge("Info").replace("Info", "인증 불필요"), f"<strong>{auth_not}</strong>"],
        ]
        parts.append(_table(["분류", "건수"], a_rows))

    # 보안 등급 상세 (4-Level 매트릭스)
    auth_detail_stats = data.get("auth_detail_stats", {})
    if auth_detail_stats:
        detail_labels = {
            "L1_완전인증": "L1 완전 인증 (required=true, permitted=true)",
            "L2_기본인증": "L2 기본 인증 (required=true)",
            "L3_비인증": "L3 비인증 (required=false)",
            "L4_조건부인증": "L4 조건부 인증 (required=false, permitted=true)",
            "preauthorize": "@PreAuthorize",
            "secured": "@Secured",
            "security_config": "Security Config",
            "no_auth_annotation": "인증 어노테이션 없음",
        }
        d_rows = []
        for key, count in sorted(auth_detail_stats.items(), key=lambda x: -x[1]):
            label = detail_labels.get(key, key)
            d_rows.append([html_escape(label), str(count)])
        if d_rows:
            parts.append("<p><em>보안 등급 상세:</em></p>")
            parts.append(_table(["등급", "건수"], d_rows))

    # 주석 처리된 컨트롤러
    commented = data.get("commented_controllers", [])
    if commented:
        parts.append("<h3>주석 처리된 컨트롤러 (분석 제외)</h3>")
        c_rows = []
        for cc in commented:
            c_rows.append([
                f"<code>{html_escape(cc.get('class', ''))}</code>",
                str(cc.get("endpoint_count", 0)),
                html_escape(cc.get("reason", "")),
                f"<code>{html_escape(cc.get('file', ''))}</code>" if cc.get("file") else "-",
            ])
        parts.append(_table(["클래스", "엔드포인트 수", "사유", "파일"], c_rows))

    # 모듈별 통계
    module_stats = data.get("module_stats", {})
    if module_stats:
        parts.append("<h3>모듈별</h3>")
        mod_rows = []
        for mod, stats in module_stats.items():
            mod_rows.append([
                html_escape(mod),
                str(stats.get("total", 0)),
                str(stats.get("auth_required", 0)),
                str(stats.get("no_auth", 0)),
            ])
        parts.append(_table(["모듈", "전체", "인증", "비인증"], mod_rows))

    # 보안 설정
    sec_configs = data.get("security_configs", {})
    if sec_configs:
        parts.append("<h3>보안 설정</h3>")
        for mod, cfg in sec_configs.items():
            cfg_file = html_escape(str(cfg.get("config_file", "")))
            csrf = "비활성화" if cfg.get("csrf_disabled") else "활성화"
            cors = "개방(*)" if cfg.get("cors_open") else "제한"
            parts.append(f"<p><strong>{html_escape(mod)}:</strong> "
                         f"<code>{cfg_file}</code> "
                         f"(CSRF: {csrf}, CORS: {cors})</p>")

    # --- 엔드포인트 목록 테이블 ---
    endpoints = data.get("endpoints", [])
    if endpoints:
        parts.append("<h2>엔드포인트 목록</h2>")
        headers = ["#", "Method", "API", "인증", "인증 상세", "핸들러", "파일"]
        rows = []
        for idx, ep in enumerate(endpoints, 1):
            auth_required = ep.get("auth_required", False)
            auth_detail = ep.get("auth_detail", "")

            if auth_required:
                auth_badge = _severity_badge("High").replace("High", "필수")
            else:
                auth_badge = _severity_badge("Info").replace("Info", "불필요")

            rows.append([
                str(idx),
                f"<code>{html_escape(str(ep.get('method', '')))}</code>",
                f"<code>{html_escape(str(ep.get('api', '')))}</code>",
                auth_badge,
                f"<code>{html_escape(auth_detail)}</code>" if auth_detail else "-",
                f"<code>{html_escape(str(ep.get('handler', '')))}</code>",
                f"<code>{html_escape(str(ep.get('file', '')))}</code>",
            ])
        parts.append(_table(headers, rows))

    # --- 엔드포인트 상세 (파라미터 보유) ---
    has_params = [ep for ep in endpoints
                  if ep.get("parameters")
                  and any(p.get("type") not in ("request", "response", "exchange")
                          for p in ep["parameters"])]
    if has_params:
        parts.append("<h2>엔드포인트 상세</h2>")
        for ep in has_params:
            api = html_escape(str(ep.get("api", "")))
            method = html_escape(str(ep.get("method", "")))
            handler = html_escape(str(ep.get("handler", "")))
            desc = html_escape(str(ep.get("description", "")))
            file_loc = html_escape(str(ep.get("file", "")))
            ret_type = html_escape(str(ep.get("return_type", "")))

            parts.append(f"<h3><code>{method} {api}</code></h3>")
            parts.append(f"<p><strong>핸들러:</strong> <code>{handler}</code> "
                         f"(<code>{file_loc}:{ep.get('line', '')}</code>)</p>")
            if desc:
                parts.append(f"<p>{desc}</p>")
            if ret_type:
                parts.append(f"<p><strong>응답:</strong> <code>{ret_type}</code></p>")

            # 인증 정보
            auth_detail = ep.get("auth_detail", "")
            if auth_detail:
                parts.append(f"<p><strong>인증:</strong> <code>{html_escape(auth_detail)}</code></p>")

            # 미들웨어
            mw = ep.get("middleware", [])
            if mw:
                mw_str = ", ".join(f"<code>{html_escape(m)}</code>" for m in mw)
                parts.append(f"<p><strong>미들웨어:</strong> {mw_str}</p>")

            # 파라미터 테이블
            params = [p for p in ep.get("parameters", [])
                      if p.get("type") not in ("request", "response", "exchange")]
            if params:
                p_headers = ["파라미터", "출처", "데이터 타입", "필수", "기본값"]
                p_rows = []
                for p in params:
                    req_str = "Y" if p.get("required") else "-"
                    default = p.get("default_value")
                    default_str = f"<code>{html_escape(str(default))}</code>" if default else "-"
                    dtype = html_escape(str(p.get("data_type", "")))
                    resolved = p.get("resolved_from", "")
                    if resolved:
                        dtype += f' <em>({html_escape(resolved)})</em>'

                    p_rows.append([
                        f"<code>{html_escape(str(p.get('name', '')))}</code>",
                        f"<code>{html_escape(str(p.get('type', '')))}</code>",
                        f"<code>{dtype}</code>",
                        req_str,
                        default_str,
                    ])
                parts.append(_table(p_headers, p_rows))

                # DTO resolved fields (세부 필드)
                for p in params:
                    resolved_fields = p.get("resolved_fields", [])
                    if resolved_fields:
                        resolved_from = html_escape(str(p.get("resolved_from", p.get("data_type", ""))))
                        parts.append(
                            f"<p><em><code>{html_escape(str(p.get('name', '')))}</code> "
                            f"타입 <code>{resolved_from}</code> 필드:</em></p>"
                        )
                        rf_headers = ["필드", "타입", "어노테이션", "Nullable"]
                        rf_rows = []
                        for rf in resolved_fields:
                            annos = rf.get("annotations", [])
                            anno_str = " ".join(
                                f"<code>{html_escape(a)}</code>" for a in annos
                            ) if annos else "-"
                            inherited = rf.get("inherited", False)
                            name_str = html_escape(str(rf.get("name", "")))
                            if inherited:
                                inh_from = html_escape(str(rf.get("inherited_from", "")))
                                name_str += f" <em>(← {inh_from})</em>"
                            rf_rows.append([
                                f"<code>{name_str}</code>",
                                f"<code>{html_escape(str(rf.get('data_type', '')))}</code>",
                                anno_str,
                                "Y" if rf.get("nullable") else "-",
                            ])
                        parts.append(_table(rf_headers, rf_rows))

    return "\n".join(parts)


def _json_to_xhtml_vuln(data):
    """Convert task_22/33/34 (vulnerability findings) JSON to XHTML."""
    task_id = data.get("task_id", "")
    target = data.get("target", "")
    parts = [f"<h2>취약점 진단 결과 (Task {html_escape(str(task_id))})</h2>"]
    if target:
        parts.append(f"<p><strong>대상:</strong> {html_escape(str(target))}</p>")

    # diagnosis criteria
    criteria = data.get("diagnosis_criteria", {})
    if criteria:
        vuln_pats = criteria.get("vulnerable_patterns", [])
        safe_pats = criteria.get("safe_patterns", [])
        if vuln_pats or safe_pats:
            parts.append("<h3>진단 기준</h3>")
        if vuln_pats:
            parts.append(f'<ac:structured-macro ac:name="warning">'
                         f'<ac:rich-text-body><p><strong>취약 패턴:</strong></p><ul>')
            for pat in vuln_pats:
                parts.append(f"<li>{html_escape(str(pat))}</li>")
            parts.append("</ul></ac:rich-text-body></ac:structured-macro>")
        if safe_pats:
            parts.append(f'<ac:structured-macro ac:name="info">'
                         f'<ac:rich-text-body><p><strong>양호 패턴:</strong></p><ul>')
            for pat in safe_pats:
                parts.append(f"<li>{html_escape(str(pat))}</li>")
            parts.append("</ul></ac:rich-text-body></ac:structured-macro>")

    findings = data.get("findings", [])

    # severity summary
    sev_count = {}
    for f in findings:
        sev = f.get("severity", "Unknown")
        sev_count[sev] = sev_count.get(sev, 0) + 1
    if sev_count:
        parts.append("<h3>심각도별 요약</h3>")
        s_headers = ["심각도", "건수"]
        s_rows = []
        for sev in ["Critical", "High", "Medium", "Low", "Info"]:
            if sev in sev_count:
                s_rows.append([_severity_badge(sev), str(sev_count[sev])])
        parts.append(_table(s_headers, s_rows))

    # individual findings
    for f in findings:
        sev = f.get("severity", "")
        fid = html_escape(str(f.get("id", "")))
        title = html_escape(str(f.get("title", "")))
        parts.append(f"<h3>{fid} - {title} {_severity_badge(sev)}</h3>")
        parts.append(f"<p><strong>카테고리:</strong> {html_escape(str(f.get('category', '')))}</p>")
        parts.append(f"<p><strong>설명:</strong> {html_escape(str(f.get('description', '')))}</p>")
        parts.append(f"<p><strong>영향 범위:</strong> {html_escape(str(f.get('affected_endpoint', '')))}</p>")

        evidence = f.get("evidence", {})
        if evidence:
            efile = html_escape(str(evidence.get("file", "")))
            elines = html_escape(str(evidence.get("lines", "")))
            parts.append(f"<p><strong>증거:</strong> <code>{efile}:{elines}</code></p>")
            # call trace
            call_trace = evidence.get("call_trace", "")
            if call_trace:
                parts.append(f"<p><strong>호출 체인:</strong> <code>{html_escape(str(call_trace))}</code></p>")
            snippet = evidence.get("code_snippet", "")
            if snippet:
                efile_name = evidence.get("file", "")
                if efile_name.endswith(".java") or efile_name.endswith(".xml"):
                    lang = "java"
                elif efile_name.endswith(".kts"):
                    lang = "groovy"
                elif efile_name.endswith(".kt"):
                    lang = "kotlin"
                elif efile_name.endswith(".py"):
                    lang = "python"
                elif efile_name.endswith(".js") or efile_name.endswith(".ts"):
                    lang = "javascript"
                else:
                    lang = "text"
                parts.append(_code_macro(snippet, lang))

        # attack example
        attack = f.get("attack_example", "")
        if attack:
            parts.append(f'<ac:structured-macro ac:name="warning">'
                         f'<ac:rich-text-body><p><strong>공격 예시:</strong> '
                         f'<code>{html_escape(str(attack))}</code></p>'
                         f'</ac:rich-text-body></ac:structured-macro>')

        cwe = f.get("cwe_id", "")
        owasp = f.get("owasp_category", "")
        if cwe or owasp:
            parts.append(f"<p><strong>CWE:</strong> {html_escape(str(cwe))} | "
                         f"<strong>OWASP:</strong> {html_escape(str(owasp))}</p>")

        rec = f.get("recommendation", "")
        if rec:
            parts.append(f'<ac:structured-macro ac:name="info">'
                         f'<ac:rich-text-body><p><strong>권고사항:</strong> '
                         f'{html_escape(rec)}</p></ac:rich-text-body>'
                         f'</ac:structured-macro>')

    # summary section
    summary = data.get("summary", {})
    if summary:
        parts.append("<h3>진단 요약</h3>")
        total = summary.get("total_findings", 0)
        parts.append(f"<p><strong>총 발견 건수:</strong> {total}</p>")
        by_cat = summary.get("by_category", {})
        if by_cat:
            cat_headers = ["카테고리", "건수"]
            cat_rows = [[html_escape(str(k)), str(v)] for k, v in by_cat.items()]
            parts.append(_table(cat_headers, cat_rows))
        by_exp = summary.get("by_exposure", {})
        if by_exp:
            exp_headers = ["노출 유형", "건수"]
            exp_rows = [[html_escape(str(k)), str(v)] for k, v in by_exp.items()]
            parts.append(_table(exp_headers, exp_rows))
        risk = summary.get("risk_assessment", "")
        if risk:
            parts.append(f'<ac:structured-macro ac:name="panel">'
                         f'<ac:parameter ac:name="borderStyle">solid</ac:parameter>'
                         f'<ac:rich-text-body><p><strong>위험 평가:</strong> '
                         f'{html_escape(str(risk))}</p>'
                         f'</ac:rich-text-body></ac:structured-macro>')

    # safe patterns found
    safe = data.get("safe_patterns_found", {})
    if safe:
        items = safe.get("items", [])
        if items:
            parts.append("<h3>양호 판정 항목</h3>")
            safe_headers = ["위치", "판정 사유"]
            safe_rows = []
            for item in items:
                safe_rows.append([
                    f"<code>{html_escape(str(item.get('location', '')))}</code>",
                    html_escape(str(item.get("reason", ""))),
                ])
            parts.append(_table(safe_headers, safe_rows))

    # notes
    notes = data.get("notes")
    if notes:
        parts.append(f'<ac:structured-macro ac:name="note">'
                     f'<ac:rich-text-body><p>{html_escape(str(notes))}</p>'
                     f'</ac:rich-text-body></ac:structured-macro>')

    return "\n".join(parts)


def _json_to_xhtml_enhanced_injection(data):
    """Convert scan_injection_enhanced.py output (endpoint_diagnoses key) to XHTML.

    Renders: summary stats, endpoint diagnosis table, global findings detail.
    """
    parts = ["<h2>인젝션 취약점 진단 결과</h2>"]

    # 메타데이터
    meta = data.get("scan_metadata", {})
    if meta:
        parts.append(f"<p><strong>소스:</strong> <code>{html_escape(str(meta.get('source_dir', '')))}</code></p>")
        parts.append(f"<p><strong>API 인벤토리:</strong> <code>{html_escape(str(meta.get('api_inventory', '')))}</code></p>")

    # --- 요약 ---
    summary = data.get("summary", {})
    if summary:
        parts.append("<h3>진단 요약</h3>")
        total = summary.get("total_endpoints", 0)
        sqli = summary.get("sqli", {})
        os_cmd = summary.get("os_command", {})
        ssi = summary.get("ssi", {})
        needs_review = summary.get("needs_review", 0)

        sum_rows = [
            ["총 엔드포인트", f"<strong>{total}</strong>"],
            ["SQLi 양호", str(sqli.get("양호", 0))],
            ["SQLi 취약", f"<strong>{sqli.get('취약', 0)}</strong>"],
            ["SQLi 정보 (수동검토)", str(sqli.get("정보", 0))],
            ["OS Command Injection", f"<strong>{os_cmd.get('total', 0)}</strong>건"],
            ["SSI Injection", str(ssi.get("total", 0)) + "건"],
        ]
        parts.append(_table(["항목", "결과"], sum_rows))

    # --- 엔드포인트별 진단 목록 ---
    diagnoses = data.get("endpoint_diagnoses", [])
    if diagnoses:
        # 결과별 분류
        result_groups = {}
        for ep in diagnoses:
            result = ep.get("result", "정보")
            result_groups.setdefault(result, []).append(ep)

        parts.append(f"<h3>엔드포인트별 진단 ({len(diagnoses)}건)</h3>")

        # 결과별 건수 요약
        result_order = ["취약", "정보", "양호", "N/A"]
        r_rows = []
        for r in result_order:
            eps = result_groups.get(r, [])
            if eps:
                if r == "취약":
                    badge = _severity_badge("High").replace("High", "취약")
                elif r == "양호":
                    badge = _severity_badge("Info").replace("Info", "양호")
                else:
                    badge = _severity_badge("Medium").replace("Medium", r)
                r_rows.append([badge, str(len(eps))])
        if r_rows:
            parts.append(_table(["판정", "건수"], r_rows))

        # 취약 엔드포인트 상세 (있으면)
        vuln_eps = result_groups.get("취약", [])
        if vuln_eps:
            parts.append("<h4>취약 판정 엔드포인트</h4>")
            v_headers = ["#", "Method", "API", "핸들러", "취약 유형", "파일"]
            v_rows = []
            for idx, ep in enumerate(vuln_eps, 1):
                v_rows.append([
                    str(idx),
                    f"<code>{html_escape(str(ep.get('http_method', '')))}</code>",
                    f"<code>{html_escape(str(ep.get('request_mapping', '')))}</code>",
                    f"<code>{html_escape(str(ep.get('handler', '')))}</code>",
                    html_escape(str(ep.get("filter_type", ""))),
                    f"<code>{html_escape(str(ep.get('process_file', '')))}</code>",
                ])
            parts.append(_table(v_headers, v_rows))

        # 전체 엔드포인트 테이블 (축약)
        parts.append("<h4>전체 엔드포인트 진단 목록</h4>")
        ep_headers = ["#", "판정", "Method", "API", "핸들러", "서비스 호출", "DB 연산"]
        ep_rows = []
        for idx, ep in enumerate(diagnoses, 1):
            result = ep.get("result", "정보")
            if result == "취약":
                badge = _severity_badge("High").replace("High", "취약")
            elif result == "양호":
                badge = _severity_badge("Info").replace("Info", "양호")
            else:
                badge = _severity_badge("Medium").replace("Medium", result)

            svc = ep.get("service_calls", [])
            svc_str = ", ".join(f"<code>{html_escape(str(s))}</code>"
                                for s in (svc[:3] if isinstance(svc, list) else []))
            if isinstance(svc, list) and len(svc) > 3:
                svc_str += f" +{len(svc)-3}"

            db_ops = ep.get("db_operations", [])
            db_str = str(len(db_ops)) + "건" if db_ops else "-"

            ep_rows.append([
                str(idx),
                badge,
                f"<code>{html_escape(str(ep.get('http_method', '')))}</code>",
                f"<code>{html_escape(str(ep.get('request_mapping', '')))}</code>",
                f"<code>{html_escape(str(ep.get('handler', '')))}</code>",
                svc_str if svc_str else "-",
                db_str,
            ])
        parts.append(_table(ep_headers, ep_rows))

    # --- 전역 취약점 ---
    global_findings = data.get("global_findings", {})
    if isinstance(global_findings, dict):
        has_findings = any(
            v.get("total", 0) > 0 if isinstance(v, dict) else len(v) > 0
            for v in global_findings.values()
        )
        if has_findings:
            parts.append("<h3>전역 취약점 (Global Findings)</h3>")
            for cat, cat_data in global_findings.items():
                if isinstance(cat_data, dict):
                    total = cat_data.get("total", 0)
                    findings = cat_data.get("findings", [])
                else:
                    total = len(cat_data) if isinstance(cat_data, list) else 0
                    findings = cat_data if isinstance(cat_data, list) else []

                if total == 0:
                    continue

                cat_label = cat.replace("_", " ").title()
                parts.append(f"<h4>{html_escape(cat_label)} ({total}건)</h4>")

                if findings:
                    gf_headers = ["#", "패턴", "파일", "라인", "코드"]
                    gf_rows = []
                    for idx, f in enumerate(findings[:50], 1):  # 최대 50건
                        snippet = str(f.get("code_snippet", ""))
                        if len(snippet) > 100:
                            snippet = snippet[:100] + "..."
                        gf_rows.append([
                            str(idx),
                            f"<code>{html_escape(str(f.get('pattern_name', '')))}</code>",
                            f"<code>{html_escape(str(f.get('file', '')))}</code>",
                            str(f.get("line", "")),
                            f"<code>{html_escape(snippet)}</code>",
                        ])
                    parts.append(_table(gf_headers, gf_rows))
                    if len(findings) > 50:
                        parts.append(f"<p><em>... 외 {len(findings)-50}건 (JSON 원본 참조)</em></p>")

    return "\n".join(parts)


def _json_to_xhtml_final(data):
    """Convert final_report.json to XHTML."""
    parts = ["<h1>AI 보안 진단 최종 보고서</h1>"]

    # Executive Summary
    es = data.get("executive_summary", {})
    if es:
        parts.append("<h2>Executive Summary</h2>")
        parts.append(f'<ac:structured-macro ac:name="panel">'
                     f'<ac:parameter ac:name="borderStyle">solid</ac:parameter>'
                     f'<ac:rich-text-body>')
        parts.append(f"<p><strong>전체 취약점:</strong> {es.get('total_vulnerabilities', 0)}</p>")
        parts.append(f"<p><strong>위험 점수:</strong> {es.get('risk_score', 0)} / 100</p>")
        parts.append(f"<p><strong>Critical:</strong> {es.get('critical_count', 0)} | "
                     f"<strong>High:</strong> {es.get('high_count', 0)}</p>")
        rec = es.get("recommendation", "")
        if rec:
            parts.append(f"<p><strong>권고:</strong> {html_escape(rec)}</p>")
        parts.append("</ac:rich-text-body></ac:structured-macro>")

    # Summary - severity distribution
    summary = data.get("summary", {})
    if summary:
        parts.append("<h2>진단 요약</h2>")
        parts.append(f"<p>총 태스크: {summary.get('total_tasks', 0)} (완료: "
                     f"{summary.get('tasks_completed', 0)})</p>")
        parts.append(f"<p>총 발견 항목: {summary.get('total_findings', 0)}</p>")
        parts.append(f"<p>위험 점수: {summary.get('risk_score', 0)} / 100</p>")

        dist = summary.get("severity_distribution", {})
        if dist:
            parts.append("<h3>심각도 분포</h3>")
            d_headers = ["심각도", "건수"]
            d_rows = []
            for sev in ["Critical", "High", "Medium", "Low", "Info"]:
                count = dist.get(sev, 0)
                d_rows.append([_severity_badge(sev), str(count)])
            parts.append(_table(d_headers, d_rows))

    # All findings table
    findings = data.get("findings", [])
    if findings:
        parts.append("<h2>전체 취약점 목록</h2>")
        f_headers = ["ID", "제목", "심각도", "카테고리", "출처"]
        f_rows = []
        for f in findings:
            f_rows.append([
                html_escape(str(f.get("id", ""))),
                html_escape(str(f.get("title", ""))),
                _severity_badge(f.get("severity", "")),
                html_escape(str(f.get("category", ""))),
                html_escape(str(f.get("source_task", ""))),
            ])
        parts.append(_table(f_headers, f_rows))

        # detailed findings
        parts.append("<h2>상세 취약점 내역</h2>")
        for f in findings:
            sev = f.get("severity", "")
            fid = html_escape(str(f.get("id", "")))
            title = html_escape(str(f.get("title", "")))
            parts.append(f"<h3>{fid} - {title} {_severity_badge(sev)}</h3>")
            parts.append(f"<p><strong>카테고리:</strong> {html_escape(str(f.get('category', '')))}</p>")
            parts.append(f"<p><strong>설명:</strong> {html_escape(str(f.get('description', '')))}</p>")
            parts.append(f"<p><strong>영향 범위:</strong> {html_escape(str(f.get('affected_endpoint', '')))}</p>")

            evidence = f.get("evidence", {})
            if evidence:
                efile = html_escape(str(evidence.get("file", "")))
                elines = html_escape(str(evidence.get("lines", "")))
                parts.append(f"<p><strong>증거:</strong> {efile}:{elines}</p>")
                snippet = evidence.get("code_snippet", "")
                if snippet:
                    parts.append(_code_macro(snippet, "kotlin"))

            cwe = f.get("cwe_id", "")
            owasp = f.get("owasp_category", "")
            if cwe or owasp:
                parts.append(f"<p><strong>CWE:</strong> {html_escape(str(cwe))} | "
                             f"<strong>OWASP:</strong> {html_escape(str(owasp))}</p>")

            rec = f.get("recommendation", "")
            if rec:
                parts.append(f'<ac:structured-macro ac:name="info">'
                             f'<ac:rich-text-body><p><strong>권고사항:</strong> '
                             f'{html_escape(rec)}</p></ac:rich-text-body>'
                             f'</ac:structured-macro>')

    # timestamp
    gen = data.get("generated_at", "")
    if gen:
        parts.append(f"<p><em>생성일시: {html_escape(str(gen))}</em></p>")

    return "\n".join(parts)


def json_to_xhtml(data, json_type, source_path=""):
    """Route JSON data to the appropriate XHTML renderer based on type.

    json_type is one of: "finding", "final_report", "api_inventory"
    source_path helps disambiguate finding sub-types.
    """
    if json_type == "final_report":
        return _json_to_xhtml_final(data)

    # scan_api.py v3.0 format auto-detection (endpoints key)
    if json_type == "api_inventory" or "endpoints" in data:
        return _json_to_xhtml_api_inventory(data)

    # scan_injection_enhanced.py format auto-detection (endpoint_diagnoses key)
    if "endpoint_diagnoses" in data:
        return _json_to_xhtml_enhanced_injection(data)

    # finding type - disambiguate by source file name or task_id
    basename = os.path.basename(source_path)
    task_id = str(data.get("task_id", ""))
    if basename.startswith("task_11") or "task_11" in basename or task_id == "1-1":
        return _json_to_xhtml_asset(data)
    if basename.startswith("task_21") or "task_21" in basename or task_id == "2-1":
        return _json_to_xhtml_api(data)
    # task_22, task_23, task_24, task_25 all use vulnerability format
    return _json_to_xhtml_vuln(data)

# ---------------------------------------------------------------------------
# Content resolver
# ---------------------------------------------------------------------------

def resolve_content(entry, base_dir):
    """Read source file and convert to XHTML based on entry type.

    Returns (xhtml_string, error_string_or_None).
    """
    source = entry["source"]
    full_path = os.path.join(base_dir, source)

    if not os.path.isfile(full_path):
        return None, f"File not found: {full_path}"

    try:
        with open(full_path, encoding="utf-8") as fh:
            raw = fh.read()
    except OSError as exc:
        return None, f"Cannot read {full_path}: {exc}"

    entry_type = entry.get("type", "doc")

    if entry_type == "doc":
        xhtml = md_to_xhtml(raw)
        return xhtml, None

    # JSON types: finding, final_report
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        return None, f"Invalid JSON in {full_path}: {exc}"

    xhtml = json_to_xhtml(data, entry_type, source)
    return xhtml, None

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _publish_entry(cfg, entry, full_title, parent_id, base_dir, dry_run):
    """Publish a single entry. Returns True on success, False on error."""
    source = entry["source"]
    entry_type = entry.get("type", "doc")

    print(f"\n  [{entry_type.upper():12s}] {source}")
    print(f"  {'':12s}   -> \"{full_title}\"")
    print(f"  {'':12s}   parent: {parent_id}")

    xhtml, err = resolve_content(entry, base_dir)
    if err:
        print(f"  {'':12s}   !! {err}")
        return False

    content_len = len(xhtml) if xhtml else 0
    print(f"  {'':12s}   content: {content_len} chars XHTML")

    if dry_run:
        print(f"  {'':12s}   (dry-run: skipped)")
        return True

    try:
        page_id, action = publish_page(cfg, full_title, xhtml, parent_id)
        print(f"  {'':12s}   {action} -> page id: {page_id}")
        return True
    except SystemExit:
        return False


def _publish_group_parent(cfg, group, full_title, parent_id, base_dir, dry_run):
    """Create or update a group parent page. Returns page id.

    If the group dict contains a ``source`` key the file content is used as
    the page body.  Otherwise a placeholder with a children macro is generated.
    """
    source = group.get("source")
    if source:
        entry_stub = {"source": source, "type": group.get("type", "doc")}
        body, err = resolve_content(entry_stub, base_dir)
        if err:
            body = None
        if body:
            # append children macro so sub-pages are listed
            body += ('\n<hr/>'
                     '<ac:structured-macro ac:name="children">'
                     '<ac:parameter ac:name="sort">title</ac:parameter>'
                     '</ac:structured-macro>')
    else:
        body = None

    if not body:
        body = (f"<p>이 페이지는 <strong>{html_escape(full_title)}</strong>의 "
                f"하위 문서를 모아놓은 상위 페이지입니다.</p>"
                f'<ac:structured-macro ac:name="children">'
                f'<ac:parameter ac:name="sort">title</ac:parameter>'
                f'</ac:structured-macro>')

    src_label = source or "(generated)"
    print(f"\n  [{'GROUP':12s}] {src_label}")
    print(f"  {'':12s}   -> \"{full_title}\"")
    print(f"  {'':12s}   parent: {parent_id}")
    print(f"  {'':12s}   content: {len(body)} chars XHTML")

    if dry_run:
        print(f"  {'':12s}   (dry-run: skipped)")
        return None

    try:
        page_id, action = publish_page(cfg, full_title, body, parent_id)
        print(f"  {'':12s}   {action} -> page id: {page_id}")
        return page_id
    except SystemExit:
        return None


def main():
    parser = argparse.ArgumentParser(
        description="Publish docs and findings to Confluence Server/DC.",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Show what would be published without making API calls.",
    )
    parser.add_argument(
        "--map", default=None,
        help="Path to page map JSON (default: tools/confluence_page_map.json).",
    )
    parser.add_argument(
        "--base-dir", default=None,
        help="Base directory for resolving source paths (default: repo root).",
    )
    parser.add_argument(
        "--filter", default=None,
        help="Only publish entries matching this source path.",
    )
    args = parser.parse_args()

    # determine base directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.abspath(os.path.join(script_dir, "..", ".."))
    base_dir = args.base_dir or repo_root

    # load .env
    load_env(os.path.join(base_dir, ".env"))

    # load page map
    map_path = args.map or os.path.join(base_dir, "tools", "confluence_page_map.json")
    if not os.path.isfile(map_path):
        print(f"[ERROR] Page map not found: {map_path}", file=sys.stderr)
        sys.exit(1)

    with open(map_path, encoding="utf-8") as fh:
        page_map = json.load(fh)

    prefix = page_map.get("prefix", "")
    root_page = page_map.get("root_page")
    entries = page_map.get("entries", [])
    groups = page_map.get("groups", [])

    # apply filter
    publish_root = True
    def _filter_groups(grps, filt):
        """Recursively filter groups by source path."""
        filtered = []
        for g in grps:
            gc = dict(g)
            gc["entries"] = [e for e in gc.get("entries", [])
                             if e["source"] == filt]
            gc["groups"] = _filter_groups(gc.get("groups", []), filt)
            if gc["entries"] or gc["groups"] or gc.get("source") == filt:
                filtered.append(gc)
        return filtered

    if args.filter:
        publish_root = (root_page and root_page.get("source") == args.filter)
        entries = [e for e in entries if e["source"] == args.filter]
        groups = _filter_groups(groups, args.filter)
        if not entries and not groups and not publish_root:
            print(f"[WARN] No entries match filter: {args.filter}", file=sys.stderr)
            sys.exit(0)
    else:
        publish_root = root_page is not None

    def _count_group_entries(grps):
        """Recursively count all publishable entries in groups."""
        n = 0
        for g in grps:
            n += len(g.get("entries", []))
            n += _count_group_entries(g.get("groups", []))
        return n

    total = len(entries) + _count_group_entries(groups)
    if publish_root:
        total += 1

    if not args.dry_run:
        cfg = get_config()
    else:
        cfg = None

    print(f"{'[DRY-RUN] ' if args.dry_run else ''}Publishing {total} entries "
          f"+ {len(groups)} group(s) (prefix: \"{prefix}\")")
    print("-" * 60)

    success = 0
    errors = 0
    root_parent = cfg["parent_id"] if cfg else "ROOT"

    # --- root page (update the parent page itself) ---
    if publish_root and root_page:
        print(f"\n{'='*40}")
        print(f"  Root page")
        print(f"{'='*40}")
        root_entry = {"source": root_page["source"],
                      "type": root_page.get("type", "doc")}
        xhtml, err = resolve_content(root_entry, base_dir)

        src = root_page["source"]
        print(f"\n  [{'ROOT':12s}] {src}")
        print(f"  {'':12s}   -> page id: {root_parent}")

        if err:
            print(f"  {'':12s}   !! {err}")
            errors += 1
        elif args.dry_run:
            print(f"  {'':12s}   content: {len(xhtml)} chars XHTML")
            print(f"  {'':12s}   (dry-run: skipped)")
            success += 1
        else:
            # append children macro so sub-pages are listed
            xhtml += ('\n<hr/>'
                      '<ac:structured-macro ac:name="children">'
                      '<ac:parameter ac:name="sort">title</ac:parameter>'
                      '</ac:structured-macro>')
            try:
                # directly update the root parent page by its known id
                params = urllib.parse.urlencode({"expand": "version"})
                page_info = confluence_api(
                    cfg, "GET",
                    f"/rest/api/content/{root_parent}?{params}")
                ver = page_info["version"]["number"]
                title = page_info["title"]
                update_page(cfg, root_parent, title, xhtml, ver)
                print(f"  {'':12s}   content: {len(xhtml)} chars XHTML")
                print(f"  {'':12s}   updated -> page id: {root_parent}")
                success += 1
            except SystemExit:
                errors += 1

    # --- flat entries (docs) under root parent ---
    if entries:
        print(f"\n{'='*40}")
        print(f"  Top-level entries ({len(entries)})")
        print(f"{'='*40}")
    for entry in entries:
        raw_title = entry["title"]
        full_title = f"{prefix} {raw_title}" if prefix else raw_title
        ok = _publish_entry(cfg, entry, full_title, root_parent,
                            base_dir, args.dry_run)
        success += ok
        errors += (not ok)

    # --- groups (findings under group parent, supports nesting) ---
    def _publish_groups(grps, parent_id, depth=0):
        nonlocal success, errors
        for group in grps:
            group_raw_title = group["title"]
            group_full_title = f"{prefix} {group_raw_title}" if prefix else group_raw_title
            group_entries = group.get("entries", [])
            sub_groups = group.get("groups", [])
            child_count = len(group_entries) + _count_group_entries(sub_groups)

            indent = "  " * depth
            print(f"\n{indent}{'='*40}")
            print(f"{indent}  Group: \"{group_full_title}\" ({child_count} entries)")
            print(f"{indent}{'='*40}")

            group_parent_id = _publish_group_parent(
                cfg, group, group_full_title, parent_id, base_dir, args.dry_run)

            if not args.dry_run and group_parent_id is None:
                print(f"{indent}  !! Failed to create group parent, skipping children")
                errors += len(group_entries) + _count_group_entries(sub_groups)
                continue

            child_parent = group_parent_id if group_parent_id else "GROUP"

            for entry in group_entries:
                raw_title = entry["title"]
                full_title = f"{prefix} {raw_title}" if prefix else raw_title
                ok = _publish_entry(cfg, entry, full_title, child_parent,
                                    base_dir, args.dry_run)
                success += ok
                errors += (not ok)

            if sub_groups:
                _publish_groups(sub_groups, child_parent, depth + 1)

    _publish_groups(groups, root_parent)

    print("\n" + "=" * 60)
    print(f"Done. {success} succeeded, {errors} failed out of {total} entries.")

    if errors > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
