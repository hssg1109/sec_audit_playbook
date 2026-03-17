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
from pathlib import Path

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
                f'<ac:structured-macro ac:name="anchor" ac:schema-version="1">'
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
                f'<ac:structured-macro ac:name="anchor" ac:schema-version="1">'
                f'<ac:parameter ac:name="name">{name}</ac:parameter>'
                f'</ac:structured-macro>'
            )
        # First unwrap from <p> tags (markdown library wraps block-level tokens)
        xhtml = re.sub(r'<p>\[\[ANCHOR:([^\]]+)\]\]</p>', repl, xhtml)
        # Then handle any remaining inline occurrences
        xhtml = re.sub(r'\[\[ANCHOR:([^\]]+)\]\]', repl, xhtml)
        return xhtml

    def _strip_html_tags(html_str: str) -> str:
        """Remove HTML tags, leaving plain text for Confluence macro parameter."""
        return re.sub(r'<[^>]+>', '', html_str)

    def _preprocess_expand_blocks(text: str, store: dict) -> str:
        """Iteratively replace innermost <details><summary>...</summary>...</details>
        blocks with [[EXPAND:N]] placeholder tokens (bottom-up for nested blocks).

        The pattern uses a negative lookahead (?!<details>) to ensure only truly
        innermost blocks (those whose body contains no further <details> tag) are
        matched in each pass, guaranteeing correct bottom-up expansion.
        """
        counter = [0]
        # Group 1: title — stops at first </summary> (no lookahead-through allowed).
        # Group 2: body  — stops if a nested <details> opener is encountered,
        #   ensuring only truly innermost blocks are matched each pass.
        pattern = re.compile(
            r'<details>\s*<summary>'
            r'((?:(?!</summary>).)*?)'   # group 1: title (no </summary> inside)
            r'</summary>'
            r'((?:(?!<details>).)*?)'    # group 2: body  (no <details> inside)
            r'</details>',
            re.DOTALL | re.IGNORECASE,
        )

        def _replace(m):
            title_html = m.group(1).strip()
            content_md = m.group(2).strip()
            key = f"[[EXPAND:{counter[0]}]]"
            counter[0] += 1
            store[key] = (_strip_html_tags(title_html), content_md)
            return key

        while True:
            new_text = pattern.sub(_replace, text)
            if new_text == text:
                break
            text = new_text
        return text

    # expand_store is shared by closures below so nested tokens resolve correctly.
    expand_store: dict = {}

    def _postprocess_code_blocks(xhtml: str) -> str:
        """Convert <pre><code class="language-X"> output (from markdown library)
        to Confluence code macros with theme and title.

        The markdown library converts ```lang\\n...\\n``` to
        <pre><code class="language-lang">...</code></pre>.
        This step replaces those with proper ac:structured-macro code blocks.
        """
        import html as _html_module

        def _repl(m: re.Match) -> str:
            cls  = m.group(1) or ""
            body = _html_module.unescape(m.group(2))
            # "language-java" → "java", "language-properties" → "properties"
            lang_m = re.search(r'(?:language-)?(\w+)', cls)
            raw_lang = lang_m.group(1) if lang_m else "text"
            # Confluence가 지원하지 않는 언어 힌트(properties, kotlin 등)는 "text"로 정규화
            lang = raw_lang if raw_lang in _CONFLUENCE_VALID_LANGS else "text"
            return _code_macro(body, lang)

        return re.sub(
            r'<pre><code(?:\s+class="([^"]*)")?>(.*?)</code></pre>',
            _repl,
            xhtml,
            flags=re.DOTALL,
        )

    def _convert_body(content_md: str) -> str:
        """Convert body markdown (may contain [[EXPAND:N]] tokens) to XHTML.
        Uses the shared expand_store so nested expand blocks are resolved."""
        try:
            body = _md_to_xhtml_lib(content_md)
        except ImportError:
            body = _md_to_xhtml_fallback(content_md)
        body = _postprocess_code_blocks(body)
        body = _postprocess_anchors(body)
        body = _postprocess_expand_blocks(body)
        return body

    def _postprocess_expand_blocks(xhtml: str) -> str:
        """Replace [[EXPAND:N]] tokens with Confluence Expand structured macros.
        Uses the shared expand_store (closure) so nested tokens are resolved."""
        def _replace(m):
            key = m.group(0)
            title, content_md = expand_store[key]
            body_xhtml = _convert_body(content_md)
            title_escaped = html_escape(title)
            return (
                f'<ac:structured-macro ac:name="expand">'
                f'<ac:parameter ac:name="title">{title_escaped}</ac:parameter>'
                f'<ac:rich-text-body>{body_xhtml}</ac:rich-text-body>'
                f'</ac:structured-macro>'
            )
        return re.sub(r'\[\[EXPAND:\d+\]\]', _replace, xhtml)

    # Confluence XML namespace tags (ac:*, ri:*) must survive the markdown→XHTML
    # pass unchanged. Extract them into a passthrough store before conversion.
    passthrough_store: dict = {}
    passthrough_counter = [0]
    # Match any block-level Confluence macro tag (single-line or multi-line)
    _ac_pattern = re.compile(r'<(?:ac:|ri:)\S[^>]*>(?:.*?</(?:ac:|ri:)\S+>)?', re.DOTALL)

    def _preprocess_passthrough(text: str) -> str:
        def _repl(m):
            key = f"[[PASSTHROUGH:{passthrough_counter[0]}]]"
            passthrough_counter[0] += 1
            passthrough_store[key] = m.group(0)
            return key
        return _ac_pattern.sub(_repl, text)

    def _postprocess_passthrough(xhtml: str) -> str:
        def _repl(m):
            return passthrough_store.get(m.group(0), m.group(0))
        # After markdown conversion the token may be inside <p>…</p>; unwrap it.
        def _repl_unwrap(m):
            raw = passthrough_store.get(m.group(1), m.group(1))
            return raw
        xhtml = re.sub(r'<p>\[\[PASSTHROUGH:(\d+)\]\]</p>', _repl_unwrap, xhtml)
        xhtml = re.sub(r'\[\[PASSTHROUGH:(\d+)\]\]',
                       lambda m: passthrough_store.get(f"[[PASSTHROUGH:{m.group(1)}]]", m.group(0)),
                       xhtml)
        return xhtml

    def _postprocess_escape_foreign_ns(xhtml: str) -> str:
        """Escape XML namespace-prefixed tags that Confluence does not recognise.

        Confluence XHTML accepts only ac: and ri: namespace prefixes.
        Tags like <c:out>, <fmt:message>, <spring:url> (JSTL/Spring) would
        cause a 400 "Undeclared namespace prefix" error.  Escape them so they
        render as visible text rather than XML elements.
        """
        # Match opening, closing, and self-closing tags with a namespace prefix
        # that is NOT ac: or ri: (Confluence built-ins).
        # Runs outside <code> blocks — those are already protected by CDATA or
        # the Confluence code macro which treats content as text.
        pattern = re.compile(
            r'<(/?)(?!ac:|ri:|!|/?\s*>)([a-zA-Z][a-zA-Z0-9]*):([^>]*?)(/?)>',
        )
        def _escape_tag(m):
            slash_open  = m.group(1)
            ns          = m.group(2)
            rest        = m.group(3)
            slash_close = m.group(4)
            raw = f"<{slash_open}{ns}:{rest}{slash_close}>"
            return html_escape(raw)
        return pattern.sub(_escape_tag, xhtml)

    def _postprocess_anchor_links(xhtml: str) -> str:
        """Convert raw <a href="#anchor-name">text</a> fragment links to
        Confluence ac:link anchor macros so in-page scroll navigation works.

        Confluence does not honour raw HTML href="#..." for anchors defined
        via ac:anchor macros.  The proper storage-format equivalent is:
          <ac:link ac:anchor="name">
            <ac:plain-text-link-body><![CDATA[text]]></ac:plain-text-link-body>
          </ac:link>
        """
        def repl(m):
            anchor = html_escape(m.group(1))
            text = m.group(2)
            return (
                f'<ac:link ac:anchor="{anchor}">'
                f'<ac:plain-text-link-body><![CDATA[{text}]]></ac:plain-text-link-body>'
                f'</ac:link>'
            )
        return re.sub(r'<a\b[^>]*\shref="#([^"]+)"[^>]*>([^<]*)</a>', repl, xhtml)

    # Standard HTML tags allowed in XHTML — must NOT be escaped.
    _KNOWN_HTML_TAGS = frozenset({
        'a', 'abbr', 'acronym', 'address', 'article', 'aside', 'b', 'blockquote',
        'br', 'caption', 'cite', 'code', 'col', 'colgroup', 'dd', 'del', 'details',
        'dfn', 'div', 'dl', 'dt', 'em', 'figcaption', 'figure', 'footer', 'h1', 'h2',
        'h3', 'h4', 'h5', 'h6', 'head', 'header', 'hr', 'html', 'i', 'img', 'ins',
        'kbd', 'li', 'main', 'mark', 'nav', 'ol', 'p', 'pre', 'q', 's', 'samp',
        'section', 'small', 'span', 'strong', 'sub', 'summary', 'sup', 'table',
        'tbody', 'td', 'tfoot', 'th', 'thead', 'time', 'title', 'tr', 'tt', 'u',
        'ul', 'var', 'wbr',
    })

    def _postprocess_escape_unknown_tags(xhtml: str) -> str:
        """Escape any XML tag whose name is not a known HTML element and not an
        ac:/ri: Confluence namespace tag.

        This catches Java generic type notation that leaked into paragraph text,
        e.g.  ResponseEntity<String> → ResponseEntity&lt;String&gt;
        Confluence code macros use CDATA so their content is never reached here.
        """
        # Match opening/closing/self-closing tags: <TagName ...> </TagName> <TagName/>
        tag_re = re.compile(
            r'<(/?)([A-Za-z][A-Za-z0-9_]*)(\s[^>]*)?(/)?>',
            re.DOTALL,
        )
        def _escape_if_unknown(m):
            slash_open  = m.group(1)   # "/" for closing tag, else ""
            tag_name    = m.group(2)
            attrs       = m.group(3) or ""
            slash_close = m.group(4) or ""
            tag_lower   = tag_name.lower()
            # Keep known HTML tags and ac:/ri: namespace tags (already handled
            # by _postprocess_escape_foreign_ns for ns: prefixes).
            if tag_lower in _KNOWN_HTML_TAGS:
                return m.group(0)
            # Keep anything that looks like a Confluence/XML namespace (contains colon).
            if ':' in tag_name:
                return m.group(0)
            # Escape everything else (Java generics, Spring tags without ns, etc.)
            raw = f"<{slash_open}{tag_name}{attrs}{slash_close}>"
            return html_escape(raw)
        return tag_re.sub(_escape_if_unknown, xhtml)

    md_text = _preprocess_anchors(md_text)
    md_text = _preprocess_expand_blocks(md_text, expand_store)
    md_text = _preprocess_passthrough(md_text)
    try:
        xhtml = _md_to_xhtml_lib(md_text)
    except ImportError:
        xhtml = _md_to_xhtml_fallback(md_text)
    xhtml = _postprocess_code_blocks(xhtml)   # <pre><code> → Confluence code macro
    xhtml = _postprocess_anchors(xhtml)
    xhtml = _postprocess_expand_blocks(xhtml)
    xhtml = _postprocess_passthrough(xhtml)
    xhtml = _postprocess_escape_foreign_ns(xhtml)
    xhtml = _postprocess_escape_unknown_tags(xhtml)
    xhtml = _postprocess_anchor_links(xhtml)
    return xhtml

# ---------------------------------------------------------------------------
# JSON -> XHTML helpers
# ---------------------------------------------------------------------------

_CODE_THEME = "RDark"  # Confluence 코드블록 기본 테마 (RDark: 시인성 좋은 다크 테마)

# 파일 확장자 → Confluence code macro language 매핑
_EXT_TO_LANG = {
    ".java": "java", ".kt": "java", ".kts": "groovy",
    ".xml": "xml", ".yml": "yaml", ".yaml": "yaml",
    ".json": "javascript", ".properties": "text",
    ".sql": "sql", ".py": "python",
    ".js": "javascript", ".ts": "javascript",
    ".sh": "bash", ".groovy": "groovy", ".gradle": "groovy",
    ".html": "html", ".jsp": "html",
}

# Confluence code macro가 인식하는 유효 언어 목록.
# 이 목록 외의 언어는 "text"(plain text)로 정규화한다.
_CONFLUENCE_VALID_LANGS = {
    "java", "python", "sql", "xml", "html", "javascript",
    "groovy", "bash", "scala", "yaml", "css", "none", "text",
    "cpp", "csharp", "php", "ruby", "diff", "powershell",
    "actionscript3", "coldfusion", "delphi", "erlang", "sass",
}


def _lang_for_file(filename: str) -> str:
    """파일 확장자에서 Confluence code macro language 결정."""
    if not filename:
        return "text"
    ext = Path(filename).suffix.lower()
    return _EXT_TO_LANG.get(ext, "text")


def _code_macro(code_text: str, lang: str = "text", theme: str = _CODE_THEME) -> str:
    """Wrap code in Confluence code macro.

    MD 코드블록의 첫 줄이 'FILE: <path>' 형식이면 title 파라미터로 추출.
    테마와 제목이 포함된 Confluence Storage Format 반환.
    """
    # FILE: 첫 줄 → title 추출
    title = ""
    lines = code_text.split("\n")
    if lines and lines[0].startswith("FILE: "):
        title = lines[0][6:].strip()
        code_text = "\n".join(lines[1:]).lstrip("\n")
        # 언어가 text이면 파일명으로 재탐지
        if lang == "text":
            lang = _lang_for_file(title.split(":")[0])  # "path/to/File.java:42" → "java"

    safe = code_text.replace("]]>", "]] >")
    params = (
        f'<ac:parameter ac:name="language">{html_escape(lang)}</ac:parameter>'
        f'<ac:parameter ac:name="theme">{html_escape(theme)}</ac:parameter>'
    )
    if title:
        params += f'<ac:parameter ac:name="title">{html_escape(title)}</ac:parameter>'
    return (
        f'<ac:structured-macro ac:name="code">'
        + params
        + f'<ac:plain-text-body><![CDATA[{safe}]]></ac:plain-text-body>'
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


def _method_badge(method: str) -> str:
    """Return a Confluence-compatible HTTP method badge using the Status macro.

    Uses <ac:structured-macro ac:name="status"> (same pattern as _severity_badge)
    so it works on all Confluence instances without requiring inline CSS support.

    Colour mapping (Swagger-inspired, Confluence status macro colours):
      GET → Blue, POST → Green, PUT → Yellow, DELETE → Red,
      PATCH → Purple, HEAD/OPTIONS → Grey
    """
    _METHOD_COLOUR = {
        "GET":     "Blue",
        "POST":    "Green",
        "PUT":     "Yellow",
        "DELETE":  "Red",
        "PATCH":   "Purple",
        "HEAD":    "Grey",
        "OPTIONS": "Grey",
    }
    m = method.upper()
    colour = _METHOD_COLOUR.get(m, "Grey")
    return (
        f'<ac:structured-macro ac:name="status">'
        f'<ac:parameter ac:name="colour">{colour}</ac:parameter>'
        f'<ac:parameter ac:name="title">{html_escape(m)}</ac:parameter>'
        f'</ac:structured-macro>'
    )


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

    # --- 엔드포인트: 모듈 → 컨트롤러별 그룹화 (Swagger tag 구조) ---
    endpoints = data.get("endpoints", [])
    if not endpoints:
        return "\n".join(parts)

    # 그룹 빌드: {module: {controller: [ep, ...]}}
    from collections import defaultdict
    by_module: dict = defaultdict(lambda: defaultdict(list))
    for ep in endpoints:
        module = ep.get("module", "unknown")
        handler = ep.get("handler", "")
        # "ControllerName.methodName()" → "ControllerName"
        ctrl = handler.split(".")[0] if handler else "Unknown"
        by_module[module][ctrl].append(ep)

    # 모듈별 요약 TOC 테이블
    parts.append("<h2>엔드포인트 현황 (모듈별)</h2>")
    method_order = ["GET", "POST", "PUT", "PATCH", "DELETE"]
    toc_rows = []
    for mod in sorted(by_module):
        ctrls = by_module[mod]
        total = sum(len(v) for v in ctrls.values())
        m_counts = {}
        for eps_list in ctrls.values():
            for ep in eps_list:
                m = ep.get("method", "").upper()
                m_counts[m] = m_counts.get(m, 0) + 1
        method_cells = " ".join(
            f'{_method_badge(m)} <strong>{m_counts[m]}</strong>'
            for m in method_order if m in m_counts
        )
        toc_rows.append([
            f"<strong>{html_escape(mod)}</strong>",
            str(len(ctrls)),
            f"<strong>{total}</strong>",
            method_cells or "-",
        ])
    parts.append(_table(["모듈", "컨트롤러", "전체 엔드포인트", "HTTP 메서드 분포"], toc_rows))

    # 모듈 → 컨트롤러 → 엔드포인트(expand) 계층 렌더링
    parts.append("<h2>API 레퍼런스</h2>")
    for mod in sorted(by_module):
        parts.append(f"<h3>📦 {html_escape(mod)}</h3>")
        ctrls = by_module[mod]
        for ctrl in sorted(ctrls):
            eps_list = ctrls[ctrl]
            parts.append(
                f"<h4>{html_escape(ctrl)} "
                f"<em style='font-weight:normal;color:#555;'>({len(eps_list)}건)</em></h4>"
            )
            # 컨트롤러 내 빠른 목록 (non-expand 요약 행)
            quick_rows = []
            for ep in eps_list:
                method = ep.get("method", "")
                api = ep.get("api", "")
                desc = ep.get("description", "") or ""
                handler_m = html_escape(ep.get("handler", "").split(".", 1)[-1].rstrip("()"))
                quick_rows.append([
                    _method_badge(method),
                    f"<code>{html_escape(api)}</code>",
                    f"<code>{handler_m}()</code>",
                    html_escape(desc) if desc else "-",
                ])
            parts.append(_table(["Method", "Path", "메서드", "설명"], quick_rows))

            # 엔드포인트 상세 — Confluence expand macro 1개씩
            for ep in eps_list:
                method   = ep.get("method", "")
                api      = ep.get("api", "")
                handler  = html_escape(ep.get("handler", ""))
                desc     = ep.get("description", "") or ""
                file_loc = html_escape(ep.get("file", ""))
                line     = ep.get("line", "")
                ret_type = ep.get("return_type", "") or ""
                auth_req = ep.get("auth_required", False)
                auth_det = ep.get("auth_detail", "") or ""
                mw_list  = ep.get("middleware", [])

                # expand 제목: plain text only (ac:parameter는 HTML 마크업 불허)
                api_display = api if api.startswith("/") else f"/{api}"
                expand_title = html_escape(f"{method}  {api_display}")

                body: list[str] = []
                # 메서드 배지 + 경로 (expand 내부 상단에 표시)
                body.append(
                    f"<p>{_method_badge(method)}&nbsp;"
                    f"<code><strong>{html_escape(api_display)}</strong></code></p>"
                )
                # 핸들러 + 위치
                body.append(
                    f"<p><strong>핸들러:</strong> <code>{handler}</code><br/>"
                    f"<strong>위치:</strong> <code>{file_loc}:{line}</code></p>"
                )
                # 인증 (Confluence status 매크로 사용 — span style 불허)
                if auth_req:
                    auth_label = (
                        '<ac:structured-macro ac:name="status">'
                        '<ac:parameter ac:name="colour">Red</ac:parameter>'
                        '<ac:parameter ac:name="title">인증 필수</ac:parameter>'
                        '</ac:structured-macro>'
                    )
                else:
                    auth_label = (
                        '<ac:structured-macro ac:name="status">'
                        '<ac:parameter ac:name="colour">Green</ac:parameter>'
                        '<ac:parameter ac:name="title">인증 불필요</ac:parameter>'
                        '</ac:structured-macro>'
                    )
                auth_line = auth_label
                if auth_det:
                    auth_line += f' <code>{html_escape(auth_det)}</code>'
                body.append(f"<p><strong>인증:</strong> {auth_line}</p>")
                # 설명
                if desc:
                    body.append(f"<p><strong>설명:</strong> {html_escape(desc)}</p>")
                # 응답 타입
                if ret_type and ret_type not in ("unknown", ""):
                    body.append(f"<p><strong>응답 타입:</strong> <code>{html_escape(ret_type)}</code></p>")
                # 미들웨어
                if mw_list:
                    mw_str = ", ".join(f"<code>{html_escape(m)}</code>" for m in mw_list)
                    body.append(f"<p><strong>미들웨어:</strong> {mw_str}</p>")

                # 파라미터
                params = [p for p in ep.get("parameters", [])
                          if p.get("type") not in ("request", "response", "exchange")]
                if params:
                    body.append("<p><strong>파라미터</strong></p>")
                    p_rows = []
                    for p in params:
                        req_str = "✅ 필수" if p.get("required") else "-"
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
                    body.append(_table(["파라미터", "출처", "데이터 타입", "필수", "기본값"], p_rows))

                    # DTO resolved fields (Request Body 스키마)
                    for p in params:
                        resolved_fields = p.get("resolved_fields", [])
                        if resolved_fields:
                            rf_from = html_escape(str(p.get("resolved_from", p.get("data_type", ""))))
                            p_name  = html_escape(str(p.get("name", "")))
                            body.append(
                                f"<p><em>Request Body 스키마 — "
                                f"<code>{p_name}</code> (<code>{rf_from}</code>):</em></p>"
                            )
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
                            body.append(_table(["필드", "타입", "어노테이션", "Nullable"], rf_rows))
                elif not params:
                    body.append("<p><em>파라미터 없음 (HttpServletRequest 직접 처리)</em></p>")

                body_html = "\n".join(body)
                # Confluence Expand 매크로 (펼치기) — title은 plain text만
                parts.append(
                    '<ac:structured-macro ac:name="expand">'
                    f'<ac:parameter ac:name="title">{expand_title}</ac:parameter>'
                    f'<ac:rich-text-body>{body_html}</ac:rich-text-body>'
                    '</ac:structured-macro>'
                )

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
                lang = _lang_for_file(efile_name)
                elines_val = evidence.get("lines", "")
                ev_title = Path(efile_name).name if efile_name else ""
                if elines_val:
                    ev_title += f"  (line {elines_val})"
                parts.append(_confluence_code_block(snippet, lang, title=ev_title))

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


def _render_sqli_endpoint_review(review: dict) -> str:
    """sqli_endpoint_review 블록을 XHTML 섹션으로 렌더링."""
    parts = []
    total = review.get("total_info_endpoints", 0)
    overall = review.get("overall_sqli_judgment", "")
    rationale = review.get("rationale", "")
    reviewed_at = review.get("reviewed_at", "")

    overall_color = "green" if overall == "양호" else ("red" if overall == "취약" else "orange")
    parts.append(
        f'<h2>🔍 LLM 수동분석 — SQL 인젝션 정보 엔드포인트 검토 결과</h2>'
        f'<p>검토 엔드포인트: <strong>{total}건</strong> | '
        f'전체 판정: <strong style="color:{overall_color}">{html_escape(overall)}</strong>'
        + (f' | 검토일: {html_escape(reviewed_at[:10])}' if reviewed_at else '') + '</p>'
    )
    if rationale:
        parts.append(
            '<ac:structured-macro ac:name="note"><ac:rich-text-body>'
            f'<p><strong>판정 근거:</strong> {html_escape(rationale)}</p>'
            '</ac:rich-text-body></ac:structured-macro>'
        )

    for gj in review.get("group_judgments", []):
        group_name = gj.get("group", "")
        judgment = gj.get("judgment", "")
        j_color = "green" if judgment == "양호" else ("red" if judgment == "취약" else "orange")
        parts.append(
            f'<h3>{html_escape(group_name)} — '
            f'<span style="color:{j_color}">{html_escape(judgment)}</span></h3>'
        )

        # services_reviewed (외부의존성 그룹)
        svc_rows = []
        for s in gj.get("services_reviewed", []):
            r = s.get("result", "")
            rc = "green" if r == "양호" else ("red" if r == "취약" else "orange")
            svc_rows.append([
                html_escape(s.get("service", "")),
                html_escape(s.get("dao", "")),
                html_escape(s.get("finding", "")),
                f'<span style="color:{rc}"><strong>{html_escape(r)}</strong></span>',
            ])
        if svc_rows:
            parts.append(_table(["서비스", "DAO / 매퍼", "검토 근거", "판정"], svc_rows))

        # daos_reviewed (XML 미발견 그룹)
        dao_rows = []
        for d in gj.get("daos_reviewed", []):
            r = d.get("result", "")
            rc = "green" if r == "양호" else ("red" if r == "취약" else "orange")
            dao_rows.append([
                html_escape(d.get("dao", "")),
                html_escape(d.get("xml", "")),
                html_escape(d.get("finding", "")),
                f'<span style="color:{rc}"><strong>{html_escape(r)}</strong></span>',
            ])
        if dao_rows:
            parts.append(_table(["DAO", "XML 매퍼", "검토 근거", "판정"], dao_rows))

    return "\n".join(parts)


def _render_xss_endpoint_review(review: dict) -> str:
    """xss_endpoint_review 블록을 XHTML 섹션으로 렌더링."""
    parts = []
    total = review.get("total_info_endpoints", 0)
    overall = review.get("overall_xss_info_judgment", "")
    reviewed_at = review.get("reviewed_at", "")

    overall_color = "green" if "양호" in overall else ("red" if "취약" in overall else "orange")
    parts.append(
        f'<h2>🔍 LLM 수동분석 — XSS 정보 엔드포인트 검토 결과</h2>'
        f'<p>검토 엔드포인트: <strong>{total}건</strong> | '
        f'전체 판정: <strong style="color:{overall_color}">{html_escape(overall)}</strong>'
        + (f' | 검토일: {html_escape(reviewed_at[:10])}' if reviewed_at else '') + '</p>'
    )

    for gj in review.get("group_judgments", []):
        group_name = gj.get("group", "")
        judgment = gj.get("judgment", "")
        j_color = "green" if judgment == "양호" else ("red" if judgment == "취약" else "orange")
        rationale = gj.get("rationale", "")
        parts.append(
            f'<h3>{html_escape(group_name)} — '
            f'<span style="color:{j_color}">{html_escape(judgment)}</span></h3>'
        )
        if rationale:
            parts.append(f'<p>{html_escape(rationale)}</p>')

        # controllers_reviewed (HTML_VIEW 미탐지 그룹)
        ctrl_rows = []
        for c in gj.get("controllers_reviewed", []):
            r = c.get("result", "")
            rc = "green" if r == "양호" else ("red" if r == "취약" else "orange")
            ctrl_rows.append([
                html_escape(c.get("controller", "")),
                html_escape(c.get("return_type", "")),
                html_escape(c.get("finding", "")),
                f'<span style="color:{rc}"><strong>{html_escape(r)}</strong></span>',
            ])
        if ctrl_rows:
            parts.append(_table(["컨트롤러", "반환 타입", "검토 근거", "판정"], ctrl_rows))

        # endpoints_reviewed (Reflected XSS 그룹)
        ep_rows = []
        for e in gj.get("endpoints_reviewed", []):
            r = e.get("result", "")
            rc = "green" if r == "양호" else ("red" if r == "취약" else "orange")
            ep_rows.append([
                html_escape(e.get("endpoint", "")),
                html_escape(e.get("finding", "")),
                f'<span style="color:{rc}"><strong>{html_escape(r)}</strong></span>',
            ])
        if ep_rows:
            parts.append(_table(["엔드포인트", "검토 근거", "판정"], ep_rows))

    return "\n".join(parts)


def _json_to_xhtml_supp_findings(data: dict) -> str:
    """LLM 수동분석 보완 JSON(findings 배열)을 자동스캔 finding 페이지에 통합하는
    섹션 렌더러. 자동스캔 XHTML 끝에 추가된다.

    - 섹션 제목: '🔍 LLM 수동분석 보완 (Phase 3)'
    - finding 카드: id / severity / description / evidence / recommendation
    - sqli_endpoint_review / xss_endpoint_review: LLM 정보 엔드포인트 검토 결과 테이블
    """
    findings = data.get("findings", [])
    sqli_review = data.get("sqli_endpoint_review")
    xss_review = data.get("xss_endpoint_review")

    if not findings and not sqli_review and not xss_review:
        return ""

    task_id = data.get("task_id", "")
    parts = []

    if findings:
        parts.append(
            '<ac:structured-macro ac:name="info">'
            '<ac:rich-text-body>'
            '<p><strong>🔍 LLM 수동분석 보완 (Phase 3)</strong> — '
            f'자동스캔 이후 수동 심층진단으로 확정된 취약점 {len(findings)}건입니다. '
            '아래 항목은 자동스캔 결과를 보완하며, 위 스캔 결과와 함께 최종 판정으로 간주합니다.</p>'
            '</ac:rich-text-body></ac:structured-macro>'
        )

        # 심각도 요약 테이블
        sev_count: dict[str, int] = {}
        for f in findings:
            sev = f.get("severity", "Unknown")
            sev_count[sev] = sev_count.get(sev, 0) + 1
        if sev_count:
            s_rows = [[_severity_badge(sev), str(cnt)]
                      for sev in ["Critical", "High", "Medium", "Low", "Info"]
                      if (cnt := sev_count.get(sev, 0))]
            parts.append(_table(["심각도", "건수"], s_rows))

        for f in findings:
            sev  = f.get("severity", "")
            fid  = html_escape(str(f.get("id", "")))
            title = html_escape(str(f.get("title", "")))
            result = f.get("result", "")
            result_badge = (
                "<strong style='color:red'>취약</strong>" if result == "취약"
                else f"<strong style='color:orange'>{html_escape(result)}</strong>"
                if result else ""
            )
            parts.append(f"<h3>{fid} — {title} {_severity_badge(sev)}"
                         + (f" [{result_badge}]" if result_badge else "") + "</h3>")

            cat = f.get("category", "")
            if cat:
                parts.append(f"<p><strong>카테고리:</strong> {html_escape(cat)}</p>")
            desc = f.get("description", "")
            if desc:
                parts.append(f"<p><strong>설명:</strong> {html_escape(desc)}</p>")

            affected = f.get("affected_endpoint", "")
            if affected:
                parts.append(f"<p><strong>영향 범위:</strong> {html_escape(affected)}</p>")

            evidence = f.get("evidence", {})
            if evidence:
                if isinstance(evidence, list):
                    # list 형태 evidence: 텍스트 줄 목록
                    ev_text = "\n".join(str(e) for e in evidence)
                    parts.append(_code_macro(ev_text, "text"))
                else:
                    efile_raw = str(evidence.get("file", ""))
                    elines_raw = str(evidence.get("lines", ""))
                    efile = html_escape(efile_raw)
                    elines = html_escape(elines_raw)
                    if efile:
                        parts.append(f"<p><strong>증거:</strong> <code>{efile}:{elines}</code></p>")
                    snippet = evidence.get("code_snippet", "")
                    if snippet:
                        lang = _lang_for_file(efile_raw)
                        ev_title = Path(efile_raw).name if efile_raw else ""
                        if elines_raw:
                            ev_title += f"  (line {elines_raw})"
                        parts.append(_confluence_code_block(snippet, lang, title=ev_title))

            # taint_evidence: DB 저장 경로 코드 흐름 (Controller → Service → Repository)
            taint_evidence = f.get("taint_evidence", [])
            if taint_evidence:
                parts.append("<p><strong>DB 저장 경로 코드 흐름 (Taint Path)</strong></p>")
                for te in taint_evidence:
                    te_title = te.get("title", "Taint Path")
                    parts.append(f"<p><strong>{html_escape(te_title)}</strong></p>")
                    # Controller
                    for role, fkey, skey in [
                        ("Controller", "controller_file", "controller_snippet"),
                        ("Service",    "service_file",    "service_snippet"),
                        ("Repository", "repository_file", "repository_snippet"),
                    ]:
                        fpath = te.get(fkey, "")
                        snippet = te.get(skey, "")
                        if snippet:
                            flines = te.get(fkey.replace("_file", "_lines"), "")
                            t_label = Path(fpath).name if fpath else role
                            if flines:
                                t_label += f"  (line {flines})"
                            lang = _lang_for_file(fpath)
                            parts.append(_confluence_code_block(snippet, lang, title=t_label))

            note = f.get("manual_review_note", "")
            if note:
                parts.append(
                    '<ac:structured-macro ac:name="note">'
                    f'<ac:rich-text-body><p><strong>수동 검토 메모:</strong> '
                    f'{html_escape(note)}</p></ac:rich-text-body></ac:structured-macro>'
                )

            cwe   = f.get("cwe_id", "")
            owasp = f.get("owasp_category", "")
            if cwe or owasp:
                parts.append(f"<p><strong>CWE:</strong> {html_escape(cwe)} | "
                             f"<strong>OWASP:</strong> {html_escape(owasp)}</p>")

            rec = f.get("recommendation", "")
            if rec:
                parts.append(
                    '<ac:structured-macro ac:name="info">'
                    f'<ac:rich-text-body><p><strong>권고사항:</strong> '
                    f'{html_escape(rec)}</p></ac:rich-text-body></ac:structured-macro>'
                )

    # LLM 정보 엔드포인트 검토 결과 섹션
    if sqli_review:
        parts.append(_render_sqli_endpoint_review(sqli_review))
    if xss_review:
        parts.append(_render_xss_endpoint_review(xss_review))

    return "\n".join(parts)


# ============================================================
#  Enhanced Injection Report — Helper Functions
# ============================================================

_INTERNAL_TAG_RE = re.compile(
    r'\s*\[(?:non-DB method|non-DB|external|direct repo|from controller'
    r'|via [^\]]*|deprecated|JPA Repository[^\]]*)\]',
    re.IGNORECASE
)


def _clean_call(s: str) -> str:
    """Remove internal analysis tags from service/repo call strings."""
    return _INTERNAL_TAG_RE.sub('', s).strip()


def _simplify_category(ep: dict) -> str:
    """Map a diagnosis to a developer-friendly category name.

    취약:
      [실제 위협] SQL Injection       — 확인된 taint 경로 (HTTP 파라미터 → ${} 삽입)
      [잠재적 위협] 취약한 쿼리 구조   — 취약 구조이나 taint 미확인
    정보:
      외부 의존성 호출                 — external_module (외부 모듈 의존)
      XML 미발견 패턴 추정             — mybatis_safe + 추정 (XML 미발견)
      호출 경로 추적 불가              — 자동 추적 실패
      DB 접근 경로 미확인              — Service 호출 후 Repository 미추적
    양호:
      JPA & ORM 방식                  — JPA 내장 메서드 / @Query / ORM
      MyBatis #{} 바인딩              — MyBatis XML/어노테이션 #{} 바인딩
      DB 미접근 엔드포인트             — 비DB Service, 비DB 핸들러, 파라미터 없음
      제어 흐름상 안전                 — 기타 안전 패턴 (bind, criteria 등)
    """
    result = ep.get("result", "정보")
    dtype = ep.get("diagnosis_type", "")
    filter_type = ep.get("filter_type", "")

    if result == "취약":
        if "[실제]" in dtype:
            return "[실제 위협] SQL Injection"
        elif "[잠재]" in dtype:
            return "[잠재적 위협] 취약한 쿼리 구조"
        # Fallback: legacy diagnosis_type 값 대응
        ft = filter_type.lower()
        if "tosql" in ft or "utils.tosql" in dtype.lower():
            return "[잠재적 위협] 취약한 쿼리 구조"
        return "[실제 위협] SQL Injection"

    elif result == "정보":
        if "외부 의존성" in dtype:
            return "외부 의존성 호출"
        elif "XML 미발견" in dtype:
            return "XML 미발견 패턴 추정"
        elif "추적 불가" in dtype:
            return "호출 경로 추적 불가"
        elif "DB 접근 미확인" in dtype:
            return "DB 접근 경로 미확인"
        return "수동 검토 필요"

    else:  # 양호
        if "JPA" in dtype or "@Query" in dtype or "ORM" in dtype:
            return "JPA & ORM 방식"
        elif ("MyBatis" in dtype or "iBatis" in dtype
              or (filter_type.lower() == "mybatis" and "추정" not in dtype)):
            return "MyBatis #{} 바인딩"
        elif ("비DB" in dtype or "미접근" in dtype or "미호출" in dtype
              or "DB 없음" in dtype or "DB 접근 없음" in dtype
              or "유형4" in dtype or "파라미터없음" in dtype
              or "세션" in dtype or "deprecated" in dtype.lower()
              or "비활성" in dtype):
            return "DB 미접근 엔드포인트"
        return "제어 흐름상 안전"


def _confluence_code_block(content: str, language: str = "text",
                           title: str = "", theme: str = _CODE_THEME) -> str:
    """Render a Confluence code block macro (XHTML storage format).

    Args:
        content: 코드 본문
        language: Confluence 언어 식별자 (java / xml / python 등)
        title: 코드블록 상단 제목 (파일명 표시용)
        theme: Confluence 코드 테마 (기본: RDark)
    """
    safe = content.replace("]]>", "]] >")
    params = (
        f'<ac:parameter ac:name="language">{html_escape(language)}</ac:parameter>'
        f'<ac:parameter ac:name="theme">{html_escape(theme)}</ac:parameter>'
    )
    if title:
        params += f'<ac:parameter ac:name="title">{html_escape(title)}</ac:parameter>'
    return (
        f'<ac:structured-macro ac:name="code">'
        + params
        + f'<ac:plain-text-body><![CDATA[{safe}]]></ac:plain-text-body>'
        f'</ac:structured-macro>'
    )


def _confluence_expand(title: str, content: str) -> str:
    """Render a Confluence expand (accordion) macro."""
    return (
        f'<ac:structured-macro ac:name="expand">'
        f'<ac:parameter ac:name="title">{html_escape(title)}</ac:parameter>'
        f'<ac:rich-text-body>{content}</ac:rich-text-body>'
        f'</ac:structured-macro>'
    )


def _render_call_graph_text(ep: dict) -> str:
    """Build a text-format call graph for one endpoint."""
    handler = ep.get("handler", "")
    svc_calls = [_clean_call(s) for s in ep.get("service_calls", [])]
    repo_calls = [_clean_call(r) for r in ep.get("repository_calls", [])]
    db_ops = ep.get("db_operations", [])

    lines = []
    if handler:
        lines.append(f"[Controller] {handler}")
    for sc in svc_calls[:6]:
        if sc:
            lines.append(f"    └─ [Service] {sc}")
    for rc in repo_calls[:6]:
        lines.append(f"        └─ [Repository] {rc}")
    if db_ops and isinstance(db_ops, list):
        for op in db_ops[:2]:
            if isinstance(op, dict):
                detail = op.get("detail", "")
                # Trim verbose boilerplate
                detail = re.sub(r'\(메서드 호출 추출[^)]*\)', '', detail).strip().rstrip(':')
                if detail:
                    lines.append(f"            └─ [DB] {detail}")
    return "\n".join(lines) if lines else ""


def _render_ep_detail(ep: dict) -> str:
    """Render detailed evidence block for a representative endpoint."""
    parts = []
    method = ep.get("http_method", "")
    path = ep.get("request_mapping", "")
    handler = ep.get("handler", "")
    proc_file = ep.get("process_file", "")
    params = ep.get("parameters", "")
    diagnosis_detail = ep.get("diagnosis_detail", "")
    filter_detail = ep.get("filter_detail", "")
    db_ops = ep.get("db_operations", [])

    # Info table
    info_rows = [
        ["API", f"<code>{html_escape(method)} {html_escape(str(path))}</code>"],
        ["핸들러", f"<code>{html_escape(handler)}</code>"],
    ]
    if proc_file:
        info_rows.append(["소스 파일", f"<code>{html_escape(proc_file)}</code>"])
    if params:
        info_rows.append(["파라미터", f"<code>{html_escape(str(params)[:300])}</code>"])
    if diagnosis_detail:
        clean_detail = re.sub(
            r'\(메서드 호출 추출 실패하였으나 JPA 내장 메서드는 안전\)', '', diagnosis_detail)
        info_rows.append(["판정 근거", html_escape(clean_detail.strip())])
    parts.append(_table(["항목", "내용"], info_rows))

    # Call graph
    cg = _render_call_graph_text(ep)
    if cg:
        parts.append("<p><strong>호출 경로 (Call Graph)</strong></p>")
        parts.append(_confluence_code_block(cg, "text"))

    # Code snippet from db_operations
    if db_ops and isinstance(db_ops, list):
        for op in db_ops:
            if isinstance(op, dict) and op.get("code_snippet"):
                op_file = op.get("file", proc_file)
                op_line = op.get("line", "")
                lang = _lang_for_file(op_file)
                op_title = Path(op_file).name if op_file else ""
                if op_line:
                    op_title += f"  (line {op_line})"
                parts.append(_confluence_code_block(op["code_snippet"], lang, title=op_title))
                break

    # Vulnerable pattern detail
    if filter_detail and filter_detail not in ("N/A", ""):
        parts.append(
            f"<p><strong>취약 패턴:</strong> "
            f"<code>{html_escape(filter_detail[:500])}</code></p>")

    return "".join(parts)


def _llm_override_badge(f: dict) -> str:
    """LLM 수동분석 보완 finding에서 '👉 LLM 판정 갱신' 인라인 배지 생성."""
    fid    = html_escape(str(f.get("id", "")))
    result = html_escape(str(f.get("result", "")))
    sev    = f.get("severity", "")
    color  = "red" if result == "취약" else "orange"
    return (
        f'<strong style="color:{color}">👉 LLM 판정 갱신: {result}</strong>'
        f'&nbsp;[{fid}]&nbsp;{_severity_badge(sev)}'
    )


def _llm_alert_box(llm_findings: list, match_keywords: list) -> str:
    """카테고리 키워드가 일치하는 LLM findings를 info 박스로 렌더링.

    자동스캔 섹션 상단에 삽입하여 LLM 판정 갱신 사실을 즉시 인지시킨다.
    """
    matched = [
        f for f in llm_findings
        if any(k in f.get("category", "").lower() for k in match_keywords)
    ]
    if not matched:
        return ""
    rows = []
    for f in matched:
        fid   = html_escape(str(f.get("id", "")))
        title = html_escape(str(f.get("title", "")))
        result = f.get("result", "")
        sev    = f.get("severity", "")
        color  = "red" if result == "취약" else "darkorange"
        rows.append(
            f'<li>{_severity_badge(sev)}&nbsp;'
            f'<strong style="color:{color}">👉 [{fid}] LLM 판정: {result}</strong>'
            f'&nbsp;— {title}</li>'
        )
    items_html = "<ul>" + "".join(rows) + "</ul>"
    return (
        '<ac:structured-macro ac:name="warning">'
        '<ac:rich-text-body>'
        '<p><strong>🔍 LLM 수동분석 보완 — 하단 「LLM 수동분석 보완 (Phase 3)」 섹션 참조</strong></p>'
        + items_html +
        '</ac:rich-text-body></ac:structured-macro>\n'
    )


def _json_to_xhtml_enhanced_injection(data, llm_findings=None, llm_supp=None):
    """Convert scan_injection_enhanced.py output to developer-friendly XHTML.

    Structure:
      - 진단 요약
      - 🚨 취약 (Vulnerable)  — category grouping, representative + expand
      - ⚠️ 정보 (Manual Check) — category grouping, representative + expand
      - ✅ 양호 (Safe)         — category grouping, representative + expand
      - 🔍 전역 취약점 (OS Command etc.) — code snippets with context

    llm_findings: supplemental_sources에서 수집된 LLM 수동분석 findings 리스트.
    """
    parts = ["<h2>인젝션 취약점 진단 결과</h2>"]

    # Metadata
    meta = data.get("scan_metadata", {})
    if meta:
        parts.append(
            f"<p>"
            f"<strong>소스:</strong> <code>{html_escape(str(meta.get('source_dir', '')))}</code>"
            f" &nbsp;|&nbsp; "
            f"<strong>분석 버전:</strong> <code>{html_escape(str(meta.get('script_version', '')))}</code>"
            f"</p>"
        )

    # Summary table
    summary = data.get("summary", {})
    sqli = summary.get("sqli", {})
    os_cmd = summary.get("os_command", {})
    total = summary.get("total_endpoints", 0)
    vuln_n = sqli.get("취약", 0)
    info_n = sqli.get("정보", 0)
    safe_n = sqli.get("양호", 0)

    # SSI 건수 (이후 테이블에서 재사용)
    ssi_total = 0
    gf = data.get("global_findings", {})
    if isinstance(gf, dict):
        ssi_total = gf.get("ssi_injection", {}).get("total", 0)

    # ── (1) 자동 분석 결과 ──────────────────────────────────────
    parts.append("<h3>(1) 자동 분석 결과</h3>")
    auto_rows = [
        [
            "SQL 인젝션",
            f"<strong style='color:green'>{safe_n}</strong>건" if safe_n else "0건",
            f"<strong style='color:orange'>{info_n}</strong>건" if info_n else "0건",
            f"<strong style='color:red'>{vuln_n}</strong>건" if vuln_n else "0건",
        ],
        [
            "OS Command 인젝션",
            "0건",
            f"<strong style='color:orange'>{os_cmd.get('total', 0)}</strong>건" if os_cmd.get('total', 0) else "0건",
            "0건",
        ],
        [
            "SSI/SSTI 인젝션",
            "1건 (스캔 완료)" if ssi_total == 0 else "0건",
            f"<strong style='color:orange'>{ssi_total}</strong>건" if ssi_total else "0건",
            "0건",
        ],
    ]
    parts.append(_table(["진단 항목", "🟢 양호", "🟡 정보 (수동검토)", "🔴 취약"], auto_rows))

    # ── (2) LLM 수동 검토 최종 결과 ────────────────────────────
    if llm_supp:
        sqli_rev = llm_supp.get("sqli_endpoint_review", {})
        sqli_overall = sqli_rev.get("overall_sqli_judgment", "")
        if sqli_overall == "양호":
            llm_sql_safe = safe_n + info_n
            llm_sql_info = 0
            llm_sql_vuln = vuln_n
        else:
            llm_sql_safe = safe_n
            llm_sql_info = info_n
            llm_sql_vuln = vuln_n

        gfa = llm_supp.get("global_findings_analysis", {})
        os_entries = gfa.get("os_command", []) if isinstance(gfa.get("os_command"), list) else []
        llm_os_safe = sum(1 for e in os_entries if "양호" in str(e.get("judgment", "")))
        llm_os_info = sum(1 for e in os_entries if str(e.get("judgment", "")).startswith("정보"))
        llm_os_vuln = sum(1 for e in os_entries if str(e.get("judgment", "")).startswith("취약"))

        llm_rows = [
            [
                "SQL 인젝션",
                f"<strong style='color:green'>{llm_sql_safe}</strong>건" if llm_sql_safe else "0건",
                f"<strong style='color:orange'>{llm_sql_info}</strong>건" if llm_sql_info else "0건",
                f"<strong style='color:red'>{llm_sql_vuln}</strong>건" if llm_sql_vuln else "0건",
            ],
            [
                "OS Command 인젝션",
                f"<strong style='color:green'>{llm_os_safe}</strong>건" if llm_os_safe else "0건",
                f"<strong style='color:orange'>{llm_os_info}</strong>건" if llm_os_info else "0건",
                f"<strong style='color:red'>{llm_os_vuln}</strong>건" if llm_os_vuln else "0건",
            ],
            [
                "SSI/SSTI 인젝션",
                "1건 (스캔 완료)" if ssi_total == 0 else "0건",
                f"<strong style='color:orange'>{ssi_total}</strong>건" if ssi_total else "0건",
                "0건",
            ],
        ]
        parts.append("<h3>(2) LLM 수동 검토 최종 결과</h3>")
        parts.append(_table(["진단 항목", "🟢 양호 (확정)", "🟡 정보", "🔴 취약"], llm_rows))

    # LLM 수동분석 보완 — 판정 갱신 alert box
    if llm_findings:
        alert = _llm_alert_box(
            llm_findings,
            ["injection", "sql", "os command", "ssi", "groovy", "command", "spel"],
        )
        if alert:
            parts.append(alert)

    # Group endpoints by result
    diagnoses = data.get("endpoint_diagnoses", [])
    result_groups: dict = {}
    for ep in diagnoses:
        r = ep.get("result", "정보")
        result_groups.setdefault(r, []).append(ep)

    def _render_result_section(result_key: str, icon: str, title_ko: str) -> str:
        eps = result_groups.get(result_key, [])
        if not eps:
            return ""

        sec = [f"<h3>{icon} {html_escape(title_ko)} — {len(eps)}건</h3>"]

        # Sub-group by simplified category
        cat_groups: dict = {}
        for ep in eps:
            cat = _simplify_category(ep)
            cat_groups.setdefault(cat, []).append(ep)

        # Category summary table
        cat_rows = [
            [html_escape(cat), f"{len(ce)}건"]
            for cat, ce in sorted(cat_groups.items(), key=lambda x: -len(x[1]))
        ]
        sec.append(_table(["원인 카테고리", "건수"], cat_rows))

        # Per-category detail
        for cat, cat_eps in sorted(cat_groups.items(), key=lambda x: -len(x[1])):
            representative = cat_eps[0]
            rest = cat_eps[1:]

            sec.append(f"<h4>{html_escape(cat)} ({len(cat_eps)}건)</h4>")
            sec.append("<p><em>대표 사례 상세:</em></p>")
            sec.append(_render_ep_detail(representative))

            if rest:
                rest_rows = []
                for idx, ep in enumerate(rest, 2):
                    svc = [_clean_call(s) for s in ep.get("service_calls", [])]
                    svc_str = " → ".join(svc[:3]) if svc else "-"
                    if len(svc) > 3:
                        svc_str += f" +{len(svc) - 3}"
                    repo = [_clean_call(r) for r in ep.get("repository_calls", [])]
                    repo_str = ", ".join(repo[:2]) if repo else "-"
                    if len(repo) > 2:
                        repo_str += f" +{len(repo) - 2}"
                    rest_rows.append([
                        str(idx),
                        f"<code>{html_escape(str(ep.get('http_method', '')))}</code>",
                        f"<code>{html_escape(str(ep.get('request_mapping', '')))}</code>",
                        f"<code>{html_escape(str(ep.get('handler', '')))}</code>",
                        html_escape(svc_str),
                        html_escape(repo_str),
                    ])
                rest_table = _table(
                    ["#", "Method", "API", "핸들러", "서비스 호출", "Repository"],
                    rest_rows
                )
                sec.append(_confluence_expand(
                    f"나머지 {len(rest)}개 API 목록 펼치기 ▶",
                    rest_table
                ))

        return "".join(sec)

    parts.append(_render_result_section("취약", "🚨", "취약 (Vulnerable)"))
    parts.append(_render_result_section("정보", "⚠️", "정보 — 수동 검토 필요 (Info)"))
    parts.append(_render_result_section("양호", "✅", "양호 (Safe)"))

    # --- Global Findings: OS Command, SSI ---
    global_findings = data.get("global_findings", {})
    if isinstance(global_findings, dict):
        for cat_key, cat_data in global_findings.items():
            if isinstance(cat_data, dict):
                findings = cat_data.get("findings", [])
                total_f = cat_data.get("total", 0)
            elif isinstance(cat_data, list):
                findings = cat_data
                total_f = len(findings)
            else:
                continue
            if not findings:
                continue

            cat_label = cat_key.replace("_", " ").title()
            parts.append(
                f"<h3>🔍 전역 취약점 — {html_escape(cat_label)} ({total_f}건)</h3>"
            )
            parts.append(
                "<p><em>아래 패턴은 전체 소스코드 수준에서 감지된 항목입니다. "
                "exec() 동반 여부 및 사용자 입력 소스를 수동으로 확인하세요.</em></p>"
            )

            def _render_global_finding(f: dict, idx: int) -> str:
                fname = f.get("file", "")
                line = f.get("line", 0)
                pattern = f.get("pattern_name", f.get("pattern_id", ""))
                desc = f.get("description", "")
                snippet = f.get("code_snippet", "")
                ctx_before = f.get("context_before", [])
                ctx_after = f.get("context_after", [])
                safe_indicators = f.get("safe_indicators", [])

                fp = [f"<h5>{idx}. {html_escape(pattern)}</h5>"]
                d_rows = [
                    ["파일", f"<code>{html_escape(fname)}:{line}</code>"],
                    ["설명", html_escape(desc)],
                ]
                if safe_indicators:
                    d_rows.append(["안전 지표", html_escape(", ".join(str(s) for s in safe_indicators))])
                fp.append(_table(["항목", "내용"], d_rows))

                if snippet or ctx_before or ctx_after:
                    full_lines = [str(ln) for ln in (ctx_before or [])[-3:]]
                    if snippet:
                        full_lines.append(f">>> {snippet}   ← 검출 라인 {line}")
                    full_lines.extend(str(ln) for ln in (ctx_after or [])[:3])
                    lang = "java"  # Confluence Server/DC does not support "kotlin"
                    fp.append("<p><strong>코드 스니펫</strong></p>")
                    fp.append(_confluence_code_block("\n".join(full_lines), lang))
                return "".join(fp)

            # First finding shown directly
            parts.append(_render_global_finding(findings[0], 1))
            if len(findings) > 1:
                rest_content = "".join(
                    _render_global_finding(f, i)
                    for i, f in enumerate(findings[1:], 2)
                )
                parts.append(_confluence_expand(
                    f"나머지 {len(findings) - 1}건 더 보기 ▶",
                    rest_content
                ))

    return "\n".join(parts)


def _simplify_xss_category(ep: dict) -> str:
    """Map XSS diagnosis to developer-friendly subcategory name.

    취약:
      Persistent XSS   — persistent_xss == "취약"
      Reflected XSS    — reflected_xss == "취약" / text/html 강제
      View XSS         — view_xss == "취약" (JSP/Thymeleaf)
      Open Redirect    — redirect_xss == "취약"
    양호:
      GET 전용 엔드포인트
      비문자열/파라미터 없음
      흐름 검증으로 안전
      DB 미접근 엔드포인트
      REST JSON 응답
    정보:
      수동 확인 필요
    """
    result   = ep.get("result", "정보")
    xss_type = ep.get("xss_type", "")
    ctrl     = ep.get("controller_type_detected", ep.get("controller_type", ""))
    diag     = ep.get("diagnosis_detail", "")

    if result == "취약":
        if ep.get("persistent_xss") == "취약" or "Persistent" in xss_type:
            return "Persistent XSS"
        if ep.get("reflected_xss") == "취약" or "Reflected" in xss_type:
            return "Reflected XSS"
        if ep.get("view_xss") == "취약" or "View" in xss_type:
            return "View XSS"
        if ep.get("redirect_xss") == "취약" or "Redirect" in xss_type or "Open Redirect" in xss_type:
            return "Open Redirect"
        return "XSS (기타)"

    if result == "양호":
        if "GET 전용" in diag:
            return "GET 전용 엔드포인트"
        if ("자유 텍스트" in diag or "비문자열" in diag
                or "파라미터 없음" in diag or "입력 파라미터 없음" in diag):
            return "비문자열/파라미터 없음"
        if "WHERE" in diag or "안전" in diag and "필터" not in diag:
            return "흐름 검증으로 안전"
        if "DB" in diag and ("미접근" in diag or "미호출" in diag or "없음" in diag):
            return "DB 미접근 엔드포인트"
        if "REST" in ctrl or "json" in ctrl.lower():
            return "REST JSON 응답"
        return "안전 확인"

    # 정보
    return "수동 확인 필요"


def _render_xss_ep_detail(ep: dict) -> str:
    """Render detailed info table for a representative XSS endpoint."""
    method  = html_escape(str(ep.get("http_method", "")))
    path    = html_escape(str(ep.get("request_mapping", "")))
    handler = html_escape(str(ep.get("handler", "")))
    pfile   = html_escape(str(ep.get("process_file", "")))
    params  = html_escape(str(ep.get("parameters", ""))[:300])
    diag    = html_escape(str(ep.get("diagnosis_detail", "")))
    xss_t   = html_escape(str(ep.get("xss_type", "")))
    ctrl    = html_escape(str(ep.get("controller_type_detected",
                                     ep.get("controller_type", ""))))

    rows = [
        ["API",      f"<code>{method} {path}</code>"],
        ["핸들러",   f"<code>{handler}</code>"],
    ]
    if pfile:
        rows.append(["소스 파일", f"<code>{pfile}</code>"])
    if params:
        rows.append(["파라미터", f"<code>{params}</code>"])
    if xss_t:
        rows.append(["XSS 유형", xss_t])
    if ctrl:
        rows.append(["컨트롤러 유형", ctrl])
    if diag:
        rows.append(["판정 근거", diag])

    parts = [_table(["항목", "내용"], rows)]

    # 취약 evidence (코드 스니펫)
    for ev in ep.get("evidence", [])[:2]:
        if isinstance(ev, dict):
            efile_raw = str(ev.get("file", ""))
            eline_raw = str(ev.get("line", ""))
            efile   = html_escape(efile_raw)
            eline   = html_escape(eline_raw)
            snippet = ev.get("code_snippet", "")
            if efile:
                parts.append(
                    f"<p><strong>위치:</strong> <code>{efile}:{eline}</code></p>"
                )
            if snippet:
                ev_lang = _lang_for_file(efile_raw)
                ev_title = Path(efile_raw).name if efile_raw else ""
                if eline_raw:
                    ev_title += f"  (line {eline_raw})"
                parts.append(_confluence_code_block(snippet, ev_lang, title=ev_title))

    return "".join(parts)


def _json_to_xhtml_enhanced_xss(data, llm_findings=None, llm_supp=None):
    """Convert scan_xss.py output (v1.1+) to developer-friendly XHTML.

    Structure — XSS 유형별(per-type) 섹션:
      - 진단 요약 (overall + per-type 통계 테이블)
      - Reflected XSS   — 취약/양호 각각 판단 근거 명시
      - Persistent XSS  — 양호 이유(필터/GET전용 등) + 해당없음 이유
      - Redirect XSS    — 양호 이유
      - View XSS        — 해당없음 이유
      - DOM XSS         — 전역 소스코드 스캔 결과 (JS/TS/Vue)
      - XSS 전역 필터 현황 (info/warning 매크로 박스)
    """
    parts = ["<h2>XSS 취약점 진단 결과</h2>"]

    meta = data.get("scan_metadata", {})
    if meta:
        parts.append(
            f"<p>"
            f"<strong>소스:</strong> <code>{html_escape(str(meta.get('source_dir', '')))}</code>"
            f" &nbsp;|&nbsp; "
            f"<strong>분석 버전:</strong>"
            f" <code>{html_escape(str(meta.get('script_version', '')))}</code>"
            f"</p>"
        )

    # --- 진단 요약 ---
    summary    = data.get("summary", {})
    total_ep   = summary.get("total_endpoints", 0)
    xss_counts = summary.get("xss", {})
    per_type   = summary.get("per_type", {})
    diagnoses  = data.get("endpoint_diagnoses", [])

    dom_scan  = meta.get("dom_xss_scan", {}) if meta else {}
    dom_total = len(dom_scan.get("findings", [])) if isinstance(dom_scan, dict) else 0
    dom_files = dom_scan.get("js_files_scanned", dom_scan.get("total_files_scanned", 0)) \
        if isinstance(dom_scan, dict) else 0

    def _pt_row(tkey: str, tlabel: str) -> list:
        td = per_type.get(tkey, {})
        if not isinstance(td, dict):
            return [tlabel, "0건", "0건", "0건"]
        s = td.get("양호", 0) + td.get("해당없음", 0)
        i = td.get("정보", 0)
        v = td.get("취약", 0)
        return [
            tlabel,
            f"<strong style='color:green'>{s}</strong>건" if s else "0건",
            f"<strong style='color:orange'>{i}</strong>건" if i else "0건",
            f"<strong style='color:red'>{v}</strong>건" if v else "0건",
        ]

    # ── (1) 자동 분석 결과 ──────────────────────────────────────
    parts.append("<h3>(1) 자동 분석 결과</h3>")
    auto_rows = [
        _pt_row("reflected_xss",  "Reflected XSS"),
        _pt_row("persistent_xss", "Persistent XSS"),
        _pt_row("redirect_xss",   "Open Redirect"),
        _pt_row("view_xss",       "View XSS"),
        [
            "DOM-based XSS",
            f"양호 (스캔 {dom_files}파일)" if not dom_total else "0건",
            "0건",
            f"<strong style='color:red'>{dom_total}</strong>건" if dom_total else "0건",
        ],
    ]
    parts.append(_table(["진단 항목", "🟢 양호", "🟡 정보 (수동검토)", "🔴 취약"], auto_rows))

    # ── (2) LLM 수동 검토 최종 결과 ────────────────────────────
    if llm_supp:
        xss_rev = llm_supp.get("xss_endpoint_review", {})
        # group_judgments 인덱싱
        # Bug fix: HTML_VIEW 그룹이 "잠재적위협" 조건에도 매칭되어 key collision 발생.
        # HTML_VIEW를 먼저 체크해야 "잠재적위협 — HTML_VIEW" 그룹이 view로 올바르게 매핑됨.
        xss_gj_map: dict[str, dict] = {}
        for gj in xss_rev.get("group_judgments", []):
            gname = gj.get("group", "")
            if "HTML_VIEW" in gname or "HTML_view" in gname.lower():
                xss_gj_map["view"] = gj
            elif "잠재적위협" in gname:
                xss_gj_map["persistent"] = gj
            elif "Reflected" in gname or "text/html" in gname:
                xss_gj_map["reflected_manual"] = gj

        def _llm_pt_row(tkey: str, tlabel: str, gj_key: str) -> list:
            gj = xss_gj_map.get(gj_key, {})
            td = per_type.get(tkey, {}) if isinstance(per_type.get(tkey), dict) else {}
            auto_s = td.get("양호", 0) + td.get("해당없음", 0)
            auto_i = td.get("정보", 0)
            auto_v = td.get("취약", 0)
            if not gj:
                s, i, v = auto_s, auto_i, auto_v
            else:
                eps = gj.get("endpoints_reviewed", []) + gj.get("controllers_reviewed", [])
                judgment = gj.get("judgment", "")
                if eps and gj_key == "view" and judgment == "양호":
                    s = auto_s + auto_i
                    i = 0
                    v = auto_v
                elif eps:
                    s = sum(1 for e in eps if e.get("result") == "양호") + auto_s
                    i = sum(1 for e in eps if e.get("result") == "정보")
                    v = sum(1 for e in eps if e.get("result") == "취약") + auto_v
                elif judgment == "양호":
                    s = auto_s + auto_i
                    i = 0
                    v = auto_v
                else:
                    s, i, v = auto_s, auto_i, auto_v
            return [
                tlabel,
                f"<strong style='color:green'>{s}</strong>건" if s else "0건",
                f"<strong style='color:orange'>{i}</strong>건" if i else "0건",
                f"<strong style='color:red'>{v}</strong>건" if v else "0건",
            ]

        def _llm_findings_pt_row(tkey: str, tlabel: str, cat_keywords: list[str]) -> list:
            """LLM 수동분석 findings 기반 per-type 집계.
            auto-scan이 놓친 LLM 발견 취약점(Open Redirect 등)을 매트릭스에 반영하고,
            LLM이 재분류한 결과(취약→정보 등)를 endpoint 단위로 보정한다.
            총계는 auto-scan total 기준 유지 (새 정적 JSP 등 외부 EP는 미포함).
            """
            td = per_type.get(tkey, {}) if isinstance(per_type.get(tkey), dict) else {}
            auto_s = td.get("양호", 0) + td.get("해당없음", 0)
            auto_i = td.get("정보", 0)
            auto_v = td.get("취약", 0)
            total  = auto_s + auto_i + auto_v

            # cat_keywords에 매칭되는 LLM finding 수집 (filter/misconfiguration 제외)
            relevant = [
                f for f in (llm_findings or [])
                if not any(k in f.get("category", "").lower()
                           for k in ("filter", "misconfiguration"))
                and any(k.lower() in (f.get("category", "") + " " +
                                      f.get("diagnosis_type", "")).lower()
                        for k in cat_keywords)
            ]
            if not relevant:
                return _llm_pt_row(tkey, tlabel, "")   # fallback to group_judgment logic

            # affected_endpoints에서 path 기준으로 결과 집계
            vuln_paths: set[str] = set()
            info_paths: set[str] = set()
            for f in relevant:
                r = f.get("result", "")
                for ep in f.get("affected_endpoints", []):
                    path = ep.get("path", "")
                    if not path or path.startswith("/static/"):
                        continue   # API 인벤토리 외부(정적 JSP 등) 제외
                    if r == "취약":
                        vuln_paths.add(path)
                    elif r == "정보":
                        info_paths.add(path)

            all_llm = vuln_paths | info_paths
            # auto-scan 취약 중 LLM이 커버한 EP → LLM 결과로 대체
            v = len(vuln_paths) + max(0, auto_v - len(all_llm))
            i = len(info_paths) + max(0, auto_i - len(info_paths & all_llm))
            s = total - v - i
            return [
                tlabel,
                f"<strong style='color:green'>{s}</strong>건" if s else "0건",
                f"<strong style='color:orange'>{i}</strong>건" if i else "0건",
                f"<strong style='color:red'>{v}</strong>건" if v else "0건",
            ]

        # XSS 전역 필터 결함 건수 집계
        filter_findings = [f for f in (llm_findings or [])
                           if "filter" in f.get("category", "").lower()]
        filter_vuln = sum(1 for f in filter_findings if f.get("result") == "취약")
        filter_info = sum(1 for f in filter_findings if f.get("result") == "정보")
        filter_safe = sum(1 for f in filter_findings if f.get("result") == "양호")

        llm_rows = [
            [
                "XSS 전역 필터 보안성",
                f"<strong style='color:green'>{filter_safe}</strong>건" if filter_safe else "0건",
                f"<strong style='color:orange'>{filter_info}</strong>건" if filter_info else "0건",
                f"<strong style='color:red'>{filter_vuln}</strong>건" if filter_vuln else "0건",
            ],
            _llm_pt_row("persistent_xss", "Persistent XSS", "persistent"),
            _llm_findings_pt_row("view_xss",      "View XSS",
                                 ["view", "html attribute"]),
            _llm_findings_pt_row("reflected_xss", "Reflected XSS",
                                 ["view", "reflected", "html attribute"]),
            _llm_findings_pt_row("redirect_xss",  "Open Redirect",
                                 ["redirect", "open redirect"]),
            [
                "DOM-based XSS",
                f"양호 (스캔 {dom_files}파일)" if not dom_total else "0건",
                "0건",
                f"<strong style='color:red'>{dom_total}</strong>건" if dom_total else "0건",
            ],
        ]
        parts.append("<h3>(2) LLM 수동 검토 최종 결과</h3>")
        parts.append(_table(["진단 항목", "🟢 양호 (확정)", "🟡 정보", "🔴 취약"], llm_rows))

        # XSS 전역 필터 보안성 — 상세 섹션
        if filter_findings:
            parts.append("<h3>🔴 XSS 전역 필터 보안성</h3>")
            parts.append(
                "<p>전역 XSS 필터 설정 및 구현 결함. 모든 API 엔드포인트의 XSS 방어에 영향.</p>"
            )
            for f in filter_findings:
                fid    = html_escape(str(f.get("id", "")))
                title  = html_escape(str(f.get("title", "")))
                result = f.get("result", "")
                sev    = f.get("severity", "")
                desc   = html_escape(str(f.get("description", "")))
                rec    = html_escape(str(f.get("recommendation", "")))
                color  = "red" if result == "취약" else ("darkorange" if result == "정보" else "green")
                parts.append(
                    f"<h4>{_severity_badge(sev)} [{fid}] {title} "
                    f"<span style='color:{color}'>({result})</span></h4>"
                )
                if desc:
                    parts.append(f"<p>{desc}</p>")
                # code evidence
                ev = f.get("evidence", {})
                if isinstance(ev, dict):
                    snippet = ev.get("code_snippet", "")
                    efile   = str(ev.get("file", ""))
                    eline   = str(ev.get("line", "")) if ev.get("line") else ""
                    elines_v = str(ev.get("lines", "")) if ev.get("lines") else eline
                    if efile:
                        parts.append(f"<p><strong>위치:</strong> <code>{html_escape(efile)}"
                                     + (f":{eline}" if eline else "") + "</code></p>")
                    if snippet:
                        ev_lang = _lang_for_file(efile)
                        ev_title = Path(efile).name if efile else ""
                        if elines_v:
                            ev_title += f"  (line {elines_v})"
                        parts.append(_confluence_code_block(snippet, ev_lang, title=ev_title))
                if rec:
                    parts.append(
                        f'<ac:structured-macro ac:name="tip">'
                        f'<ac:rich-text-body><p><strong>권고:</strong> {rec}</p></ac:rich-text-body>'
                        f'</ac:structured-macro>'
                    )

    # LLM 수동분석 보완 — 판정 갱신 alert box
    if llm_findings:
        alert = _llm_alert_box(
            llm_findings,
            ["xss", "filter", "persistent", "reflected", "dom", "redirect", "view"],
        )
        if alert:
            parts.append(alert)

    # ── 공통 헬퍼 ──────────────────────────────────────────────────────────
    def _ep_list_row(idx: int, ep: dict, reason_col: str = "") -> list:
        return [
            str(idx),
            f"<code>{html_escape(str(ep.get('http_method','')))}</code>",
            f"<code>{html_escape(str(ep.get('request_mapping','')))}</code>",
            f"<code>{html_escape(str(ep.get('handler','')))}</code>",
            html_escape(reason_col[:100]) if reason_col else
            html_escape(str(ep.get("diagnosis_detail",""))[:100]),
        ]

    def _render_vuln_group(vuln_eps: list) -> str:
        """취약 항목: 대표 상세 + 나머지 expand."""
        if not vuln_eps:
            return ""
        sec = ["<p><em>대표 사례 상세:</em></p>", _render_xss_ep_detail(vuln_eps[0])]
        if len(vuln_eps) > 1:
            rest_rows = [_ep_list_row(i, ep) for i, ep in enumerate(vuln_eps[1:], 2)]
            sec.append(_confluence_expand(
                f"나머지 {len(vuln_eps) - 1}개 취약 API ▶",
                _table(["#", "Method", "API", "핸들러", "판정 요약"], rest_rows),
            ))
        return "".join(sec)

    def _render_good_group_by_reason(good_eps: list, phase_key: str) -> str:
        """양호 항목: reason별 그룹 → 각 그룹에 건수+이유+대표 API 펼치기."""
        if not good_eps:
            return ""
        from collections import defaultdict
        reason_groups: dict = defaultdict(list)
        for ep in good_eps:
            pd   = ep.get("phase_details", {})
            r    = (pd.get(phase_key) or {}).get("reason", "") if phase_key else ""
            r    = r or ep.get("diagnosis_detail", "알 수 없음")
            reason_groups[r[:120]].append(ep)

        sec = []
        for reason, reps in sorted(reason_groups.items(), key=lambda x: -len(x[1])):
            sec.append(
                f"<p><strong>✅ {html_escape(reason)}</strong> — {len(reps)}건</p>"
            )
            list_rows = [_ep_list_row(i, ep) for i, ep in enumerate(reps, 1)]
            sec.append(_confluence_expand(
                f"{len(reps)}개 API 목록 ▶",
                _table(["#", "Method", "API", "핸들러", "판정 요약"], list_rows),
            ))
        return "".join(sec)

    def _render_na_summary(na_eps: list, phase_key: str) -> str:
        """해당없음: reason별 건수만 표시 (expand 없음)."""
        if not na_eps:
            return ""
        from collections import Counter
        reasons = Counter()
        for ep in na_eps:
            pd = ep.get("phase_details", {})
            r  = (pd.get(phase_key) or {}).get("reason", "") if phase_key else ""
            r  = r or ep.get("diagnosis_detail", "해당없음")
            reasons[r[:100]] += 1
        rows = [[html_escape(r), f"{c}건"] for r, c in reasons.most_common()]
        return _table(["해당없음 이유", "건수"], rows)

    # ── 1. Reflected XSS ───────────────────────────────────────────────────
    r_vuln = [ep for ep in diagnoses if ep.get("reflected_xss") == "취약"]
    r_good = [ep for ep in diagnoses if ep.get("reflected_xss") == "양호"]
    r_na   = [ep for ep in diagnoses if ep.get("reflected_xss") == "해당없음"]
    parts.append(f"<h3>🔴 Reflected XSS — 취약 {len(r_vuln)}건 / 양호 {len(r_good)}건"
                 + (f" / 해당없음 {len(r_na)}건" if r_na else "") + "</h3>")
    parts.append(
        "<p>HTTP 요청 파라미터가 HTML 응답에 인코딩 없이 반사될 때 발생. "
        "서버가 <code>Content-Type: text/html</code>로 응답하는 엔드포인트가 대상.</p>"
    )
    if r_vuln:
        parts.append("<h4>🚨 취약 항목</h4>")
        parts.append(_render_vuln_group(r_vuln))
    if r_good:
        parts.append(f"<h4>✅ 양호 — {len(r_good)}건 (판단 근거)</h4>")
        parts.append(_render_good_group_by_reason(r_good, "phase1_controller"))
    if r_na:
        parts.append(f"<h4>➖ 해당없음 — {len(r_na)}건</h4>")
        parts.append(_render_na_summary(r_na, "phase1_controller"))

    # ── 2. Persistent XSS ─────────────────────────────────────────────────
    p_vuln = [ep for ep in diagnoses if ep.get("persistent_xss") == "취약"]
    p_good = [ep for ep in diagnoses if ep.get("persistent_xss") == "양호"]
    p_na   = [ep for ep in diagnoses if ep.get("persistent_xss") == "해당없음"]
    parts.append(f"<h3>🔴 Persistent XSS — 취약 {len(p_vuln)}건 / 양호 {len(p_good)}건"
                 + (f" / 해당없음 {len(p_na)}건" if p_na else "") + "</h3>")
    parts.append(
        "<p>HTTP 파라미터가 DB에 저장된 후 다른 사용자의 브라우저에서 실행되는 패턴. "
        "SQLi 진단 결과(DB write 경로)와 교차 검증하여 판정.</p>"
    )
    if p_vuln:
        parts.append("<h4>🚨 취약 항목</h4>")
        parts.append(_render_vuln_group(p_vuln))
    if p_good:
        parts.append(f"<h4>✅ 양호 — {len(p_good)}건 (판단 근거)</h4>")
        parts.append(_render_good_group_by_reason(p_good, "phase5_persistent"))
    if p_na:
        parts.append(f"<h4>➖ 해당없음 — {len(p_na)}건 (Persistent XSS 경로 없음)</h4>")
        parts.append(_render_na_summary(p_na, "phase5_persistent"))

    # ── 3. Redirect XSS (Open Redirect) ───────────────────────────────────
    rd_vuln = [ep for ep in diagnoses if ep.get("redirect_xss") == "취약"]
    rd_good = [ep for ep in diagnoses if ep.get("redirect_xss") == "양호"]
    rd_na   = [ep for ep in diagnoses if ep.get("redirect_xss") == "해당없음"]
    parts.append(f"<h3>🔴 Redirect XSS (Open Redirect) — 취약 {len(rd_vuln)}건 / 양호 {len(rd_good)}건"
                 + (f" / 해당없음 {len(rd_na)}건" if rd_na else "") + "</h3>")
    parts.append(
        "<p>응답에 포함된 URL 리다이렉트 경로를 사용자가 조작할 수 있을 때 발생. "
        "302 Redirect 또는 Location 헤더가 직접 사용자 입력을 반영하는 패턴이 대상.</p>"
    )
    if rd_vuln:
        parts.append("<h4>🚨 취약 항목</h4>")
        parts.append(_render_vuln_group(rd_vuln))
    if rd_good:
        parts.append(f"<h4>✅ 양호 — {len(rd_good)}건 (판단 근거)</h4>")
        parts.append(_render_good_group_by_reason(rd_good, "phase4_redirect"))
    if rd_na:
        parts.append(f"<h4>➖ 해당없음 — {len(rd_na)}건</h4>")
        parts.append(_render_na_summary(rd_na, "phase4_redirect"))

    # ── 4. View XSS (Server-Side Template Injection) ──────────────────────
    v_vuln = [ep for ep in diagnoses if ep.get("view_xss") == "취약"]
    v_na   = [ep for ep in diagnoses if ep.get("view_xss") == "해당없음"]
    v_good = [ep for ep in diagnoses if ep.get("view_xss") == "양호"]
    parts.append(
        f"<h3>🔴 View XSS (Server Template) — 취약 {len(v_vuln)}건"
        + (f" / 양호 {len(v_good)}건" if v_good else "")
        + (f" / 해당없음 {len(v_na)}건" if v_na else "") + "</h3>"
    )
    parts.append(
        "<p>Thymeleaf, JSP, FreeMarker 등 서버 사이드 템플릿이 사용자 입력을 "
        "이스케이프 없이 렌더링할 때 발생. REST API 전용 서비스는 해당 없음.</p>"
    )
    if v_vuln:
        parts.append("<h4>🚨 취약 항목</h4>")
        parts.append(_render_vuln_group(v_vuln))
    if v_good:
        parts.append(f"<h4>✅ 양호 — {len(v_good)}건</h4>")
        parts.append(_render_good_group_by_reason(v_good, "phase2_view"))
    if v_na:
        parts.append(f"<h4>➖ 해당없음 — {len(v_na)}건 (REST API 구조, 서버 템플릿 없음)</h4>")
        parts.append(_render_na_summary(v_na, "phase2_view"))

    # ── 5. DOM XSS (전역 소스코드 스캔) ────────────────────────────────────
    dom_findings = dom_scan.get("findings", []) if isinstance(dom_scan, dict) else []
    dom_vuln_icon = "🚨" if dom_total else "✅"
    parts.append(
        f"<h3>{dom_vuln_icon} DOM XSS — 전역 스캔 결과 ({dom_total}건)</h3>"
    )
    parts.append(
        f"<p>JS/TS/Vue 파일 전체({dom_files}개)를 대상으로 "
        f"<code>innerHTML</code>, <code>document.write</code>, <code>eval</code> 등 "
        f"DOM XSS 유발 패턴을 정적 분석. 개별 API 엔드포인트와 독립적으로 수행.</p>"
    )
    parts.append(_table(
        ["항목", "값"],
        [
            ["스캔 대상 (JS/TS/Vue)", f"{dom_files}개 파일"],
            ["DOM XSS 패턴 발견",     f"{dom_total}건"],
            ["스캔 결과 요약",         html_escape(str(dom_scan.get("summary", "")))],
        ],
    ))
    if dom_findings:
        def _render_dom_finding(f: dict, idx: int) -> str:
            fname   = html_escape(str(f.get("file", "")))
            line    = f.get("line", 0)
            pattern = html_escape(str(f.get("pattern_name", "")))
            snippet = f.get("code_snippet", "")
            fp = [f"<h5>{idx}. {pattern}</h5>"]
            fp.append(_table(
                ["항목", "내용"],
                [["파일", f"<code>{fname}:{line}</code>"], ["패턴", pattern]],
            ))
            if snippet:
                fp.append("<p><strong>코드 스니펫</strong></p>")
                fp.append(_confluence_code_block(snippet, "javascript"))
            return "".join(fp)

        parts.append(_render_dom_finding(dom_findings[0], 1))
        if len(dom_findings) > 1:
            parts.append(_confluence_expand(
                f"나머지 {len(dom_findings) - 1}건 더 보기 ▶",
                "".join(_render_dom_finding(f, i) for i, f in enumerate(dom_findings[1:], 2)),
            ))

    # ── XSS 전역 필터 현황 (info/warning 박스) ─────────────────────────────
    global_filter = meta.get("global_xss_filter", {}) if meta else {}
    if global_filter:
        has_filter    = global_filter.get("has_filter", False)
        filter_type   = html_escape(str(global_filter.get("filter_type", "없음")))
        filter_detail = html_escape(str(global_filter.get("filter_detail", "")))
        filter_badge  = (
            _severity_badge("Info").replace("Info", "적용됨")
            if has_filter
            else _severity_badge("Medium").replace("Medium", "미설정")
        )
        parts.append("<h3>⚙️ XSS 전역 필터 현황</h3>")
        if has_filter:
            body = f"<p><strong>필터 상태:</strong> {filter_badge} — {filter_type}</p>"
            if filter_detail:
                body += f"<p><strong>상세:</strong> {filter_detail}</p>"
            for fkey, flabel in [
                ("has_lucy",        "Lucy XSS Filter"),
                ("has_antisamy",    "AntiSamy"),
                ("has_esapi",       "ESAPI"),
                ("has_ss_xss",      "Spring Security XSS"),
                ("has_jackson_xss", "Jackson XSS Deserializer"),
            ]:
                if global_filter.get(fkey):
                    body += f"<p>✓ {flabel} 발견</p>"
            parts.append(
                f'<ac:structured-macro ac:name="info">'
                f'<ac:rich-text-body>{body}</ac:rich-text-body>'
                f'</ac:structured-macro>'
            )
        else:
            parts.append(
                f'<ac:structured-macro ac:name="warning">'
                f'<ac:rich-text-body>'
                f'<p><strong>현황:</strong> {filter_badge} — '
                f'Lucy XSS Filter, AntiSamy, ESAPI, Jackson XSS Deserializer 등 전역 XSS 필터 미발견</p>'
                f'<p><strong>현재 위험도:</strong> <strong>낮음</strong> — '
                f'REST API JSON 응답 구조로 서버 레벨 XSS 발생 경로 없음</p>'
                f'<p><strong>향후 위험:</strong> HTML View 추가 또는 외부 포털이 '
                f'이 API 응답을 HTML에 직접 렌더링하는 경우 위험</p>'
                f'<p><strong>권고:</strong> JSON Request Body용 Jackson XSS Deserializer '
                f'또는 Spring Security 기반 필터 적용 검토</p>'
                f'</ac:rich-text-body></ac:structured-macro>'
            )
            parts.append(_confluence_code_block(
                "// 권고: Jackson ObjectMapper에 XSS Deserializer 전역 등록\n"
                "mapper.registerModule(new SimpleModule()\n"
                "    .addDeserializer(String.class, new XSSStringDeserializer()));",
                "java",
            ))

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
                efile_raw = str(evidence.get("file", ""))
                elines_raw = str(evidence.get("lines", ""))
                efile = html_escape(efile_raw)
                elines = html_escape(elines_raw)
                parts.append(f"<p><strong>증거:</strong> {efile}:{elines}</p>")
                snippet = evidence.get("code_snippet", "")
                if snippet:
                    ev_lang = _lang_for_file(efile_raw)
                    ev_title = Path(efile_raw).name if efile_raw else ""
                    if elines_raw:
                        ev_title += f"  (line {elines_raw})"
                    parts.append(_confluence_code_block(snippet, ev_lang, title=ev_title))

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


def json_to_xhtml(data, json_type, source_path="", llm_findings=None, llm_supp=None):
    """Route JSON data to the appropriate XHTML renderer based on type.

    json_type is one of: "finding", "final_report", "api_inventory"
    source_path helps disambiguate finding sub-types.
    llm_findings: LLM supplemental findings list (from supplemental_sources), passed to
                  enhanced renderers so they can display an alert box in the summary section.
    llm_supp: full supplemental data dict (for sqli_endpoint_review / xss_endpoint_review).
    """
    if json_type == "final_report":
        return _json_to_xhtml_final(data)

    # scan_api.py v3.0 format auto-detection (endpoints key)
    if json_type == "api_inventory" or "endpoints" in data:
        return _json_to_xhtml_api_inventory(data)

    # scan_xss.py format auto-detection (endpoint_diagnoses + per_type in summary)
    if "endpoint_diagnoses" in data and data.get("summary", {}).get("per_type"):
        return _json_to_xhtml_enhanced_xss(data, llm_findings=llm_findings, llm_supp=llm_supp)

    # scan_injection_enhanced.py format auto-detection (endpoint_diagnoses key)
    if "endpoint_diagnoses" in data:
        return _json_to_xhtml_enhanced_injection(data, llm_findings=llm_findings, llm_supp=llm_supp)

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
# Main Report (통합 보고서) renderer
# ---------------------------------------------------------------------------

def _load_json_safe(rel_path: str, base_dir: str) -> dict:
    """Load a JSON file relative to base_dir. Returns {} on any error."""
    if not rel_path:
        return {}
    full = os.path.join(base_dir, rel_path)
    if not os.path.isfile(full):
        return {}
    try:
        with open(full, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}


def _md_strip_detail_sections(md_content: str) -> str:
    """진단보고서.md 에서 세부 Task 섹션(인젝션/XSS 상세)을 제거하고
    개요·한계 부분만 반환한다.

    제거 대상 패턴 (## 레벨 섹션):
      ## 4.  Task 2-2 인젝션 ...
      ## 5.  Task 2-3 XSS ...
      ## 6.  정보 항목 ...

    유지 대상:
      ## 1.  진단 대상 개요
      ## 2.  종합 결과 요약  ← 주석 처리(JSON 으로 대체)
      ## 3.  API 인벤토리   ← 주석 처리(JSON 으로 대체)
      ## 7.  전체 결과 요약 ← 주석 처리(JSON 으로 대체)
      ## 8.  진단 한계 사항  ← 유지
    """
    # 유지할 최상위 섹션 번호: 1, 8 (개요 + 한계)
    # 2,3,7 은 JSON 기반 동적 렌더링으로 대체
    _KEEP_SECTION_NOS = {'1', '8'}
    _SKIP_SECTION_NOS = {'2', '3', '4', '5', '6', '7'}

    # non-numbered ## headings to always skip (JSON으로 대체)
    _SKIP_HEADING_NAMES = {'summary-table', 'summary', '요약'}

    lines = md_content.splitlines()
    result_lines = []
    skip = False
    for line in lines:
        # 최상위 ## 섹션 헤딩 탐지
        m = re.match(r'^##\s+(\d+)[\.\s]', line)
        if m:
            sec_no = m.group(1)
            if sec_no in _SKIP_SECTION_NOS:
                skip = True
                continue
            elif sec_no in _KEEP_SECTION_NOS:
                skip = False
        else:
            # 번호 없는 ## 헤딩 처리 (예: ## summary-table)
            m2 = re.match(r'^##\s+(\S+)', line)
            if m2 and m2.group(1).lower() in _SKIP_HEADING_NAMES:
                skip = True
                continue
        if not skip:
            result_lines.append(line)
    return '\n'.join(result_lines).strip()


def _count_findings(data: dict):
    """findings 배열에서 (취약 건수, 정보 건수)를 집계한다.
    scan_injection_enhanced / scan_xss / task2x LLM finding JSON 공통 지원."""
    findings = data.get("findings", [])
    vuln_n = sum(1 for f in findings if f.get("result") == "취약")
    info_n = sum(1 for f in findings if f.get("result") == "정보")
    return vuln_n, info_n


def _build_main_summary_table(injection_data: dict, xss_data: dict,
                               dp_data: dict = None) -> str:
    """JSON 데이터로부터 통합 결과 요약 표를 생성한다.
    이 함수가 단일 데이터 소스이므로 세부 보고서와 수치가 항상 일치한다.

    injection_data / xss_data:
      - scan_injection_enhanced.py / scan_xss.py 출력 (summary.sqli / summary.xss 키)
      - 또는 task22 / task23 LLM finding JSON (findings 배열 fallback)
    dp_data: task25 LLM finding JSON (findings 배열)
    """
    rows = []

    # SQL Injection
    if injection_data:
        sqli = injection_data.get("summary", {}).get("sqli", {})
        if sqli:
            vuln_n = sqli.get("취약", 0)
            info_n = sqli.get("정보", 0)
        else:
            # LLM finding JSON fallback (task22)
            ep_sum = injection_data.get("endpoint_summary", {})
            vuln_n = ep_sum.get("취약", 0)
            info_n = ep_sum.get("정보", 0)
            # findings 배열에서도 재집계 (더 정확)
            f_vuln, f_info = _count_findings(injection_data)
            if f_vuln or f_info:
                vuln_n, info_n = f_vuln, f_info
        result_str = "<strong>전체 양호</strong>" if vuln_n == 0 and info_n == 0 \
            else f"<strong style='color:red'>취약 {vuln_n}건</strong>"
        rows.append(["SQL Injection", result_str,
                     f"{vuln_n}건", f"{info_n}건"])
        os_cmd = injection_data.get("summary", {}).get("os_command", {})
        os_total = os_cmd.get("total", 0)
        # LLM finding JSON: global_findings_analysis.os_command 확인
        if not os_total:
            os_entries = injection_data.get("global_findings_analysis", {}).get("os_command", [])
            os_total = sum(1 for e in os_entries if e.get("result") not in ("양호", ""))
        rows.append(["OS Command Injection",
                     "오탐 검토 필요" if os_total else "해당없음",
                     "0건", "0건"])
        # SSI — global_findings에서 실제 건수 반영
        ssi_gf = injection_data.get("global_findings", {})
        ssi_total = ssi_gf.get("ssi_injection", {}).get("total", 0) if isinstance(ssi_gf, dict) else 0
        ssi_result = f"<strong style='color:orange'>⚠️ {ssi_total}건 (세부 보고서 참조)</strong>" \
            if ssi_total else "해당없음"
        rows.append(["SSI / SpEL Injection", ssi_result, f"{ssi_total}건", "0건"])
    else:
        rows.append(["SQL Injection", "—", "—", "—"])
        rows.append(["OS Command Injection", "—", "—", "—"])
        rows.append(["SSI / SpEL Injection", "—", "—", "—"])

    # XSS
    if xss_data:
        xss_sum = xss_data.get("summary", {}).get("xss", {})
        per_type = xss_data.get("summary", {}).get("per_type", {})
        if xss_sum:
            xss_vuln = xss_sum.get("취악", xss_sum.get("취약", 0))
            xss_info = xss_sum.get("정보", 0)
        else:
            # LLM finding JSON fallback (task23)
            xss_scan = xss_data.get("xss_scan_summary", {})
            xss_vuln = xss_scan.get("취약_자동", 0)
            xss_info = 0
            f_vuln, f_info = _count_findings(xss_data)
            xss_vuln = max(xss_vuln, f_vuln)
            xss_info = f_info
        xss_result = "<strong>전체 양호</strong>" \
            if xss_vuln == 0 and xss_info == 0 \
            else f"<strong style='color:red'>취약 {xss_vuln}건</strong>"
        rows.append(["XSS (전체)", xss_result,
                     f"{xss_vuln}건", f"{xss_info}건"])
        if per_type:
            _xss_labels = [
                ("reflected_xss", "Reflected XSS"),
                ("view_xss",      "View XSS"),
                ("persistent_xss","Persistent XSS"),
                ("redirect_xss",  "Redirect XSS"),
                ("dom_xss",       "DOM XSS"),
            ]
            for key, label in _xss_labels:
                td = per_type.get(key, {})
                # per_type 값이 string 인 경우(dom_xss 전역 스캔 요약 문자열)는 해당없음 처리
                if not isinstance(td, dict):
                    rows.append([f"&nbsp;&nbsp;— {label}", "해당없음 (전역 스캔)",
                                 "0건", "0건"])
                    continue
                tv = td.get("취약", 0)
                ti_n = td.get("정보", 0)
                ts = td.get("양호", 0)
                na = td.get("해당없음", 0)
                if na and not tv and not ti_n and not ts:
                    sub_result = "해당없음"
                elif tv == 0:
                    sub_result = f"양호 {ts}건"
                else:
                    sub_result = f"취약 {tv}건"
                rows.append([f"&nbsp;&nbsp;— {label}", sub_result,
                             f"{tv}건", f"{ti_n}건"])
        else:
            # LLM finding JSON: xss_filter_assessment 기반 간략 정보
            xss_filter = xss_data.get("xss_filter_assessment", {})
            if xss_filter:
                filter_ok = xss_filter.get("filter_default_enabled", False)
                filter_level = xss_filter.get("filter_level", "")
                filter_info = "활성화" if filter_ok else "<strong style='color:orange'>비활성화(기본값)</strong>"
                rows.append([f"&nbsp;&nbsp;— XSS 전역 필터",
                             f"필터 상태: {filter_info} / 수준: {html_escape(filter_level)}",
                             "", ""])
    else:
        rows.append(["XSS (전체)", "—", "—", "—"])

    # 데이터 보호 (task25 LLM finding JSON)
    if dp_data:
        dp_findings = dp_data.get("findings", [])
        dp_vuln = sum(1 for f in dp_findings if f.get("result") == "취약")
        dp_info = sum(1 for f in dp_findings if f.get("result") == "정보")
        dp_result = "<strong>전체 양호</strong>" if dp_vuln == 0 and dp_info == 0 \
            else f"<strong style='color:red'>취약 {dp_vuln}건</strong>"
        rows.append(["데이터 보호 (전체)", dp_result,
                     f"{dp_vuln}건", f"{dp_info}건"])
        # 카테고리별 세부 분류
        cred_vuln = sum(1 for f in dp_findings
                        if "Hardcoded" in f.get("category", "") and f.get("result") == "취약")
        log_issues = sum(1 for f in dp_findings if "Logging" in f.get("category", ""))
        crypto_issues = sum(1 for f in dp_findings if "Crypto" in f.get("category", ""))
        acl_issues = sum(1 for f in dp_findings if "Access Control" in f.get("category", ""))
        if cred_vuln:
            rows.append([f"&nbsp;&nbsp;— 하드코딩 자격증명",
                         f"<strong style='color:red'>취약 {cred_vuln}건</strong>",
                         f"{cred_vuln}건", "0건"])
        if log_issues:
            log_vuln = sum(1 for f in dp_findings
                           if "Logging" in f.get("category", "") and f.get("result") == "취약")
            rows.append([f"&nbsp;&nbsp;— 민감정보 로깅",
                         f"취약 {log_vuln}건" if log_vuln else f"정보 {log_issues}건",
                         f"{log_vuln}건", f"{log_issues - log_vuln}건"])
        if crypto_issues:
            rows.append([f"&nbsp;&nbsp;— 취약 암호화",
                         f"정보 {crypto_issues}건", "0건", f"{crypto_issues}건"])
        if acl_issues:
            rows.append([f"&nbsp;&nbsp;— 접근제어",
                         f"정보 {acl_issues}건", "0건", f"{acl_issues}건"])
    else:
        rows.append(["데이터 보호 (전체)", "—", "—", "—"])

    return _table(["진단 항목", "결과", "취약 건수", "정보 건수"], rows)


def _format_api_inputs(params: list) -> str:
    """API 엔드포인트의 실제 사용자 입력값 목록을 HTML 문자열로 반환한다.

    @RequestParam / @PathVariable 파라미터는 `name(Type)` 형태로 표시한다.
    @RequestBody 파라미터는 resolved_fields(DTO 내부 필드)가 있으면 전개하여
    `[DtoClass] field1:Type1, field2:Type2` 형태로, 없으면 `name(DtoClass)` 형태로 표시한다.
    인프라 파라미터(HttpServletRequest, Authentication 등)는 제외한다.
    """
    _INFRA_TYPES = {
        "HttpServletRequest", "HttpServletResponse", "ServerHttpRequest",
        "ServerHttpResponse", "ServerWebExchange", "Authentication",
        "Principal", "BindingResult", "Model", "ModelMap",
    }

    inline_parts: list[str] = []   # 단순 파라미터
    dto_parts: list[str] = []      # DTO 전개 파라미터

    skip_sources = {"request", "response", "exchange"}

    for p in params:
        if not isinstance(p, dict):
            continue
        src = p.get("type", "")
        if src in skip_sources:
            continue

        dtype_raw = p.get("data_type", "")
        dtype_base = dtype_raw.rstrip("?").split("<")[0].split(".")[-1].rstrip("[]")
        if dtype_base in _INFRA_TYPES:
            continue

        name = p.get("name", "")
        resolved_fields = p.get("resolved_fields", [])

        if src == "body" and resolved_fields:
            # DTO 내부 필드 전개 — 실제 사용자 입력값 명시
            dto_class = html_escape(p.get("resolved_from", dtype_raw).split(".")[-1])
            fields_shown = resolved_fields[:8]
            field_strs = []
            for rf in fields_shown:
                fn = html_escape(str(rf.get("name", "")))
                ft = html_escape(str(rf.get("data_type", "")).rstrip("?").split("<")[0])
                nullable = "?" if rf.get("nullable") else ""
                field_strs.append(f"{fn}:{ft}{nullable}")
            overflow = len(resolved_fields) - len(fields_shown)
            fields_html = ", ".join(field_strs)
            if overflow > 0:
                fields_html += f" … +{overflow}필드"
            dto_parts.append(
                f"<em>[{dto_class}]</em> <code>{fields_html}</code>"
            )
        elif src == "body":
            # DTO이나 resolved_fields 미확보 — DTO 타입명만 표시
            dto_class = html_escape(dtype_base or dtype_raw)
            inline_parts.append(f"<em>[{dto_class}]</em>")
        else:
            # @RequestParam / @PathVariable 등 단순 파라미터
            type_str = html_escape(dtype_base or dtype_raw)
            inline_parts.append(
                f"<code>{html_escape(name)}</code>"
                + (f"<small>({type_str})</small>" if type_str else "")
            )

    parts = inline_parts + dto_parts
    return " ".join(parts) if parts else "—"


def _build_main_api_inventory(api_data: dict) -> str:
    """API 인벤토리 JSON 에서 엔드포인트 목록 표를 생성한다.

    @RequestBody DTO가 있는 경우 resolved_fields(DTO 내부 필드)를 전개하여
    API별 실제 사용자 입력값을 명시한다. (scan_dto.py + --dto-catalog 연동 시 동작)
    """
    endpoints = api_data.get("endpoints", [])
    if not endpoints:
        return "<p>API 인벤토리 데이터 없음</p>"

    rows = []
    for ep in endpoints:
        # scan_api.py v3 포맷: method/api  vs  이전 포맷: http_method/request_mapping
        method = ep.get("method", ep.get("http_method", ""))
        path = ep.get("api", ep.get("request_mapping", ""))
        handler = ep.get("handler", "")
        ctrl = handler.split(".")[0] if "." in handler else handler
        params = ep.get("parameters", [])

        inputs_html = _format_api_inputs(params)

        rows.append([
            f"<code>{html_escape(method)}</code>",
            f"<code>{html_escape(path)}</code>",
            html_escape(ctrl),
            inputs_html,
        ])
    return _table(["Method", "Endpoint", "Controller", "사용자 입력값"], rows)


def _json_to_xhtml_main_report(md_content: str, task_sources: dict,
                                base_dir: str) -> str:
    """통합 보고서 렌더러 (type=main_report).

    generate_finding_report.py 로 생성된 Markdown 파일을 그대로 XHTML로 변환한다.
    (--anchor-style md2cf 포맷의 ## summary-table, HTML 인라인 테이블 포함)

    이후 하위 Task 보고서 페이지 링크(children 매크로)를 추가한다.
    """
    # MD 파일 전체를 XHTML로 변환 (md2cf anchor 스타일 포함)
    xhtml = md_to_xhtml(md_content)

    # 하위 Task 보고서 링크 안내 추가
    children_macro = (
        "<h2>세부 진단 결과 (하위 페이지)</h2>"
        "<p>인젝션·XSS 등 각 항목별 상세 내용(카테고리 분류, Call Graph, "
        "코드 증적)은 하위 Task 보고서 페이지를 참조하십시오.</p>"
        '<ac:structured-macro ac:name="children">'
        '<ac:parameter ac:name="sort">title</ac:parameter>'
        '</ac:structured-macro>'
    )

    return xhtml + "\n" + children_macro


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

    # main_report: 통합 보고서 (개요+요약만, 세부 내용은 Task 페이지에)
    if entry_type == "main_report":
        task_sources = entry.get("task_sources", {})
        xhtml = _json_to_xhtml_main_report(raw, task_sources, base_dir)
        return xhtml, None

    if entry_type == "doc":
        xhtml = md_to_xhtml(raw)
        return xhtml, None

    # JSON types: finding, final_report
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        return None, f"Invalid JSON in {full_path}: {exc}"

    # supplemental_sources: finding 타입에서만 LLM 수동분석 보완 섹션을 추가로 렌더링.
    # 먼저 모든 supplemental JSON의 findings를 수집해 enhanced renderer에 전달한다.
    llm_findings: list = []
    llm_supp_data: dict = {}
    if entry_type == "finding":
        for supp_path in entry.get("supplemental_sources", []):
            supp_data = _load_json_safe(supp_path, base_dir)
            if supp_data:
                llm_findings.extend(supp_data.get("findings", []))
                if not llm_supp_data and (
                    supp_data.get("sqli_endpoint_review")
                    or supp_data.get("xss_endpoint_review")
                ):
                    llm_supp_data = supp_data

    xhtml = json_to_xhtml(
        data, entry_type, source,
        llm_findings=llm_findings or None,
        llm_supp=llm_supp_data or None,
    )

    # supplemental_sources 섹션(「LLM 수동분석 보완」)을 페이지 하단에 추가
    if entry_type == "finding":
        for supp_path in entry.get("supplemental_sources", []):
            supp_data = _load_json_safe(supp_path, base_dir)
            if supp_data:
                rendered = _json_to_xhtml_supp_findings(supp_data)
                if rendered:
                    xhtml += "\n" + rendered

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
        help="Only publish entries matching this source path (exact match).",
    )
    parser.add_argument(
        "--filter-group", default=None,
        help="Publish all entries in groups whose title contains this substring "
             "(case-insensitive). Example: --filter-group 테스트28",
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
        """Recursively filter groups by source path (exact match)."""
        filtered = []
        for g in grps:
            gc = dict(g)
            gc["entries"] = [e for e in gc.get("entries", [])
                             if e["source"] == filt]
            gc["groups"] = _filter_groups(gc.get("groups", []), filt)
            if gc["entries"] or gc["groups"] or gc.get("source") == filt:
                filtered.append(gc)
        return filtered

    def _filter_groups_by_title(grps, title_substr):
        """Recursively keep groups whose title contains title_substr (case-insensitive).
        Matching groups are kept whole (all entries preserved).
        Non-matching groups are kept only if they contain a matching descendant.
        """
        needle = title_substr.lower()
        filtered = []
        for g in grps:
            if needle in g["title"].lower():
                # entire group matches — keep as-is
                filtered.append(g)
            else:
                # check children
                gc = dict(g)
                gc["groups"] = _filter_groups_by_title(gc.get("groups", []), title_substr)
                if gc["groups"]:
                    filtered.append(gc)
        return filtered

    if args.filter and args.filter_group:
        print("[ERROR] --filter and --filter-group are mutually exclusive.", file=sys.stderr)
        sys.exit(1)
    elif args.filter:
        publish_root = (root_page and root_page.get("source") == args.filter)
        entries = [e for e in entries if e["source"] == args.filter]
        groups = _filter_groups(groups, args.filter)
        if not entries and not groups and not publish_root:
            print(f"[WARN] No entries match filter: {args.filter}", file=sys.stderr)
            sys.exit(0)
    elif args.filter_group:
        publish_root = False
        entries = []
        groups = _filter_groups_by_title(groups, args.filter_group)
        if not groups:
            print(f"[WARN] No groups match filter-group: {args.filter_group}", file=sys.stderr)
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
