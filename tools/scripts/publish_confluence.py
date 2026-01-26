#!/usr/bin/env python3
import argparse
import base64
import json
import os
import pathlib
import urllib.request
import urllib.parse

def load_dotenv(path):
    if not path.exists():
        return
    for line in path.read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if '=' not in line:
            continue
        key, val = line.split('=', 1)
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = val


ROOT = pathlib.Path(__file__).resolve().parents[2]
DEFAULT_MAP = ROOT / 'tools' / 'confluence_page_map.json'

def load_page_map(path):
    return json.loads(path.read_text(encoding='utf-8'))

def md_to_wiki(md_text):
    lines = []
    in_code = False
    code_lang = ''
    for line in md_text.splitlines():
        if line.strip().startswith('```') and not in_code:
            in_code = True
            code_lang = line.strip()[3:].strip()
            if code_lang:
                lines.append('{code:language=' + code_lang + '}')
            else:
                lines.append('{code}')
            continue
        if line.strip().startswith('```') and in_code:
            in_code = False
            code_lang = ''
            lines.append('{code}')
            continue
        if in_code:
            lines.append(line)
            continue
        if line.startswith('### '):
            lines.append('=== ' + line[4:])
        elif line.startswith('## '):
            lines.append('== ' + line[3:])
        elif line.startswith('# '):
            lines.append('= ' + line[2:])
        elif line.startswith('- '):
            lines.append('* ' + line[2:])
        else:
            lines.append(line)
    return '\n'.join(lines)

def auth_header(user, token):
    if user:
        raw = f"{user}:{token}".encode('utf-8')
        return "Basic " + base64.b64encode(raw).decode('ascii')
    return "Bearer " + token

def request_json(method, url, token, user=None, payload=None):
    data = None
    if payload is not None:
        data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header('Content-Type', 'application/json')
    req.add_header('Accept', 'application/json')
    req.add_header('Authorization', auth_header(user, token))
    try:
        with urllib.request.urlopen(req) as resp:
            body = resp.read().decode('utf-8')
            return json.loads(body) if body else {}
    except urllib.error.HTTPError as e:
        detail = e.read().decode('utf-8')
        raise SystemExit(f"HTTP {e.code} for {url}: {detail}")

def convert_wiki_to_storage(base_url, wiki, token, user=None):
    url = base_url.rstrip('/') + '/rest/api/contentbody/convert/storage'
    payload = {"value": wiki, "representation": "wiki"}
    resp = request_json('POST', url, token, user, payload)
    return resp.get('value', '')

def find_page(base_url, space_key, title, parent_id, token, user=None):
    cql = f'space="{space_key}" and title="{title}" and ancestor={parent_id}'
    params = urllib.parse.urlencode({'cql': cql, 'limit': 1})
    url = base_url.rstrip('/') + '/rest/api/content/search?' + params
    resp = request_json('GET', url, token, user)
    results = resp.get('results', [])
    return results[0] if results else None

def get_page_version(base_url, page_id, token, user=None):
    url = base_url.rstrip('/') + f'/rest/api/content/{page_id}?expand=version'
    resp = request_json('GET', url, token, user)
    return resp.get('version', {}).get('number', 1)

def create_page(base_url, space_key, parent_id, title, storage, token, user=None):
    url = base_url.rstrip('/') + '/rest/api/content'
    payload = {
        "type": "page",
        "title": title,
        "ancestors": [{"id": str(parent_id)}],
        "space": {"key": space_key},
        "body": {"storage": {"value": storage, "representation": "storage"}}
    }
    return request_json('POST', url, token, user, payload)

def update_page(base_url, page_id, title, storage, token, user=None):
    version = get_page_version(base_url, page_id, token, user) + 1
    url = base_url.rstrip('/') + f'/rest/api/content/{page_id}'
    payload = {
        "id": page_id,
        "type": "page",
        "title": title,
        "version": {"number": version},
        "body": {"storage": {"value": storage, "representation": "storage"}}
    }
    return request_json('PUT', url, token, user, payload)

def main():
    load_dotenv(ROOT / '.env')
    parser = argparse.ArgumentParser(description='Publish docs to Confluence')
    parser.add_argument('--base-url', default=os.getenv('CONFLUENCE_BASE_URL'))
    parser.add_argument('--space-key', default=os.getenv('CONFLUENCE_SPACE_KEY'))
    parser.add_argument('--parent-id', default=os.getenv('CONFLUENCE_PARENT_ID'))
    parser.add_argument('--user', default=os.getenv('CONFLUENCE_USER'))
    parser.add_argument('--token', default=os.getenv('CONFLUENCE_TOKEN'))
    parser.add_argument('--page-map', default=str(DEFAULT_MAP))
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()

    if not all([args.base_url, args.space_key, args.parent_id, args.token]):
        raise SystemExit('Missing required config: base-url, space-key, parent-id, token')

    page_map = load_page_map(pathlib.Path(args.page_map))

    for rel_path, title in page_map.items():
        src = ROOT / rel_path
        if not src.exists():
            raise SystemExit(f'Missing source file: {rel_path}')
        md = src.read_text(encoding='utf-8')
        wiki = md_to_wiki(md)
        storage = convert_wiki_to_storage(args.base_url, wiki, args.token, args.user)
        if args.dry_run:
            print(f'[DRY RUN] {rel_path} -> {title}')
            continue

        existing = find_page(args.base_url, args.space_key, title, args.parent_id, args.token, args.user)
        if existing:
            update_page(args.base_url, existing['id'], title, storage, args.token, args.user)
            print(f'Updated: {title}')
        else:
            create_page(args.base_url, args.space_key, args.parent_id, title, storage, args.token, args.user)
            print(f'Created: {title}')

if __name__ == '__main__':
    main()
