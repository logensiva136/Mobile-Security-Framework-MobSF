# -*- coding: utf_8 -*-
"""OWASP MAS standards data (MASVS, MASWE, MASTG).

The data is parsed from the public search index of https://mas.owasp.org/.
A bundled snapshot works offline. A fresher copy, written under MOBSF_HOME,
takes precedence. Every copy records when it was retrieved so each
assessment can show how current the checklist is.
"""
import hashlib
import json
import logging
import os
import re
import threading
import time
from datetime import datetime, timezone
from html import unescape
from pathlib import Path

from django.conf import settings

from mobsf.MobSF.security import safe_request

logger = logging.getLogger(__name__)

SITE = 'https://mas.owasp.org/'
SOURCE_URL = f'{SITE}search/search_index.json'
MAX_BYTES = 30 * 1024 * 1024
MAX_AGE_DAYS = 30
RETRY_SECONDS = 24 * 3600
SNAPSHOT = (Path(__file__).resolve().parents[2]
            / 'mas_data' / 'mas_standards.json')
SAFE_LOCATION = re.compile(r'^[A-Za-z0-9/_.-]+$')
MASVS_RE = re.compile(r'^MASVS/controls/(MASVS-[A-Z]+-\d+)/$')
MASWE_RE = re.compile(r'^MASWE/(MASVS-[A-Z]+)/(MASWE-\d{4})/$')
MASTG_RE = re.compile(
    r'^MASTG/tests/(android|ios)/(MASVS-[A-Z]+)/(MASTG-TEST-\d{4})/$')
TAG_RE = re.compile(r'<[^>]+>')
TECH_RE = re.compile(
    r'^MASTG/techniques/([a-z]+)/(MASTG-TECH-\d{4})/$')
TOOL_RE = re.compile(
    r'^MASTG/tools/([a-z]+)/(MASTG-TOOL-\d{4})/$')
PLATFORM_SUFFIX = re.compile(r'\s*\((?:Android|iOS)\)$')
MAX_REFS = 8
V1_RE = re.compile(r'MSTG-[A-Z]+-\d+')
V2_RE = re.compile(r'MASVS-[A-Z]+-\d+')
WEAK_RE = re.compile(r'MASWE-\d{4}')
CWE_RE = re.compile(r'CWE-\d+')
CWE_STOP = ('MASVS V1:', 'MASVS V2:', 'Android ', 'iOS ',
            'MAS Requirement', 'Platform')
SCHEMA = 3
TEST_RE = re.compile(r'MASTG-TEST-\d{4}')

_lock = threading.Lock()
_cache = {'key': None, 'data': None}
_state = {'last_attempt': 0.0}


def _text(html):
    """Return plain text from an HTML fragment."""
    return re.sub(r'\s+', ' ', unescape(TAG_RE.sub(' ', html or ''))).strip()


def _lines(html, limit=1200):
    """Return readable text from HTML, keeping list items on own lines."""
    html = re.sub(r'</(li|p|ul|ol|h\d)>|<br\s*/?>', '\n', html or '')
    html = re.sub(r'<li[^>]*>', '- ', html)
    text = unescape(TAG_RE.sub(' ', html))
    lines = [re.sub(r'\s+', ' ', line).strip()
             for line in text.split('\n')]
    out = '\n'.join(line for line in lines if line and line != '-')
    return out if len(out) <= limit else out[:limit].rstrip() + '...'


def _section(docs, loc, name, limit=1200):
    return _lines(docs.get(f'{loc}#{name}', {}).get('text'), limit)


def _refs(docs, regex):
    """Return {(platform, id): (title, url)} for technique/tool pages."""
    refs = {}
    for loc, doc in docs.items():
        match = regex.match(loc)
        if match:
            title = _split_title(doc.get('title', ''), match.group(2))
            refs[(match.group(1), match.group(2))] = (title, _url(loc))
    return refs


def _mentioned(refs, platform, text, strip_platform=False):
    """List refs of this platform (or generic) named in the text."""
    found = []
    for (plat, ident), (title, url) in sorted(refs.items(),
                                              key=lambda kv: kv[0][1]):
        if plat not in (platform, 'generic'):
            continue
        name = PLATFORM_SUFFIX.sub('', title) if strip_platform else title
        if len(name) < 4:
            continue
        pattern = r'(?<![A-Za-z0-9])' + re.escape(name) + r'(?![A-Za-z0-9])'
        if re.search(pattern, text):
            found.append({'id': ident, 'title': title, 'url': url})
    return found[:MAX_REFS]


def _unique(items):
    return list(dict.fromkeys(items))


def _url(location):
    if SAFE_LOCATION.match(location):
        return SITE + location
    return ''


def _split_title(title, ident):
    prefix = f'{ident}:'
    if title.startswith(prefix):
        return title[len(prefix):].strip()
    return title.strip()


def _segment(text, start, stops):
    """Return text after label start up to the first stop label."""
    pos = text.find(start)
    if pos < 0:
        return ''
    seg = text[pos + len(start):]
    cut = [seg.find(s) for s in stops if seg.find(s) >= 0]
    return seg[:min(cut)] if cut else seg[:400]


def parse_search_index(index, retrieved_at=None, sha256=''):
    """Parse the mas.owasp.org search index into checklist data."""
    docs = {d['location']: d for d in index.get('docs', [])}
    masvs, maswe, mastg = [], [], []
    techs = _refs(docs, TECH_RE)
    tools = _refs(docs, TOOL_RE)
    for loc, doc in docs.items():
        match = MASVS_RE.match(loc)
        if match:
            ident = match.group(1)
            first = re.search(r'<p>(.*?)</p>', doc.get('text', ''), re.S)
            rel = docs.get(f'{loc}#related-weaknesses', {})
            masvs.append({
                'id': ident,
                'category': ident.rsplit('-', 1)[0],
                'title': _text(first.group(1)) if first else ident,
                'weaknesses': _unique(
                    WEAK_RE.findall(_text(rel.get('text')))),
                'url': _url(loc),
            })
            continue
        match = MASWE_RE.match(loc)
        if match:
            cat, ident = match.groups()
            text = _text(doc.get('text'))
            v1 = _segment(text, 'MASVS V1:', ['MASVS V2:', 'CWE:'])
            v2 = _segment(text, 'MASVS V2:', ['CWE:', 'MASVS V1:'])
            cwe = _segment(text, 'CWE:', CWE_STOP)
            tests = docs.get(f'{loc}#tests', {})
            maswe.append({
                'id': ident,
                'title': _split_title(doc.get('title', ''), ident),
                'category': cat,
                'masvs_v1': _unique(V1_RE.findall(v1)),
                'masvs_v2': _unique(V2_RE.findall(v2)),
                'cwe': _unique(CWE_RE.findall(cwe)),
                'tests': _unique(TEST_RE.findall(_text(tests.get('text')))),
                'overview': _section(docs, loc, 'overview', 700),
                'modes': _section(docs, loc, 'modes-of-introduction', 900),
                'impact': _section(docs, loc, 'impact', 700),
                'mitigations': _section(docs, loc, 'mitigations', 900),
                'url': _url(loc),
            })
            continue
        match = MASTG_RE.match(loc)
        if match:
            platform, cat, ident = match.groups()
            steps = _section(docs, loc, 'steps', 1500)
            overview = _section(docs, loc, 'overview', 700)
            context = f'{steps} {overview}'
            mastg.append({
                'id': ident,
                'title': _split_title(doc.get('title', ''), ident),
                'platform': platform,
                'category': cat,
                'deprecated': 'Deprecated Test' in (doc.get('text') or ''),
                'overview': overview,
                'steps': steps,
                'observation': _section(docs, loc, 'observation', 500),
                'evaluation': _section(docs, loc, 'evaluation', 900),
                'techniques': _mentioned(techs, platform, context),
                'tools': _mentioned(tools, platform, context, True),
                'url': _url(loc),
            })
    masvs.sort(key=lambda i: i['id'])
    maswe.sort(key=lambda i: i['id'])
    mastg.sort(key=lambda i: (i['id'], i['platform']))
    return {
        'meta': {
            'source': 'OWASP MAS',
            'schema': SCHEMA,
            'source_url': SOURCE_URL,
            'retrieved_at': retrieved_at or datetime.now(
                timezone.utc).isoformat(timespec='seconds'),
            'index_sha256': sha256,
            'counts': {
                'masvs': len(masvs),
                'maswe': len(maswe),
                'mastg': len(mastg),
            },
        },
        'masvs': masvs,
        'maswe': maswe,
        'mastg': mastg,
    }


def is_valid(data):
    """Check that loaded data has the expected shape."""
    try:
        return (isinstance(data, dict)
                and all(isinstance(data.get(k), list) and data[k]
                        for k in ('masvs', 'maswe', 'mastg'))
                and isinstance(data.get('meta'), dict)
                and data['meta'].get('schema') == SCHEMA
                and bool(data['meta'].get('retrieved_at')))
    except (AttributeError, TypeError):
        return False


def _local_path():
    return Path(settings.MOBSF_HOME) / 'mas' / 'mas_standards.json'


def _read(path):
    with open(path, 'r', encoding='utf-8') as fp:
        data = json.load(fp)
    if not is_valid(data):
        raise ValueError(f'Invalid MAS standards data in {path}')
    return data


def load_standards():
    """Return the newest valid standards data (local copy or snapshot)."""
    for path in (_local_path(), SNAPSHOT):
        try:
            stamp = (str(path), path.stat().st_mtime)
            if _cache['key'] == stamp:
                return _cache['data']
            data = _read(path)
            _cache.update(key=stamp, data=data)
            return data
        except (OSError, ValueError):
            continue
    raise RuntimeError('OWASP MAS standards data is not available')


def _parse_time(value):
    try:
        stamp = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    return stamp


def standards_info(data=None):
    """Return source details and freshness for display in reports."""
    data = data or load_standards()
    meta = dict(data['meta'])
    stamp = _parse_time(meta.get('retrieved_at'))
    age = (datetime.now(timezone.utc) - stamp).days if stamp else None
    meta['retrieved_display'] = (
        stamp.strftime('%Y-%m-%d %H:%M UTC') if stamp else 'unknown')
    meta['age_days'] = age
    meta['stale'] = age is None or age > MAX_AGE_DAYS
    meta['max_age_days'] = MAX_AGE_DAYS
    return meta


def update_standards():
    """Download, parse and store the latest standards. Return its meta."""
    response = safe_request(
        'GET',
        SOURCE_URL,
        allowed_ports=(443,),
        max_redirects=0,
        max_response_size=MAX_BYTES,
        timeout=60,
        headers={'User-Agent': 'MobSF-MAS-Updater'})
    if response.status_code != 200:
        raise ValueError(f'MAS source returned HTTP {response.status_code}')
    raw = response.content
    data = parse_search_index(
        json.loads(raw), sha256=hashlib.sha256(raw).hexdigest())
    if not is_valid(data):
        raise ValueError('Downloaded MAS data failed validation')
    path = _local_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix('.tmp')
    with open(tmp, 'w', encoding='utf-8') as fp:
        json.dump(data, fp, indent=1)
    os.replace(tmp, path)
    logger.info('Updated OWASP MAS checklists: %s', data['meta']['counts'])
    return data['meta']


def _refresh():
    try:
        update_standards()
    except Exception:
        logger.warning('Could not update OWASP MAS checklists')


def refresh_if_stale():
    """Refresh stale data in the background, at most once a day."""
    if not getattr(settings, 'MAS_AUTO_UPDATE', True):
        return False
    if not standards_info()['stale']:
        return False
    with _lock:
        now = time.time()
        if now - _state['last_attempt'] < RETRY_SECONDS:
            return False
        _state['last_attempt'] = now
    threading.Thread(target=_refresh, daemon=True).start()
    return True
