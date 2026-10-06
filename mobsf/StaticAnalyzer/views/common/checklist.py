# -*- coding: utf_8 -*-
"""MASVS / MASWE / MASTG checklist mapped from static analysis results.

Standards data comes from OWASP MAS (see ``mas_standards``). MobSF rules
carry legacy MASVS v1 tags (``MSTG-STORAGE-2``). OWASP lists those tags on
each MASWE weakness, which is the crosswalk used here:

    finding tag -> MASWE weakness -> MASVS v2 control

Each item is Success, Failed, ToBeTest or NotApplicable:

* Failed: a high/warning finding is tagged with the weakness.
* Success: every legacy tag of the weakness is covered by an automated
  rule that ran on this scan and found nothing.
* ToBeTest: anything else, it needs a manual test. Info findings and
  partially covered weaknesses land here.
* NotApplicable: wrong platform for a test, or a scan type without
  a checklist (e.g. APPX, JAR/AAR).

MASTG tests are manual procedures, so they are never marked Success or
Failed by MobSF. Their evidence points to the weakness result instead.
"""
import re
from enum import Enum
from functools import lru_cache
from pathlib import Path

from django.shortcuts import render
from django.views.decorators.http import require_http_methods

from mobsf.MobSF import settings
from mobsf.MobSF.utils import (
    is_md5,
    print_n_send_error_response,
)
from mobsf.MobSF.views.authentication import (
    login_required,
)
from mobsf.StaticAnalyzer.models import (
    StaticAnalyzerAndroid,
    StaticAnalyzerIOS,
)
from mobsf.StaticAnalyzer.views.android.db_interaction import (
    get_context_from_db_entry as adb)
from mobsf.StaticAnalyzer.views.common.mas_standards import (
    load_standards,
    refresh_if_stale,
    standards_info,
)
from mobsf.StaticAnalyzer.views.ios.db_interaction import (
    get_context_from_db_entry as idb)


class CheckStatus(Enum):
    """Checklist item status."""

    SUCCESS = 'Success'
    FAILED = 'Failed'
    TO_BE_TEST = 'ToBeTest'
    NOT_APPLICABLE = 'NotApplicable'


RULES = Path(__file__).resolve().parents[1]
RULE_FILES = {
    'android': [RULES / 'android' / 'rules' / 'android_rules.yaml'],
    'ios': [
        RULES / 'ios' / 'rules' / 'objective_c_rules.yaml',
        RULES / 'ios' / 'rules' / 'swift_rules.yaml',
        RULES / 'ios' / 'rules' / 'ipa_rules.py',
    ],
}
TAG = re.compile(
    r'\b(?:MSTG-|MASVS-)?(storage|crypto|auth|network|platform|code|'
    r'resilience)[-_ ]*(\d+)\b', re.I)
FAIL_SEV = {'high', 'warning'}
PASS_SEV = {'good', 'secure'}


def _tags(text):
    """Return legacy requirement tags (MSTG-STORAGE-2) found in text."""
    return {f'MSTG-{cat.upper()}-{int(num)}'
            for cat, num in TAG.findall(str(text or ''))}


@lru_cache(maxsize=None)
def _tested(platform):
    """Legacy tags covered by at least one automated rule."""
    tested = set()
    for path in RULE_FILES.get(platform, []):
        try:
            for line in path.read_text(encoding='utf-8').splitlines():
                if 'masvs' in line.lower():
                    tested |= _tags(line)
        except OSError:
            continue
    return tested


def _walk(obj, found):
    """Collect (tags, severity, title) from dicts with metadata.masvs."""
    if isinstance(obj, dict):
        meta = obj.get('metadata')
        if isinstance(meta, dict) and meta.get('masvs'):
            found.append((
                _tags(meta['masvs']),
                str(meta.get('severity', '')).lower(),
                meta.get('description') or meta.get('title') or ''))
        for val in obj.values():
            _walk(val, found)
    elif isinstance(obj, (list, tuple)):
        for val in obj:
            _walk(val, found)


def _item(std, item, status, evidence=None):
    return {
        'standard': std,
        'id': item['id'],
        'title': item['title'],
        'status': status.value,
        'evidence': evidence or [],
        'url': item.get('url', ''),
    }


def summarize(items):
    """Count items per status."""
    out = {s.value: 0 for s in CheckStatus}
    for i in items:
        out[i['status']] += 1
    return out


def _collect(data):
    """Group finding titles by tag and severity class."""
    found = []
    _walk(data, found)
    failed, passed, review = {}, {}, {}
    for tags, sev, title in found:
        if sev in FAIL_SEV:
            bucket = failed
        elif sev in PASS_SEV:
            bucket = passed
        else:
            bucket = review
        for tag in tags:
            bucket.setdefault(tag, []).append(title)
    return failed, passed, review


def _maswe_status(weak, tested, failed, passed, review):
    """Return (status, evidence) for one weakness."""
    tags = weak['masvs_v1']
    hits = [t for t in tags if t in failed]
    if hits:
        titles = [x for t in hits for x in failed[t]]
        return CheckStatus.FAILED, list(dict.fromkeys(titles))
    notes = [x for t in tags for x in review.get(t, [])]
    covered = bool(tags) and all(
        t in tested or t in passed for t in tags)
    if covered and not notes:
        return CheckStatus.SUCCESS, []
    return CheckStatus.TO_BE_TEST, list(dict.fromkeys(notes))


def _masvs_status(weaknesses, maswe_status):
    """Aggregate the weaknesses of a control into one status."""
    sts = [maswe_status[w] for w in weaknesses if w in maswe_status]
    if CheckStatus.FAILED in sts:
        return CheckStatus.FAILED
    if sts and all(s == CheckStatus.SUCCESS for s in sts):
        return CheckStatus.SUCCESS
    return CheckStatus.TO_BE_TEST


def build_checklist(data, platform, standards=None):
    """Build MASVS, MASWE and MASTG checklists from a static context."""
    standards = standards or load_standards()
    applicable = platform in RULE_FILES
    failed, passed, review = _collect(data)
    tested = _tested(platform)
    na = CheckStatus.NOT_APPLICABLE

    maswe_items, maswe_status, maswe_ev = [], {}, {}
    for weak in standards['maswe']:
        if applicable:
            status, ev = _maswe_status(weak, tested, failed, passed, review)
        else:
            status, ev = na, []
        maswe_status[weak['id']] = status
        maswe_ev[weak['id']] = ev
        maswe_items.append(_item('MASWE', weak, status, ev))

    masvs_items = []
    for ctl in standards['masvs']:
        # Union of the control's own list and weaknesses mapping to it
        weaknesses = list(dict.fromkeys(ctl['weaknesses'] + [
            w['id'] for w in standards['maswe']
            if ctl['id'] in w['masvs_v2']]))
        status = _masvs_status(weaknesses, maswe_status) if applicable else na
        related = [w for w in weaknesses
                   if maswe_status.get(w) == CheckStatus.FAILED]
        masvs_items.append(_item('MASVS', ctl, status, related))

    parent = {}
    for weak in standards['maswe']:
        for test in weak['tests']:
            parent.setdefault(test, []).append(weak['id'])
    mastg_items = []
    for test in standards['mastg']:
        if test['deprecated']:
            continue
        if not applicable or test['platform'] != platform:
            status, ev = na, []
        else:
            status = CheckStatus.TO_BE_TEST
            ev = [f'{w} {maswe_status[w].value} in automated scan'
                  for w in parent.get(test['id'], [])
                  if maswe_status.get(w) == CheckStatus.FAILED]
        mastg_items.append(_item('MASTG', test, status, ev))

    return {
        'source': standards_info(standards),
        'MASVS': {'items': masvs_items, 'summary': summarize(masvs_items)},
        'MASWE': {'items': maswe_items, 'summary': summarize(maswe_items)},
        'MASTG': {'items': mastg_items, 'summary': summarize(mastg_items)},
    }


@login_required
@require_http_methods(['GET'])
def checklist_page(request, checksum, api=False):
    """Dedicated MASVS/MASWE/MASTG checklist page for a scanned app."""
    if not is_md5(checksum):
        return print_n_send_error_response(request, 'Invalid Hash', api)
    android = StaticAnalyzerAndroid.objects.filter(MD5=checksum).first()
    ios = StaticAnalyzerIOS.objects.filter(MD5=checksum).first()
    if android:
        data, platform = adb([android]), 'android'
    elif ios:
        data, platform = idb([ios]), 'ios'
    else:
        msg = 'Report not found or supported'
        if api:
            return {'not_found': msg}
        return print_n_send_error_response(request, msg, api)
    refresh_if_stale()
    checklist = build_checklist(data, platform)
    sections = [(n, checklist[n]) for n in ('MASVS', 'MASWE', 'MASTG')]
    context = {
        'checklist': checklist,
        'sections': sections,
        'source': checklist['source'],
        'summary': {n: c['summary'] for n, c in sections},
        'platform': platform,
        'hash': checksum,
        'file_name': data.get('file_name', ''),
        'app_name': data.get('app_name', ''),
        'version': settings.MOBSF_VER,
        'title': 'Security Checklist',
    }
    if api:
        return context
    return render(request, 'static_analysis/checklist.html', context)
