# -*- coding: utf_8 -*-
"""MASVS / MASTG / MASWE checklist mapped from static analysis results.

Every scanned app gets three checklists. Each item is one of
Success, Failed, ToBeTest or NotApplicable.

* Failed:  a finding tagged with the item has severity high/warning.
* Success: a rule covering the item ran for this platform and did not fail.
* ToBeTest: no automated rule covers the item, so it needs manual testing.
* NotApplicable: the scan type has no checklist (e.g. APPX, JAR/AAR).
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
# Requirement count per category (MASVS v1 / MASTG requirement ids)
MSTG_COUNTS = {
    'STORAGE': 15, 'CRYPTO': 6, 'AUTH': 12, 'NETWORK': 6,
    'PLATFORM': 11, 'CODE': 9, 'RESILIENCE': 13,
}
# MASVS v2 controls per category
MASVS_COUNTS = {
    'STORAGE': 2, 'CRYPTO': 2, 'AUTH': 3, 'NETWORK': 2,
    'PLATFORM': 3, 'CODE': 4, 'RESILIENCE': 4, 'PRIVACY': 4,
}
TAG = re.compile(
    r'\b(?:MSTG-|MASVS-)?(storage|crypto|auth|network|platform|code|'
    r'resilience)[-_ ]*(\d+)\b', re.I)
FAIL_SEV = {'high', 'warning'}
PASS_SEV = {'good', 'secure'}


def _tags(text):
    """Return a set of (CATEGORY, number) tags found in text."""
    return {(c.upper(), int(n)) for c, n in TAG.findall(str(text or ''))}


@lru_cache(maxsize=None)
def _tested(platform):
    """Requirements covered by at least one automated rule."""
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
    """Collect (tags, severity, title) from any dict with metadata.masvs."""
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


def _item(std, item_id, title, status, evidence=None):
    return {
        'standard': std,
        'id': item_id,
        'title': title,
        'status': status.value,
        'evidence': evidence or [],
    }


def _agg(statuses):
    if CheckStatus.FAILED in statuses:
        return CheckStatus.FAILED
    if CheckStatus.TO_BE_TEST in statuses:
        return CheckStatus.TO_BE_TEST
    if CheckStatus.SUCCESS in statuses:
        return CheckStatus.SUCCESS
    return CheckStatus.NOT_APPLICABLE


def _masvs_status(cat, mastg, review, applicable):
    """Aggregate MASTG items of a category into one status.

    Failed if any test failed, ToBeTest if a finding needs review,
    Success if automated tests ran clean, else ToBeTest.
    """
    if not applicable:
        return CheckStatus.NOT_APPLICABLE
    items = [i for i in mastg if i['id'].split('-')[1] == cat]
    sts = {i['status'] for i in items}
    if CheckStatus.FAILED.value in sts:
        return CheckStatus.FAILED
    if any(i['evidence'] for i in items):
        return CheckStatus.TO_BE_TEST
    if CheckStatus.SUCCESS.value in sts:
        return CheckStatus.SUCCESS
    return CheckStatus.TO_BE_TEST


def summarize(items):
    out = {s.value: 0 for s in CheckStatus}
    for i in items:
        out[i['status']] += 1
    return out


def build_checklist(data, platform):
    """Build MASVS, MASTG and MASWE checklists from a static context."""
    found = []
    _walk(data, found)
    failed, passed, review = {}, {}, {}
    for tags, sev, title in found:
        for tag in tags:
            if sev in FAIL_SEV:
                failed.setdefault(tag, []).append(title)
            elif sev in PASS_SEV:
                passed.setdefault(tag, []).append(title)
            else:
                review.setdefault(tag, []).append(title)
    tested = _tested(platform)
    applicable = platform in RULE_FILES

    def status_of(tag):
        if not applicable:
            return CheckStatus.NOT_APPLICABLE
        if tag in failed:
            return CheckStatus.FAILED
        if tag in review and tag not in passed:
            return CheckStatus.TO_BE_TEST
        if tag in tested or tag in passed:
            return CheckStatus.SUCCESS
        return CheckStatus.TO_BE_TEST

    # MASTG: one item per requirement id
    mastg = []
    for cat, count in MSTG_COUNTS.items():
        for num in range(1, count + 1):
            tag = (cat, num)
            mastg.append(_item(
                'MASTG', f'MSTG-{cat}-{num}', f'{cat.title()} {num}',
                status_of(tag),
                failed.get(tag) or review.get(tag)))

    # MASVS v2: one item per category control, aggregated from MASTG items
    masvs = []
    for cat, count in MASVS_COUNTS.items():
        status = _masvs_status(cat, mastg, review, applicable)
        for num in range(1, count + 1):
            masvs.append(_item(
                'MASVS', f'MASVS-{cat}-{num}', f'{cat.title()} {num}',
                status))

    # MASWE: each distinct failing weakness, plus per-category coverage
    maswe = []
    for (cat, num), titles in sorted(failed.items()):
        for title in dict.fromkeys(titles):
            maswe.append(_item(
                'MASWE', f'MASWE-{cat}', title, CheckStatus.FAILED,
                [f'MSTG-{cat}-{num}']))
    for cat in MSTG_COUNTS:
        if not any(i['standard'] == 'MASWE' and i['id'] == f'MASWE-{cat}'
                   for i in maswe):
            maswe.append(_item(
                'MASWE', f'MASWE-{cat}', f'{cat.title()} weaknesses',
                _masvs_status(cat, mastg, review, applicable)))

    return {
        'MASVS': {'items': masvs, 'summary': summarize(masvs)},
        'MASTG': {'items': mastg, 'summary': summarize(mastg)},
        'MASWE': {'items': maswe, 'summary': summarize(maswe)},
    }


@login_required
@require_http_methods(['GET'])
def checklist_page(request, checksum, api=False):
    """Dedicated MASVS/MASTG/MASWE checklist page for a scanned app."""
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
    checklist = build_checklist(data, platform)
    context = {
        'checklist': checklist,
        'summary': {k: v['summary'] for k, v in checklist.items()},
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
