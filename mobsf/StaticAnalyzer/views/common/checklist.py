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

Testers can record a decision per item. It replaces the automated status,
except that it never hides an automated Failed. Both are kept, together
with who decided and when.
"""
import csv
import io
import json
import logging
import re
from enum import Enum
from functools import lru_cache
from pathlib import Path

import yaml

from django.conf import settings as django_settings
from django.contrib.auth import get_user_model
from django.http import HttpResponse, JsonResponse
from django.shortcuts import render
from django.utils import timezone
from django.views.decorators.http import require_http_methods

from mobsf.MobSF import settings
from mobsf.MobSF.forms import FormUtil
from mobsf.MobSF.security import (
    sanitize_filename,
    sanitize_for_logging,
)
from mobsf.MobSF.utils import (
    is_md5,
    print_n_send_error_response,
)
from mobsf.MobSF.views.authentication import (
    login_required,
)
from mobsf.MobSF.views.authorization import (
    Permissions,
    has_permission,
    permission_required,
)
from mobsf.StaticAnalyzer.forms import (
    ChecklistAssignForm,
    ChecklistEngagementForm,
    ChecklistExportForm,
    ChecklistItemForm,
    ChecklistReviewForm,
)
from mobsf.StaticAnalyzer.models import (
    ChecklistAssignment,
    ChecklistEngagement,
    ChecklistEvidence,
    ChecklistReview,
    ChecklistReviewLog,
    StaticAnalyzerAndroid,
    StaticAnalyzerIOS,
)
from mobsf.StaticAnalyzer.views.android.db_interaction import (
    get_context_from_db_entry as adb)
from mobsf.StaticAnalyzer.views.common.checklist_data import (
    PROFILE_ORDER,
    actor_name,
    load_engagement,
    log_action,
    report_links,
)
from mobsf.StaticAnalyzer.views.common.mas_standards import (
    load_standards,
    refresh_if_stale,
    standards_info,
)
from mobsf.StaticAnalyzer.views.ios.db_interaction import (
    get_context_from_db_entry as idb)

logger = logging.getLogger(__name__)


class CheckStatus(Enum):
    """Checklist item status."""

    SUCCESS = 'Success'
    FAILED = 'Failed'
    TO_BE_TEST = 'ToBeTest'
    NOT_APPLICABLE = 'NotApplicable'


RULES = Path(__file__).resolve().parents[1]
RULE_FILES = {
    'android': [
        RULES / 'android' / 'rules' / 'android_rules.yaml',
        RULES / 'android' / 'rules' / 'android_apis.yaml',
    ],
    'ios': [
        RULES / 'ios' / 'rules' / 'objective_c_rules.yaml',
        RULES / 'ios' / 'rules' / 'swift_rules.yaml',
        RULES / 'ios' / 'rules' / 'ipa_rules.py',
    ],
}
# API rules that only run on source (zip) scans, not on IPA binaries
SOURCE_RULE_FILES = {
    'ios': [RULES / 'ios' / 'rules' / 'ios_apis.yaml'],
}
TAG = re.compile(
    r'\b(?:MSTG-|MASVS-)?(storage|crypto|auth|network|platform|code|'
    r'resilience)[-_ ]*(\d+)\b', re.I)
CWE = re.compile(r'cwe-?(\d+)', re.I)
MASWE_ID = re.compile(r'MASWE-\d{4}')
FAIL_SEV = {'high', 'warning'}
PASS_SEV = {'good', 'secure'}


def _cwe_tags(text):
    """Return CWE ids (CWE-295) found in text."""
    return {f'CWE-{num}' for num in CWE.findall(str(text or ''))}


def _maswe_tags(text):
    """Return MASWE ids a rule explicitly evidences."""
    return set(MASWE_ID.findall(str(text or '')))


def _tags(text):
    """Return legacy requirement tags (MSTG-STORAGE-2) found in text."""
    return {f'MSTG-{cat.upper()}-{int(num)}'
            for cat, num in TAG.findall(str(text or ''))}


def _label(text, limit=80):
    """Collapse whitespace and cap the length of a label."""
    return re.sub(r'\s+', ' ', str(text or '')).strip()[:limit]


def _yaml_rules(path):
    """Yield (label, tags) for each rule in a YAML rule file."""
    rules = yaml.safe_load(path.read_text(encoding='utf-8')) or []
    for rule in rules:
        meta = rule.get('metadata') or {}
        tags = (_tags(meta.get('masvs'))
                | _cwe_tags(meta.get('cwe'))
                | _maswe_tags(meta.get('maswe')))
        yield _label(rule.get('message') or rule.get('id')), tags


def _python_rules(path):
    """Yield (label, tags) for each rule in the IPA binary rule file."""
    text = path.read_text(encoding='utf-8')
    for block in text.split('\n    {\n')[1:]:
        match = re.search(r"'description': '([^']+)'", block)
        tags = set()
        for line in block.splitlines():
            low = line.lower()
            if 'masvs' in low:
                tags |= _tags(line)
            if 'cwe' in low:
                tags |= _cwe_tags(line)
        yield _label(match.group(1) if match else 'IPA binary rule'), tags


@lru_cache(maxsize=None)
def _tested(platform, source=False):
    """Map each tag covered by an automated rule to the rule labels."""
    tested = {}
    files = list(RULE_FILES.get(platform, []))
    if source:
        files += SOURCE_RULE_FILES.get(platform, [])
    for path in files:
        try:
            rules = (_python_rules(path) if path.suffix == '.py'
                     else _yaml_rules(path))
            for label, tags in rules:
                for tag in tags:
                    labels = tested.setdefault(tag, [])
                    if label not in labels:
                        labels.append(label)
        except (OSError, yaml.YAMLError):
            continue
    return tested


def _walk(obj, found):
    """Collect (tags, severity, title, files) from rule findings."""
    if isinstance(obj, dict):
        meta = obj.get('metadata')
        if isinstance(meta, dict) and (
                meta.get('masvs') or meta.get('cwe')
                or meta.get('maswe')):
            found.append((
                _tags(meta.get('masvs'))
                | _cwe_tags(meta.get('cwe'))
                | _maswe_tags(meta.get('maswe')),
                str(meta.get('severity', '')).lower(),
                meta.get('description') or meta.get('title') or '',
                obj.get('files')))
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
        'automated_status': status.value,
        'evidence': evidence or [],
        'url': item.get('url', ''),
        'review': None,
        'review_status': '',
        'review_note': '',
        'files': [],
        'assignee': '',
        'guide': None,
    }


def _with_review(item, reviews, files=None, assignments=None):
    """Apply a tester decision, never hiding an automated Failed."""
    key = (item['standard'], item['id'])
    item['files'] = (files or {}).get(key, [])
    item['assignee'] = (assignments or {}).get(key, '')
    review = (reviews or {}).get(key)
    if review:
        item['review'] = review
        item['review_status'] = review['status']
        item['review_note'] = review['note']
        if item['automated_status'] != CheckStatus.FAILED.value:
            item['status'] = review['status']
    return item


def summarize(items):
    """Count items per status."""
    out = {s.value: 0 for s in CheckStatus}
    for i in items:
        out[i['status']] += 1
    return out


def _describe(title, sev, files):
    """Describe a finding: title, severity and where it was found."""
    text = _label(title, 160)
    if sev:
        text += f' [{sev}]'
    if isinstance(files, dict) and files:
        shown = [f'{_label(path, 60)} ({_label(lines, 30)})'
                 for path, lines in list(files.items())[:3]]
        text += ' in ' + ', '.join(shown)
        if len(files) > 3:
            text += f' +{len(files) - 3} more'
    return text


def _names(labels, limit=3):
    """Join rule labels, capping how many are listed."""
    shown = '; '.join(labels[:limit])
    more = len(labels) - limit
    return shown + (f' (+{more} more)' if more > 0 else '')


def _collect(data):
    """Group finding titles by tag and severity class."""
    found = []
    _walk(data, found)
    failed, passed, review = {}, {}, {}
    for tags, sev, title, files in found:
        text = _describe(title, sev, files)
        if sev in FAIL_SEV:
            bucket = failed
        elif sev in PASS_SEV:
            bucket = passed
        else:
            bucket = review
        for tag in tags:
            bucket.setdefault(tag, []).append(text)
    return failed, passed, review


def _maswe_status(weak, tested, failed, passed, review):
    """Return (status, evidence) for one weakness.

    A rule that names the weakness itself (``maswe`` metadata) decides it.
    Otherwise legacy MSTG tags are used, and for weaknesses without them
    the CWE ids OWASP lists on the weakness. The evidence says why.
    """
    if weak['id'] in tested:
        tags = [weak['id']]
    else:
        tags = weak['masvs_v1'] or weak.get('cwe', [])
    hits = [t for t in tags if t in failed]
    if hits:
        titles = [f'{x} ({t})' if t.startswith('CWE') else x
                  for t in hits for x in failed[t]]
        return CheckStatus.FAILED, list(dict.fromkeys(titles))
    notes = list(dict.fromkeys(x for t in tags for x in review.get(t, [])))
    covered = [t for t in tags if t in tested or t in passed]
    rules = list(dict.fromkeys(
        label for t in covered for label in tested.get(t, [])))
    if tags and len(covered) == len(tags) and not notes:
        if rules:
            return CheckStatus.SUCCESS, [
                f'Automated check passed, no findings from: {_names(rules)}']
        return CheckStatus.SUCCESS, ['Automated check passed']
    if notes:
        return CheckStatus.TO_BE_TEST, notes
    if covered:
        return CheckStatus.TO_BE_TEST, [
            f'Partly covered by: {_names(rules)}. '
            'The rest needs manual testing.']
    return CheckStatus.TO_BE_TEST, [
        'No automated rule covers this weakness. Test it manually.']


def _masvs_evidence(weaknesses, maswe_status):
    """Explain a control status from its related weaknesses."""
    sts = [maswe_status[w] for w in weaknesses if w in maswe_status]
    failed = [w for w in weaknesses
              if maswe_status.get(w) == CheckStatus.FAILED]
    if failed:
        return ['Failed weaknesses: ' + ', '.join(failed)]
    if not sts:
        return ['No related weaknesses are listed by OWASP']
    ok = sum(1 for s in sts if s == CheckStatus.SUCCESS)
    if ok == len(sts):
        return [f'All {ok} related weaknesses passed automated checks']
    return [f'{ok} of {len(sts)} related weaknesses passed automated '
            'checks, the rest need manual testing']


def _masvs_status(weaknesses, maswe_status):
    """Aggregate the weaknesses of a control into one status."""
    sts = [maswe_status[w] for w in weaknesses if w in maswe_status]
    if CheckStatus.FAILED in sts:
        return CheckStatus.FAILED
    if sts and all(s == CheckStatus.SUCCESS for s in sts):
        return CheckStatus.SUCCESS
    return CheckStatus.TO_BE_TEST


def build_checklist(
        data, platform, standards=None, reviews=None, files=None,
        assignments=None):
    """Build MASVS, MASWE and MASTG checklists from a static context.

    reviews maps (standard, item id) to a tester decision dict and
    files maps it to the list of attached evidence files and
    assignments maps it to the username it is assigned to.
    """
    standards = standards or load_standards()
    applicable = platform in RULE_FILES
    failed, passed, review = _collect(data)
    source = str(data.get('file_name', '')).lower().endswith('.zip')
    tested = _tested(platform, source)
    na = CheckStatus.NOT_APPLICABLE

    maswe_items, maswe_status = [], {}
    for weak in standards['maswe']:
        if applicable:
            status, ev = _maswe_status(weak, tested, failed, passed, review)
        else:
            status, ev = na, ['No checklist for this scan type']
        item = _with_review(
            _item('MASWE', weak, status, ev), reviews, files, assignments)
        maswe_status[weak['id']] = CheckStatus(item['status'])
        maswe_items.append(item)

    masvs_items = []
    for ctl in standards['masvs']:
        # Union of the control's own list and weaknesses mapping to it
        weaknesses = list(dict.fromkeys(ctl['weaknesses'] + [
            w['id'] for w in standards['maswe']
            if ctl['id'] in w['masvs_v2']]))
        status = _masvs_status(weaknesses, maswe_status) if applicable else na
        related = (_masvs_evidence(weaknesses, maswe_status)
                   if applicable else ['No checklist for this scan type'])
        masvs_items.append(
            _with_review(
                _item('MASVS', ctl, status, related), reviews, files, assignments))

    parent = {}
    for weak in standards['maswe']:
        for test in weak['tests']:
            parent.setdefault(test, []).append(weak['id'])
    mastg_items = []
    for test in standards['mastg']:
        if test['deprecated']:
            continue
        if not applicable:
            status, ev = na, ['No checklist for this scan type']
        elif test['platform'] != platform:
            status = na
            ev = [f"This test applies to {test['platform']} apps only"]
        else:
            status = CheckStatus.TO_BE_TEST
            ev = [f'{w} {maswe_status[w].value} in automated scan'
                  for w in parent.get(test['id'], [])
                  if maswe_status.get(w) == CheckStatus.FAILED]
            ev.append('Manual test procedure. MobSF does not run it '
                      'automatically.')
        mastg_items.append(
            _with_review(
                _item('MASTG', test, status, ev), reviews, files, assignments))

    return {
        'source': standards_info(standards),
        'MASVS': {'items': masvs_items, 'summary': summarize(masvs_items)},
        'MASWE': {'items': maswe_items, 'summary': summarize(maswe_items)},
        'MASTG': {'items': mastg_items, 'summary': summarize(mastg_items)},
    }


def load_scan(checksum):
    """Return (static analysis context, platform) or (None, None)."""
    android = StaticAnalyzerAndroid.objects.filter(MD5=checksum).first()
    if android:
        return adb([android]), 'android'
    ios = StaticAnalyzerIOS.objects.filter(MD5=checksum).first()
    if ios:
        return idb([ios]), 'ios'
    return None, None


def load_reviews(checksum):
    """Return tester decisions for a scan keyed by (standard, item id)."""
    return {
        (r.STANDARD, r.ITEM_ID): {
            'status': r.STATUS,
            'note': r.NOTE,
            'reviewer': r.REVIEWER,
            'updated_at': r.UPDATED_AT.strftime('%Y-%m-%d %H:%M UTC'),
        }
        for r in ChecklistReview.objects.filter(MD5=checksum)
    }


GUIDE_DEFAULTS = {
    'what': '', 'when': '', 'how': '', 'expect': '', 'impact': '',
    'fix': '', 'tools': [], 'techniques': [], 'links': [],
}


def _guide(**values):
    """Return a guide with every key present."""
    guide = {k: (list(v) if isinstance(v, list) else v)
             for k, v in GUIDE_DEFAULTS.items()}
    guide.update(values)
    return guide


def _refs_of(tests, key):
    """Union of technique/tool references of several tests."""
    seen = {}
    for test in tests:
        for ref in test.get(key, []):
            seen.setdefault(ref['id'], ref)
    return list(seen.values())[:8]


def _test_links(tests):
    return [{'id': t['id'], 'title': t['title'], 'url': t['url']}
            for t in tests]


def attach_guides(checklist, standards, platform):
    """Add OWASP "how to test" guidance (what, when, how, tools) to items.

    Only used for the web page. Text comes from the OWASP MAS data.
    """
    maswe = {w['id']: w for w in standards['maswe']}
    tests = {t['id']: t for t in standards['mastg'] if not t.get('deprecated')}
    parents = {}
    for weak in standards['maswe']:
        for test_id in weak['tests']:
            parents.setdefault(test_id, []).append(weak)
    for item in checklist['MASVS']['items']:
        control = next(c for c in standards['masvs']
                       if c['id'] == item['id'])
        related = [maswe[w] for w in control['weaknesses'] if w in maswe]
        item['guide'] = _guide(
            what=control.get('title', ''),
            when='Decided by the weaknesses below. Test each of them.',
            how='Open each related weakness and run its MASTG tests.',
            links=[{'id': w['id'], 'title': w['title'], 'url': w['url']}
                   for w in related],
        )
    for item in checklist['MASWE']['items']:
        weak = maswe[item['id']]
        mine = [tests[t] for t in weak['tests']
                if t in tests and tests[t]['platform'] == platform]
        how = ('Run the MASTG tests listed below.' if mine else
               'OWASP has no MASTG test for this weakness yet. Review the '
               'app against the mitigations.')
        item['guide'] = _guide(
            what=weak.get('overview', ''),
            when=weak.get('modes', ''),
            how=how,
            tools=_refs_of(mine, 'tools'),
            techniques=_refs_of(mine, 'techniques'),
            impact=weak.get('impact', ''),
            fix=weak.get('mitigations', ''),
            links=_test_links(mine),
        )
    for item in checklist['MASTG']['items']:
        test = tests.get(item['id'])
        if not test:
            continue
        owners = parents.get(item['id'], [])
        item['guide'] = _guide(
            what=test.get('overview', ''),
            when='\n'.join(w.get('modes', '') for w in owners[:1]),
            how=test.get('steps', ''),
            tools=test.get('tools', []),
            techniques=test.get('techniques', []),
            expect='\n'.join(
                x for x in (test.get('observation', ''),
                            test.get('evaluation', '')) if x),
            links=[{'id': w['id'], 'title': w['title'], 'url': w['url']}
                   for w in owners],
        )


def load_assignments(checksum):
    """Return assignees keyed by (standard, item id)."""
    return {
        (a.STANDARD, a.ITEM_ID): a.ASSIGNEE
        for a in ChecklistAssignment.objects.filter(MD5=checksum)
    }


def load_files(checksum):
    """Return evidence file details keyed by (standard, item id)."""
    files = {}
    for row in ChecklistEvidence.objects.filter(MD5=checksum).order_by('id'):
        files.setdefault((row.STANDARD, row.ITEM_ID), []).append({
            'id': row.id,
            'name': row.FILE_NAME,
            'size_kb': max(1, row.SIZE // 1024),
            'uploader': row.UPLOADER,
            'uploaded_at': row.UPLOADED_AT.strftime('%Y-%m-%d %H:%M UTC'),
        })
    return files


def _checklist_response(request, checksum, api):
    """Build the checklist page or API response for a scan hash."""
    if not is_md5(checksum):
        return print_n_send_error_response(request, 'Invalid Hash', api)
    data, platform = load_scan(checksum)
    if not data:
        msg = 'Report not found or supported'
        if api:
            return {'not_found': msg}
        return print_n_send_error_response(request, msg, api)
    refresh_if_stale()
    checklist = build_checklist(
        data, platform, reviews=load_reviews(checksum),
        files=load_files(checksum),
        assignments=load_assignments(checksum))
    if api:
        return {
            'hash': checksum,
            'app_name': data.get('app_name', ''),
            'file_name': data.get('file_name', ''),
            'platform': platform,
            'engagement': load_engagement(checksum),
            'checklist': checklist,
        }
    attach_guides(checklist, load_standards(), platform)
    sections = [(n, checklist[n]) for n in ('MASVS', 'MASWE', 'MASTG')]
    context = {
        'checklist': checklist,
        'sections': sections,
        'source': checklist['source'],
        'summary': {n: c['summary'] for n, c in sections},
        'platform': platform,
        'report_links': report_links(checksum),
        'engagement': load_engagement(checksum),
        'can_review': has_permission(
            request, Permissions.REVIEW, False),
        'current_user': (request.user.get_username()
                         if request.user.is_authenticated else ''),
        'hash': checksum,
        'file_name': data.get('file_name', ''),
        'app_name': data.get('app_name', ''),
        'version': settings.MOBSF_VER,
        'title': 'Security Checklist',
    }
    return render(request, 'static_analysis/checklist.html', context)


@login_required
@require_http_methods(['GET'])
def checklist_page(request, checksum):
    """Dedicated MASVS/MASWE/MASTG checklist page for a scanned app."""
    return _checklist_response(request, checksum, False)


@login_required
def checklist_api(request, checksum, api=True):
    """Checklist data for the REST API (called by api_checklist)."""
    return _checklist_response(request, checksum, api)


def _json_error(message, status):
    return JsonResponse(
        {'status': 'failed', 'message': message}, status=status)


@login_required
@require_http_methods(['POST'])
@permission_required(Permissions.REVIEW)
def checklist_review(request, checksum, api=False):
    """Save or clear a tester decision for one checklist item."""
    if not is_md5(checksum):
        return _json_error('Invalid Hash', 400)
    form = ChecklistReviewForm(request.POST)
    if not form.is_valid():
        return JsonResponse(FormUtil.errors_message(form), status=400)
    data, platform = load_scan(checksum)
    if not data:
        return _json_error('Report not found or supported', 404)
    std = form.cleaned_data['standard']
    item_id = form.cleaned_data['item_id']
    checklist = build_checklist(data, platform)
    if not any(i['id'] == item_id for i in checklist[std]['items']):
        return _json_error('Unknown checklist item', 400)
    status = form.cleaned_data['status']
    keys = {'MD5': checksum, 'STANDARD': std, 'ITEM_ID': item_id}
    actor = actor_name(request, api)
    if not status:
        ChecklistReview.objects.filter(**keys).delete()
        log_action(checksum, std, item_id, 'clear', actor)
        return JsonResponse({'status': 'ok', 'review': None})
    ChecklistReview.objects.update_or_create(
        defaults={
            'STATUS': status,
            'NOTE': form.cleaned_data['note'],
            'REVIEWER': actor,
            'UPDATED_AT': timezone.now(),
        },
        **keys)
    log_action(
        checksum, std, item_id, 'set', actor,
        status, form.cleaned_data['note'])
    logger.info(
        'Checklist review saved for %s %s',
        sanitize_for_logging(checksum),
        sanitize_for_logging(item_id))
    return JsonResponse({
        'status': 'ok',
        'review': load_reviews(checksum)[(std, item_id)],
    })


def _csv_safe(value):
    """Neutralize spreadsheet formulas in exported cells."""
    value = str(value if value is not None else '')
    if value[:1] in ('=', '+', '-', '@', '\t', '\r'):
        return "'" + value
    return value


def _export_csv(checklist):
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow([
        'standard', 'id', 'title', 'status', 'automated_status',
        'evidence', 'files', 'assignee', 'reviewer', 'reviewed_at', 'note',
        'url'])
    for std in ('MASVS', 'MASWE', 'MASTG'):
        for item in checklist[std]['items']:
            review = item['review'] or {}
            writer.writerow([_csv_safe(v) for v in (
                item['standard'], item['id'], item['title'],
                item['status'], item['automated_status'],
                '; '.join(item['evidence']),
                '; '.join(f['name'] for f in item['files']),
                item['assignee'],
                review.get('reviewer'), review.get('updated_at'),
                review.get('note'), item['url'])])
    return out.getvalue()


@login_required
@require_http_methods(['GET'])
def checklist_export(request, checksum):
    """Download the checklist as JSON or CSV, with source and reviews."""
    if not is_md5(checksum):
        return print_n_send_error_response(request, 'Invalid Hash', False)
    form = ChecklistExportForm(request.GET)
    if not form.is_valid():
        return JsonResponse(FormUtil.errors_message(form), status=400)
    data, platform = load_scan(checksum)
    if not data:
        return print_n_send_error_response(
            request, 'Report not found or supported', False)
    checklist = build_checklist(
        data, platform, reviews=load_reviews(checksum),
        files=load_files(checksum),
        assignments=load_assignments(checksum))
    fmt = form.cleaned_data['format']
    name = sanitize_filename(
        f'{data.get("app_name") or checksum[:8]}_checklist.{fmt}')
    if fmt == 'csv':
        body, ctype = _export_csv(checklist), 'text/csv; charset=utf-8'
    else:
        body = json.dumps({
            'hash': checksum,
            'app_name': data.get('app_name', ''),
            'platform': platform,
            'engagement': load_engagement(checksum),
            'checklist': checklist,
        }, indent=1)
        ctype = 'application/json; charset=utf-8'
    response = HttpResponse(body, content_type=ctype)
    response['Content-Disposition'] = f'attachment; filename="{name}"'
    return response


@login_required
@require_http_methods(['GET'])
def checklist_history(request, checksum):
    """Return the latest tester actions on one checklist item."""
    if not is_md5(checksum):
        return _json_error('Invalid Hash', 400)
    form = ChecklistItemForm(request.GET)
    if not form.is_valid():
        return JsonResponse(FormUtil.errors_message(form), status=400)
    rows = ChecklistReviewLog.objects.filter(
        MD5=checksum,
        STANDARD=form.cleaned_data['standard'],
        ITEM_ID=form.cleaned_data['item_id']).order_by('-id')[:50]
    return JsonResponse({'status': 'ok', 'history': [{
        'action': r.ACTION,
        'status': r.STATUS,
        'note': r.NOTE,
        'actor': r.ACTOR,
        'at': r.CREATED_AT.strftime('%Y-%m-%d %H:%M UTC'),
    } for r in rows]})


@login_required
@require_http_methods(['POST'])
@permission_required(Permissions.REVIEW)
def checklist_assign(request, checksum, api=False):
    """Assign a checklist item to a tester, or clear the assignment."""
    if not is_md5(checksum):
        return _json_error('Invalid Hash', 400)
    form = ChecklistAssignForm(request.POST)
    if not form.is_valid():
        return JsonResponse(FormUtil.errors_message(form), status=400)
    data, platform = load_scan(checksum)
    if not data:
        return _json_error('Report not found or supported', 404)
    std = form.cleaned_data['standard']
    item_id = form.cleaned_data['item_id']
    checklist = build_checklist(data, platform)
    if not any(i['id'] == item_id for i in checklist[std]['items']):
        return _json_error('Unknown checklist item', 400)
    assignee = form.cleaned_data['assignee']
    actor = actor_name(request, api)
    keys = {'MD5': checksum, 'STANDARD': std, 'ITEM_ID': item_id}
    if not assignee:
        ChecklistAssignment.objects.filter(**keys).delete()
        log_action(checksum, std, item_id, 'unassign', actor)
        return JsonResponse({'status': 'ok', 'assignee': ''})
    if (django_settings.DISABLE_AUTHENTICATION != '1'
            and not get_user_model().objects.filter(
                username=assignee).exists()):
        return _json_error('Unknown user', 400)
    ChecklistAssignment.objects.update_or_create(
        defaults={
            'ASSIGNEE': assignee,
            'ASSIGNED_BY': actor,
            'UPDATED_AT': timezone.now(),
        },
        **keys)
    log_action(checksum, std, item_id, 'assign', actor, note=assignee)
    return JsonResponse({'status': 'ok', 'assignee': assignee})


@login_required
@require_http_methods(['POST'])
@permission_required(Permissions.REVIEW)
def checklist_engagement(request, checksum, api=False):
    """Save the engagement record (scope and setup) of a scan."""
    if not is_md5(checksum):
        return _json_error('Invalid Hash', 400)
    form = ChecklistEngagementForm(request.POST)
    if not form.is_valid():
        return JsonResponse(FormUtil.errors_message(form), status=400)
    if not (StaticAnalyzerAndroid.objects.filter(MD5=checksum).exists()
            or StaticAnalyzerIOS.objects.filter(MD5=checksum).exists()):
        return _json_error('Report not found or supported', 404)
    cd = form.cleaned_data
    profiles = [p for p in PROFILE_ORDER if p in cd['profiles']]
    ChecklistEngagement.objects.update_or_create(
        MD5=checksum,
        defaults={
            'PROFILES': ','.join(profiles),
            'SCOPE': cd['scope'],
            'RULES': cd['rules'],
            'TESTERS': cd['testers'],
            'START_DATE': cd['start_date'],
            'END_DATE': cd['end_date'],
            'DEVICE': cd['device'],
            'OS_VERSION': cd['os_version'],
            'ROOTED': cd['rooted'],
            'TOOLS': cd['tools'],
            'PROXY': cd['proxy'],
            'ACCOUNTS': cd['accounts'],
            'API_NOTES': cd['api_notes'],
            'UPDATED_BY': actor_name(request, api),
            'UPDATED_AT': timezone.now(),
        })
    logger.info(
        'Engagement record saved for %s', sanitize_for_logging(checksum))
    return JsonResponse(
        {'status': 'ok', 'engagement': load_engagement(checksum)})
