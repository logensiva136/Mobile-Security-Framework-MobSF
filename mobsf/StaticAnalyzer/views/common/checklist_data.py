# -*- coding: utf_8 -*-
"""Storage helpers for checklist reviews and evidence files."""
import logging
import shutil
from pathlib import Path

from django.conf import settings
from django.urls import NoReverseMatch, reverse

from mobsf.StaticAnalyzer.models import (
    ChecklistAssignment,
    ChecklistEngagement,
    ChecklistEvidence,
    ChecklistReview,
    ChecklistReviewLog,
    RecentScansDB,
)
from mobsf.MobSF.utils import get_md5

logger = logging.getLogger(__name__)


def evidence_root():
    """Return the directory holding all evidence files."""
    return Path(settings.MOBSF_HOME) / 'evidence'


def evidence_dir(checksum):
    """Return the evidence directory of one scan (validated md5 only)."""
    return evidence_root() / checksum


def delete_checklist_data(checksum):
    """Remove reviews, evidence rows and evidence files of a scan."""
    ChecklistReview.objects.filter(MD5=checksum).delete()
    ChecklistEvidence.objects.filter(MD5=checksum).delete()
    ChecklistReviewLog.objects.filter(MD5=checksum).delete()
    ChecklistAssignment.objects.filter(MD5=checksum).delete()
    ChecklistEngagement.objects.filter(MD5=checksum).delete()
    scan_dir = evidence_dir(checksum)
    if scan_dir.is_dir() and not scan_dir.is_symlink():
        shutil.rmtree(scan_dir, ignore_errors=True)


def actor_name(request, api=False):
    """Return who performs an action."""
    if request.user.is_authenticated:
        return request.user.get_username()
    return 'api' if api else 'anonymous'


def log_action(checksum, standard, item_id, action, actor,
               status='', note=''):
    """Record a tester action in the item history."""
    ChecklistReviewLog.objects.create(
        MD5=checksum,
        STANDARD=standard,
        ITEM_ID=item_id,
        ACTION=action,
        STATUS=status,
        NOTE=note,
        ACTOR=actor)


ANDROID_DYNAMIC = ('.apk', '.xapk', '.apks', '.aab')
STATIC_ANALYZERS = ('static_analyzer', 'static_analyzer_ios')


def _reverse(name, **kwargs):
    try:
        return reverse(name, kwargs=kwargs)
    except NoReverseMatch:
        return ''


def report_links(checksum):
    """Return links back to the static and dynamic reports of a scan.

    Every key is always present so templates never miss one.
    """
    links = {
        'static_url': '',
        'dynamic_url': '',
        'dynamic_exists': False,
    }
    scan = RecentScansDB.objects.filter(MD5=checksum).first()
    if not scan:
        return links
    if scan.ANALYZER in STATIC_ANALYZERS:
        links['static_url'] = _reverse(scan.ANALYZER, checksum=checksum)
    name = scan.FILE_NAME.lower()
    updir = Path(settings.UPLD_DIR)
    if name.endswith(ANDROID_DYNAMIC):
        links['dynamic_url'] = _reverse('dynamic_report', checksum=checksum)
        links['dynamic_exists'] = (updir / checksum / 'logcat.txt').exists()
    elif name.endswith('.ipa') and scan.PACKAGE_NAME:
        links['dynamic_url'] = _reverse(
            'ios_view_report', bundle_id=scan.PACKAGE_NAME)
        bundle = get_md5(scan.PACKAGE_NAME.encode('utf-8'))
        links['dynamic_exists'] = (
            updir / bundle / 'mobsf_dump_file.txt').exists()
    return links


PROFILE_ORDER = ('L1', 'L2', 'R', 'P')
ENGAGEMENT_TEXT = (
    'scope', 'rules', 'testers', 'device', 'os_version', 'rooted', 'tools',
    'proxy', 'accounts', 'api_notes')


def load_engagement(checksum):
    """Return the engagement record of a scan, every key always present."""
    out = dict.fromkeys(ENGAGEMENT_TEXT, '')
    out.update(
        exists=False, profiles=[], profiles_text='', start_date='',
        end_date='', updated_by='', updated_at='')
    row = ChecklistEngagement.objects.filter(MD5=checksum).first()
    if not row:
        return out
    out.update(
        exists=True,
        scope=row.SCOPE,
        rules=row.RULES,
        testers=row.TESTERS,
        device=row.DEVICE,
        os_version=row.OS_VERSION,
        rooted=row.ROOTED,
        tools=row.TOOLS,
        proxy=row.PROXY,
        accounts=row.ACCOUNTS,
        api_notes=row.API_NOTES,
        start_date=row.START_DATE.isoformat() if row.START_DATE else '',
        end_date=row.END_DATE.isoformat() if row.END_DATE else '',
        updated_by=row.UPDATED_BY,
        updated_at=row.UPDATED_AT.strftime('%Y-%m-%d %H:%M UTC'))
    out['profiles'] = [p for p in PROFILE_ORDER
                       if p in row.PROFILES.split(',')]
    out['profiles_text'] = ', '.join(out['profiles'])
    return out
