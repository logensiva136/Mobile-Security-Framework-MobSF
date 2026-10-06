# -*- coding: utf_8 -*-
"""Storage helpers for checklist reviews and evidence files."""
import logging
import shutil
from pathlib import Path

from django.conf import settings

from mobsf.StaticAnalyzer.models import (
    ChecklistAssignment,
    ChecklistEvidence,
    ChecklistReview,
    ChecklistReviewLog,
)

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
