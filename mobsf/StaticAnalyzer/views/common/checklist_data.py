# -*- coding: utf_8 -*-
"""Storage helpers for checklist reviews and evidence files."""
import logging
import shutil
from pathlib import Path

from django.conf import settings

from mobsf.StaticAnalyzer.models import (
    ChecklistEvidence,
    ChecklistReview,
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
    scan_dir = evidence_dir(checksum)
    if scan_dir.is_dir() and not scan_dir.is_symlink():
        shutil.rmtree(scan_dir, ignore_errors=True)
