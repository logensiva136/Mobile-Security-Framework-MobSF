# -*- coding: utf_8 -*-
"""Evidence files attached to MASVS/MASWE/MASTG checklist items.

Files are stored under MOBSF_HOME/evidence/<md5>/ with random names,
never in a web-served folder. Only a small allowlist of types is accepted,
checked by extension and content, and downloads are always attachments.
"""
import hashlib
import logging
import uuid
from pathlib import Path

from django.db.models import Sum
from django.http import FileResponse, JsonResponse
from django.utils import timezone
from django.views.decorators.http import require_http_methods

from mobsf.MobSF.forms import FormUtil
from mobsf.MobSF.security import (
    is_pipe_or_link,
    is_safe_path,
    sanitize_filename,
    sanitize_for_logging,
)
from mobsf.MobSF.utils import is_md5
from mobsf.MobSF.views.authentication import (
    login_required,
)
from mobsf.MobSF.views.authorization import (
    Permissions,
    permission_required,
)
from mobsf.StaticAnalyzer.forms import ChecklistEvidenceForm
from mobsf.StaticAnalyzer.models import ChecklistEvidence
from mobsf.StaticAnalyzer.views.common.checklist import (
    build_checklist,
    load_scan,
)
from mobsf.StaticAnalyzer.views.common.checklist_data import (
    actor_name,
    evidence_dir,
    log_action,
)

logger = logging.getLogger(__name__)

MAX_EVIDENCE_BYTES = 5 * 1024 * 1024
MAX_FILES_PER_ITEM = 10
MAX_SCAN_EVIDENCE_BYTES = 50 * 1024 * 1024
MAX_NAME_LENGTH = 100
ALLOWED_TYPES = {
    'png': 'image/png',
    'jpg': 'image/jpeg',
    'jpeg': 'image/jpeg',
    'gif': 'image/gif',
    'pdf': 'application/pdf',
    'txt': 'text/plain',
    'log': 'text/plain',
    'json': 'application/json',
}
MAGIC = {
    'png': (b'\x89PNG\r\n\x1a\n',),
    'jpg': (b'\xff\xd8\xff',),
    'jpeg': (b'\xff\xd8\xff',),
    'gif': (b'GIF87a', b'GIF89a'),
    'pdf': (b'%PDF-',),
}
TEXT_TYPES = {'txt', 'log', 'json'}


def _error(message, status=400):
    return JsonResponse(
        {'status': 'failed', 'message': message}, status=status)


def validate_upload(name, data):
    """Return the lowercase extension of an acceptable file.

    Raises ValueError when the extension is not allowed, the content
    does not match the extension, or the file is empty.
    """
    ext = Path(name).suffix.lower().lstrip('.')
    if ext not in ALLOWED_TYPES:
        raise ValueError('File type not allowed')
    if not data:
        raise ValueError('File is empty')
    if ext in MAGIC:
        if not data.startswith(MAGIC[ext]):
            raise ValueError('File content does not match its type')
    else:
        try:
            data[:65536].decode('utf-8')
        except UnicodeDecodeError as exp:
            raise ValueError('Text file must be UTF-8') from exp
        if b'\x00' in data[:65536]:
            raise ValueError('Text file contains binary data')
    return ext


def evidence_item(row):
    """Return the public fields of an evidence row."""
    return {
        'id': row.id,
        'name': row.FILE_NAME,
        'size_kb': max(1, row.SIZE // 1024),
        'uploader': row.UPLOADER,
        'uploaded_at': row.UPLOADED_AT.strftime('%Y-%m-%d %H:%M UTC'),
    }


@login_required
@require_http_methods(['POST'])
@permission_required(Permissions.REVIEW)
def checklist_evidence_upload(request, checksum, api=False):
    """Attach an evidence file to a checklist item."""
    if not is_md5(checksum):
        return _error('Invalid Hash')
    form = ChecklistEvidenceForm(request.POST, request.FILES)
    if not form.is_valid():
        return JsonResponse(FormUtil.errors_message(form), status=400)
    data, platform = load_scan(checksum)
    if not data:
        return _error('Report not found or supported', 404)
    std = form.cleaned_data['standard']
    item_id = form.cleaned_data['item_id']
    checklist = build_checklist(data, platform)
    if not any(i['id'] == item_id for i in checklist[std]['items']):
        return _error('Unknown checklist item')
    existing = ChecklistEvidence.objects.filter(
        MD5=checksum, STANDARD=std, ITEM_ID=item_id).count()
    if existing >= MAX_FILES_PER_ITEM:
        return _error('Too many evidence files for this item')
    used = ChecklistEvidence.objects.filter(
        MD5=checksum).aggregate(total=Sum('SIZE'))['total'] or 0
    upload = form.cleaned_data['file']
    if upload.size > MAX_EVIDENCE_BYTES:
        return _error('File is too large')
    content = upload.read(MAX_EVIDENCE_BYTES + 1)
    if len(content) > MAX_EVIDENCE_BYTES:
        return _error('File is too large')
    if used + len(content) > MAX_SCAN_EVIDENCE_BYTES:
        return _error('Evidence storage limit reached for this scan')
    try:
        ext = validate_upload(upload.name, content)
    except ValueError as exp:
        return _error(str(exp))
    display = sanitize_filename(Path(upload.name).name)[:MAX_NAME_LENGTH]
    stored = f'{uuid.uuid4().hex}.{ext}'
    scan_dir = evidence_dir(checksum)
    target = scan_dir / stored
    if not is_safe_path(scan_dir, target, stored):
        return _error('Invalid file name')
    scan_dir.mkdir(parents=True, exist_ok=True)
    with open(target, 'xb') as fp:
        fp.write(content)
    actor = actor_name(request, api)
    row = ChecklistEvidence.objects.create(
        MD5=checksum,
        STANDARD=std,
        ITEM_ID=item_id,
        FILE_NAME=display,
        STORED_NAME=stored,
        CONTENT_TYPE=ALLOWED_TYPES[ext],
        SIZE=len(content),
        SHA256=hashlib.sha256(content).hexdigest(),
        UPLOADER=actor,
        UPLOADED_AT=timezone.now())
    log_action(checksum, std, item_id, 'evidence_add', actor, note=display)
    logger.info(
        'Checklist evidence added for %s %s',
        sanitize_for_logging(checksum),
        sanitize_for_logging(item_id))
    return JsonResponse({'status': 'ok', 'evidence': evidence_item(row)})


def _file_path(row):
    """Return the stored file path when it is safe to read, else None."""
    scan_dir = evidence_dir(row.MD5)
    path = scan_dir / row.STORED_NAME
    if not is_safe_path(scan_dir, path, row.STORED_NAME):
        return None
    if not path.is_file() or is_pipe_or_link(path):
        return None
    return path


@login_required
@require_http_methods(['GET'])
def checklist_evidence_download(request, checksum, evidence_id):
    """Download an evidence file as an attachment."""
    if not is_md5(checksum):
        return _error('Invalid Hash')
    row = ChecklistEvidence.objects.filter(
        pk=evidence_id, MD5=checksum).first()
    path = _file_path(row) if row else None
    if not path:
        return _error('Evidence not found', 404)
    response = FileResponse(
        open(path, 'rb'),
        as_attachment=True,
        filename=row.FILE_NAME,
        content_type=row.CONTENT_TYPE)
    response['X-Content-Type-Options'] = 'nosniff'
    return response


@login_required
@require_http_methods(['POST'])
@permission_required(Permissions.REVIEW)
def checklist_evidence_delete(
        request, checksum, evidence_id, api=False):
    """Delete an evidence file and its record."""
    if not is_md5(checksum):
        return _error('Invalid Hash')
    row = ChecklistEvidence.objects.filter(
        pk=evidence_id, MD5=checksum).first()
    if not row:
        return _error('Evidence not found', 404)
    path = _file_path(row)
    if path:
        path.unlink()
    log_action(
        checksum, row.STANDARD, row.ITEM_ID, 'evidence_remove',
        actor_name(request, api), note=row.FILE_NAME)
    row.delete()
    return JsonResponse({'status': 'ok'})
