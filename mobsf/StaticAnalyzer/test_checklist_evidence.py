# -*- coding: utf_8 -*-
"""Tests for checklist evidence uploads."""
import tempfile
from pathlib import Path
from unittest import mock

from django.contrib.auth.models import Permission, User
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import SimpleTestCase, TestCase

from mobsf.StaticAnalyzer.models import ChecklistEvidence, ChecklistReview
from mobsf.StaticAnalyzer.test_checklist import (
    FIXTURE,
    HASH,
    _patch_scan,
)
from mobsf.StaticAnalyzer.views.common import (
    checklist as checklist_module,
    checklist_evidence,
)
from mobsf.StaticAnalyzer.views.common.checklist_data import (
    delete_checklist_data,
    evidence_dir,
)

PNG = b'\x89PNG\r\n\x1a\n' + b'0' * 32
OTHER = 'b' * 32


class ValidateUploadTests(SimpleTestCase):
    """Extension and content checks."""

    def test_accepts_allowed_types(self):
        validate = checklist_evidence.validate_upload
        self.assertEqual(validate('a.PNG', PNG), 'png')
        self.assertEqual(validate('a.jpg', b'\xff\xd8\xff\xe0data'), 'jpg')
        self.assertEqual(validate('a.pdf', b'%PDF-1.4 x'), 'pdf')
        self.assertEqual(validate('a.txt', 'café'.encode()), 'txt')
        self.assertEqual(validate('a.json', b'{"a": 1}'), 'json')

    def test_rejects_bad_files(self):
        validate = checklist_evidence.validate_upload
        for name, data in (
                ('a.exe', b'MZ'),
                ('a.html', b'<script>'),
                ('a.svg', b'<svg>'),
                ('a', b'x'),
                ('a.png', b'not a png'),
                ('a.pdf', PNG),
                ('a.png', b''),
                ('a.txt', b'ab\x00cd'),
                ('a.txt', b'\xff\xfe\xfa')):
            with self.assertRaises(ValueError, msg=name):
                validate(name, data)


class EvidenceEndpointTests(TestCase):
    """Upload, download and delete through the web endpoints."""

    base = f'/checklist/{HASH}/evidence/'

    def setUp(self):
        for patch in _patch_scan():
            patch.start()
            self.addCleanup(patch.stop)
        std = mock.patch.object(
            checklist_module, 'load_standards', return_value=FIXTURE)
        std.start()
        self.addCleanup(std.stop)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        override = self.settings(
            MOBSF_HOME=self.tmp.name, DISABLE_AUTHENTICATION='1')
        override.enable()
        self.addCleanup(override.disable)

    def upload(self, name='proof.png', data=PNG, **fields):
        form = {'standard': 'MASWE', 'item_id': 'MASWE-0099',
                'file': SimpleUploadedFile(name, data)}
        form.update(fields)
        return self.client.post(self.base, form)

    def test_upload_download_delete(self):
        response = self.upload()
        self.assertEqual(response.status_code, 200)
        row = ChecklistEvidence.objects.get()
        self.assertEqual(row.FILE_NAME, 'proof.png')
        self.assertEqual(row.CONTENT_TYPE, 'image/png')
        self.assertEqual(len(row.SHA256), 64)
        stored = evidence_dir(HASH) / row.STORED_NAME
        self.assertTrue(stored.is_file())
        self.assertNotIn('proof', row.STORED_NAME)
        url = f'{self.base}{row.id}/'
        download = self.client.get(url)
        self.assertEqual(download.status_code, 200)
        self.assertIn('attachment', download['Content-Disposition'])
        self.assertEqual(download['X-Content-Type-Options'], 'nosniff')
        self.assertEqual(b''.join(download.streaming_content), PNG)
        self.assertEqual(self.client.post(f'{url}delete/').status_code, 200)
        self.assertFalse(stored.exists())
        self.assertEqual(ChecklistEvidence.objects.count(), 0)

    def test_hostile_file_name_is_sanitized(self):
        self.assertEqual(
            self.upload(name='../../evil.png').status_code, 200)
        row = ChecklistEvidence.objects.get()
        self.assertNotIn('/', row.FILE_NAME)
        self.assertNotIn('..', row.STORED_NAME)
        stored = Path(self.tmp.name, 'evidence', HASH, row.STORED_NAME)
        self.assertTrue(stored.is_file())

    def test_rejects_invalid_uploads(self):
        self.assertEqual(self.upload(name='x.exe').status_code, 400)
        self.assertEqual(
            self.upload(name='x.png', data=b'nope').status_code, 400)
        self.assertEqual(self.upload(standard='X').status_code, 400)
        self.assertEqual(self.upload(item_id='MASWE-7777').status_code, 400)
        self.assertEqual(self.upload(item_id='../x').status_code, 400)
        no_file = self.client.post(
            self.base, {'standard': 'MASWE', 'item_id': 'MASWE-0099'})
        self.assertEqual(no_file.status_code, 400)
        self.assertEqual(ChecklistEvidence.objects.count(), 0)

    def test_size_and_count_limits(self):
        with mock.patch.object(checklist_evidence, 'MAX_EVIDENCE_BYTES', 40):
            self.assertEqual(
                self.upload(data=PNG + b'0' * 20).status_code, 400)
        with mock.patch.object(checklist_evidence, 'MAX_FILES_PER_ITEM', 2):
            self.assertEqual(self.upload().status_code, 200)
            self.assertEqual(self.upload().status_code, 200)
            self.assertEqual(self.upload().status_code, 400)
        self.assertEqual(ChecklistEvidence.objects.count(), 2)

    def test_scan_storage_quota(self):
        with mock.patch.object(
                checklist_evidence, 'MAX_SCAN_EVIDENCE_BYTES', 100):
            self.assertEqual(self.upload().status_code, 200)
            self.assertEqual(self.upload().status_code, 200)
            self.assertEqual(self.upload().status_code, 400)
        self.assertEqual(ChecklistEvidence.objects.count(), 2)

    def test_methods(self):
        self.assertEqual(self.client.get(self.base).status_code, 405)
        self.upload()
        row = ChecklistEvidence.objects.get()
        self.assertEqual(
            self.client.get(f'{self.base}{row.id}/delete/').status_code, 405)
        self.assertEqual(
            self.client.post(f'{self.base}{row.id}/').status_code, 405)

    def test_evidence_of_other_scan_is_not_reachable(self):
        self.upload()
        row = ChecklistEvidence.objects.get()
        other = f'/checklist/{OTHER}/evidence/{row.id}/'
        self.assertEqual(self.client.get(other).status_code, 404)
        self.assertEqual(self.client.post(f'{other}delete/').status_code, 404)
        self.assertEqual(ChecklistEvidence.objects.count(), 1)

    def test_missing_file_on_disk(self):
        self.upload()
        row = ChecklistEvidence.objects.get()
        (evidence_dir(HASH) / row.STORED_NAME).unlink()
        self.assertEqual(
            self.client.get(f'{self.base}{row.id}/').status_code, 404)

    def test_permissions(self):
        with self.settings(DISABLE_AUTHENTICATION='0'):
            anon = self.client.post(self.base, {})
            self.assertEqual(anon.status_code, 302)
            User.objects.create_user('viewer', password='pw-for-test-2')
            self.client.login(username='viewer', password='pw-for-test-2')
            self.assertEqual(self.upload().status_code, 403)
            user = User.objects.get(username='viewer')
            user.user_permissions.add(
                Permission.objects.get(codename='can_review'))
            self.assertEqual(self.upload().status_code, 200)
            row = ChecklistEvidence.objects.get()
            self.assertEqual(row.UPLOADER, 'viewer')
            # Viewers can download but not delete
            user.user_permissions.clear()
            user = User.objects.get(pk=user.pk)
            self.assertEqual(
                self.client.get(f'{self.base}{row.id}/').status_code, 200)
            self.assertEqual(
                self.client.post(f'{self.base}{row.id}/delete/').status_code,
                403)

    def test_files_listed_on_page_and_export(self):
        self.upload()
        page = self.client.get(f'/checklist/{HASH}/')
        self.assertContains(page, 'proof.png')
        self.assertContains(page, 'cl-upload')
        export = self.client.get(
            f'/checklist/{HASH}/export/', {'format': 'csv'})
        self.assertIn('proof.png', export.content.decode())

    def test_delete_scan_data_removes_everything(self):
        self.upload()
        ChecklistReview.objects.create(
            MD5=HASH, STANDARD='MASWE', ITEM_ID='MASWE-0099', STATUS='Failed')
        self.assertTrue(evidence_dir(HASH).is_dir())
        delete_checklist_data(HASH)
        self.assertFalse(evidence_dir(HASH).exists())
        self.assertEqual(ChecklistEvidence.objects.count(), 0)
        self.assertEqual(ChecklistReview.objects.count(), 0)
