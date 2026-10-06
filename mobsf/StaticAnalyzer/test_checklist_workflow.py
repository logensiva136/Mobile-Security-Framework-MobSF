# -*- coding: utf_8 -*-
"""Tests for checklist history and the tester REST API."""
import tempfile
from pathlib import Path
from unittest import mock

from django.conf import settings
from django.contrib.auth.models import Permission, User
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase

from mobsf.MobSF.init import api_key
from mobsf.StaticAnalyzer.models import (
    ChecklistAssignment,
    ChecklistEvidence,
    ChecklistReview,
    ChecklistReviewLog,
)
from mobsf.StaticAnalyzer.test_checklist import (
    FIXTURE,
    HASH,
    _patch_scan,
)
from mobsf.StaticAnalyzer.views.common import (
    appsec,
    checklist as checklist_module,
)
from mobsf.StaticAnalyzer.views.common import checklist_data
from mobsf.StaticAnalyzer.views.common.checklist_data import (
    delete_checklist_data,
)

PNG = b'\x89PNG\r\n\x1a\n' + b'0' * 32
ITEM = {'standard': 'MASWE', 'item_id': 'MASWE-0099'}


class WorkflowBase(TestCase):
    """Shared setup: patched scan, fixture standards and a temp home."""

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
        root = mock.patch.object(
            checklist_data, 'evidence_root',
            return_value=Path(self.tmp.name))
        root.start()
        self.addCleanup(root.stop)
        override = self.settings(DISABLE_AUTHENTICATION='1')
        override.enable()
        self.addCleanup(override.disable)


class HistoryTests(WorkflowBase):
    """Every tester action is recorded and readable."""

    base = f'/checklist/{HASH}'

    def history(self, **params):
        query = dict(ITEM)
        query.update(params)
        return self.client.get(f'{self.base}/history/', query)

    def test_actions_are_recorded_newest_first(self):
        review = dict(ITEM, status='Success', note='looks fine')
        self.client.post(f'{self.base}/review/', review)
        self.client.post(
            f'{self.base}/evidence/',
            dict(ITEM, file=SimpleUploadedFile('p.png', PNG)))
        evidence = ChecklistEvidence.objects.get()
        self.client.post(f'{self.base}/evidence/{evidence.id}/delete/')
        self.client.post(f'{self.base}/review/', dict(ITEM, status=''))
        response = self.history()
        self.assertEqual(response.status_code, 200)
        actions = [h['action'] for h in response.json()['history']]
        self.assertEqual(
            actions, ['clear', 'evidence_remove', 'evidence_add', 'set'])
        first = response.json()['history'][-1]
        self.assertEqual((first['status'], first['note']),
                         ('Success', 'looks fine'))
        self.assertEqual(first['actor'], 'anonymous')

    def test_history_is_per_item(self):
        self.client.post(
            f'{self.base}/review/', dict(ITEM, status='Failed'))
        other = self.history(item_id='MASWE-0001')
        self.assertEqual(other.json()['history'], [])

    def test_bad_requests(self):
        self.assertEqual(self.history(standard='X').status_code, 400)
        self.assertEqual(self.history(item_id='../x').status_code, 400)
        self.assertEqual(
            self.client.post(f'{self.base}/history/').status_code, 405)

    def test_login_required(self):
        with self.settings(DISABLE_AUTHENTICATION='0'):
            self.assertEqual(self.history().status_code, 302)

    def test_scan_delete_removes_history(self):
        self.client.post(
            f'{self.base}/review/', dict(ITEM, status='Failed'))
        self.assertEqual(ChecklistReviewLog.objects.count(), 1)
        delete_checklist_data(HASH)
        self.assertEqual(ChecklistReviewLog.objects.count(), 0)


class TesterApiTests(WorkflowBase):
    """REST endpoints to review items and attach evidence."""

    def post(self, url, data, key=True):
        headers = {}
        if key:
            headers['HTTP_X_MOBSF_API_KEY'] = api_key(settings.MOBSF_HOME)
        return self.client.post(url, data, **headers)

    def test_review_requires_api_key(self):
        data = dict(ITEM, hash=HASH, status='Success')
        response = self.post('/api/v1/checklist_review', data, key=False)
        self.assertEqual(response.status_code, 401)

    def test_review_flow(self):
        data = dict(ITEM, hash=HASH, status='Success', note='ci check')
        with self.settings(DISABLE_AUTHENTICATION='0'):
            response = self.post('/api/v1/checklist_review', data)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['review']['reviewer'], 'api')
        self.assertEqual(ChecklistReview.objects.get().NOTE, 'ci check')
        listing = self.post('/api/v1/checklist', {'hash': HASH})
        item = next(
            i for i in listing.json()['checklist']['MASWE']['items']
            if i['id'] == 'MASWE-0099')
        self.assertEqual(item['status'], 'Success')
        self.assertEqual(item['automated_status'], 'ToBeTest')
        cleared = self.post(
            '/api/v1/checklist_review', dict(data, status=''))
        self.assertEqual(cleared.status_code, 200)
        self.assertEqual(ChecklistReview.objects.count(), 0)

    def test_review_validation(self):
        url = '/api/v1/checklist_review'
        self.assertEqual(self.post(url, {}).status_code, 422)
        bad = dict(ITEM, hash=HASH, status='Maybe')
        self.assertEqual(self.post(url, bad).status_code, 400)
        unknown = dict(ITEM, hash=HASH, item_id='MASWE-7777')
        self.assertEqual(self.post(url, unknown).status_code, 400)
        self.assertEqual(
            self.post(url, dict(ITEM, hash='zz')).status_code, 400)

    def test_evidence_upload_and_validation(self):
        url = '/api/v1/checklist_evidence'
        good = dict(ITEM, hash=HASH, file=SimpleUploadedFile('a.png', PNG))
        response = self.post(url, good)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(ChecklistEvidence.objects.get().UPLOADER, 'api')
        bad = dict(ITEM, hash=HASH, file=SimpleUploadedFile('a.exe', b'MZ'))
        self.assertEqual(self.post(url, bad).status_code, 400)
        self.assertEqual(self.post(url, {}).status_code, 422)
        self.assertEqual(
            self.post(url, good, key=False).status_code, 401)

    def test_get_not_allowed(self):
        key = api_key(settings.MOBSF_HOME)
        for url in ('/api/v1/checklist_review',
                    '/api/v1/checklist_evidence'):
            response = self.client.get(url, HTTP_X_MOBSF_API_KEY=key)
            self.assertEqual(response.status_code, 405)


class ScorecardTests(WorkflowBase):
    """Scorecard and PDF data carry tester reviews and evidence."""

    def test_dashboard_includes_reviews_and_files(self):
        ChecklistReview.objects.create(
            MD5=HASH, STANDARD='MASWE', ITEM_ID='MASWE-0099',
            STATUS='Success', NOTE='manual', REVIEWER='tester')
        ChecklistEvidence.objects.create(
            MD5=HASH, STANDARD='MASWE', ITEM_ID='MASWE-0099',
            FILE_NAME='proof.png', STORED_NAME='x.png',
            CONTENT_TYPE='image/png', SIZE=10, UPLOADER='tester')
        data = {'md5': HASH}
        with mock.patch.object(appsec, 'common_fields'), \
                mock.patch.object(
                    checklist_module, 'load_standards',
                    return_value=FIXTURE):
            findings = appsec.get_android_dashboard(data, from_ctx=True)
        item = next(
            i for i in findings['checklist']['MASWE']['items']
            if i['id'] == 'MASWE-0099')
        self.assertEqual(item['status'], 'Success')
        self.assertEqual(item['review']['reviewer'], 'tester')
        self.assertEqual(item['files'][0]['name'], 'proof.png')


class AssignmentTests(WorkflowBase):
    """Assigning checklist items to testers."""

    base = f'/checklist/{HASH}'

    def assign(self, assignee='alice', **fields):
        data = dict(ITEM, assignee=assignee)
        data.update(fields)
        return self.client.post(f'{self.base}/assign/', data)

    def test_assign_change_and_clear(self):
        self.assertEqual(self.assign().status_code, 200)
        self.assertEqual(ChecklistAssignment.objects.get().ASSIGNEE, 'alice')
        self.assign('bob')
        self.assertEqual(ChecklistAssignment.objects.count(), 1)
        self.assertEqual(ChecklistAssignment.objects.get().ASSIGNEE, 'bob')
        self.assertEqual(self.assign('').status_code, 200)
        self.assertEqual(ChecklistAssignment.objects.count(), 0)
        history = self.client.get(
            f'{self.base}/history/', ITEM).json()['history']
        self.assertEqual(
            [h['action'] for h in history],
            ['unassign', 'assign', 'assign'])

    def test_validation(self):
        self.assertEqual(self.assign('bad name!').status_code, 400)
        self.assertEqual(self.assign('x' * 40).status_code, 400)
        self.assertEqual(self.assign(standard='X').status_code, 400)
        self.assertEqual(self.assign(item_id='MASWE-7777').status_code, 400)
        self.assertEqual(
            self.client.get(f'{self.base}/assign/').status_code, 405)
        self.assertEqual(ChecklistAssignment.objects.count(), 0)

    def test_assignee_must_be_a_user_when_auth_is_on(self):
        User.objects.create_user('alice', password='pw-for-test-3')
        User.objects.create_user('lead', password='pw-for-test-4')
        lead = User.objects.get(username='lead')
        lead.user_permissions.add(
            Permission.objects.get(codename='can_review'))
        with self.settings(DISABLE_AUTHENTICATION='0'):
            self.client.login(username='lead', password='pw-for-test-4')
            self.assertEqual(self.assign('ghost').status_code, 400)
            self.assertEqual(self.assign('alice').status_code, 200)
        row = ChecklistAssignment.objects.get()
        self.assertEqual((row.ASSIGNEE, row.ASSIGNED_BY), ('alice', 'lead'))

    def test_requires_permission(self):
        with self.settings(DISABLE_AUTHENTICATION='0'):
            self.assertEqual(self.assign().status_code, 302)
            User.objects.create_user('viewer', password='pw-for-test-5')
            self.client.login(username='viewer', password='pw-for-test-5')
            self.assertEqual(self.assign().status_code, 403)

    def test_shown_in_page_api_and_export(self):
        self.assign('alice')
        page = self.client.get(f'{self.base}/')
        self.assertContains(page, 'Assigned to alice')
        self.assertContains(page, 'cl-assign-filter')
        export = self.client.get(f'{self.base}/export/', {'format': 'csv'})
        self.assertIn(',alice,', export.content.decode())
        listing = self.client.post(
            '/api/v1/checklist', {'hash': HASH},
            HTTP_X_MOBSF_API_KEY=api_key(settings.MOBSF_HOME))
        item = next(
            i for i in listing.json()['checklist']['MASWE']['items']
            if i['id'] == 'MASWE-0099')
        self.assertEqual(item['assignee'], 'alice')

    def test_api_and_cleanup(self):
        response = self.client.post(
            '/api/v1/checklist_assign',
            dict(ITEM, hash=HASH, assignee='carol'),
            HTTP_X_MOBSF_API_KEY=api_key(settings.MOBSF_HOME))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(ChecklistAssignment.objects.get().ASSIGNED_BY, 'api')
        self.assertEqual(self.client.post(
            '/api/v1/checklist_assign', {},
            HTTP_X_MOBSF_API_KEY=api_key(settings.MOBSF_HOME)).status_code,
            422)
        delete_checklist_data(HASH)
        self.assertEqual(ChecklistAssignment.objects.count(), 0)
