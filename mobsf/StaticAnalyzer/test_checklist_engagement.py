# -*- coding: utf_8 -*-
"""Tests for the pentest engagement record."""
from unittest import mock

from django.conf import settings
from django.contrib.auth.models import Permission, User

from mobsf.MobSF.init import api_key
from mobsf.StaticAnalyzer.models import ChecklistEngagement
from mobsf.StaticAnalyzer.test_checklist import HASH
from mobsf.StaticAnalyzer.test_checklist_workflow import WorkflowBase
from mobsf.StaticAnalyzer.views.common import (
    appsec,
    checklist as checklist_module,
)
from mobsf.StaticAnalyzer.views.common.checklist_data import (
    delete_checklist_data,
    load_engagement,
)

FORM = {
    'profiles': ['R', 'L1', 'L2'],
    'scope': 'Android app and its API',
    'rules': 'No DoS. Business hours only.',
    'testers': 'alice, bob',
    'start_date': '2026-10-01',
    'end_date': '2026-10-10',
    'device': 'Pixel 7',
    'os_version': 'Android 14',
    'rooted': 'yes',
    'tools': 'Burp 2026.1, Frida 17',
    'proxy': 'Burp on 192.168.1.5:8080',
    'accounts': 'user-A (normal), user-B (admin)',
    'api_notes': 'api.example.test, JWT auth',
}


class EngagementTests(WorkflowBase):
    """Saving and reading the engagement record."""

    base = f'/checklist/{HASH}'

    def save(self, **fields):
        data = dict(FORM)
        data.update(fields)
        return self.client.post(f'{self.base}/engagement/', data)

    def test_defaults_when_nothing_saved(self):
        out = load_engagement(HASH)
        self.assertFalse(out['exists'])
        self.assertEqual(out['profiles'], [])
        for key in ('scope', 'rules', 'testers', 'device', 'os_version',
                    'rooted', 'tools', 'proxy', 'accounts', 'api_notes',
                    'start_date', 'end_date', 'updated_by', 'updated_at'):
            self.assertEqual(out[key], '')

    def test_save_and_update_keeps_one_record(self):
        response = self.save()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(ChecklistEngagement.objects.count(), 1)
        body = response.json()['engagement']
        self.assertTrue(body['exists'])
        self.assertEqual(body['profiles'], ['L1', 'L2', 'R'])
        self.assertEqual(body['profiles_text'], 'L1, L2, R')
        self.assertEqual(body['start_date'], '2026-10-01')
        self.assertEqual(body['updated_by'], 'anonymous')
        self.save(scope='Changed', profiles=['P'])
        self.assertEqual(ChecklistEngagement.objects.count(), 1)
        out = load_engagement(HASH)
        self.assertEqual((out['scope'], out['profiles']), ('Changed', ['P']))

    def test_empty_save_clears_fields(self):
        self.save()
        self.client.post(f'{self.base}/engagement/', {})
        out = load_engagement(HASH)
        self.assertEqual((out['scope'], out['profiles'], out['start_date']),
                         ('', [], ''))

    def test_validation(self):
        for bad in ({'profiles': ['L3']}, {'start_date': 'not-a-date'},
                    {'rooted': 'maybe'}, {'scope': 'x' * 4001},
                    {'testers': 'x' * 301}, {'accounts': 'x' * 2001},
                    {'start_date': '2026-10-10', 'end_date': '2026-10-01'}):
            self.assertEqual(self.save(**bad).status_code, 400, bad)
        self.assertEqual(ChecklistEngagement.objects.count(), 0)

    def test_methods_hash_and_unknown_scan(self):
        self.assertEqual(
            self.client.get(f'{self.base}/engagement/').status_code, 405)
        bad = self.client.post('/checklist/zz/engagement/', FORM)
        self.assertEqual(bad.status_code, 404)
        with mock.patch.object(
                checklist_module.StaticAnalyzerAndroid.objects, 'filter',
                return_value=mock.Mock(exists=lambda: False)), \
                mock.patch.object(
                    checklist_module.StaticAnalyzerIOS.objects, 'filter',
                    return_value=mock.Mock(exists=lambda: False)):
            self.assertEqual(self.save().status_code, 404)

    def test_requires_login_and_permission(self):
        with self.settings(DISABLE_AUTHENTICATION='0'):
            self.assertEqual(self.save().status_code, 302)
            User.objects.create_user('viewer', password='pw-for-test-6')
            self.client.login(username='viewer', password='pw-for-test-6')
            self.assertEqual(self.save().status_code, 403)
            viewer = User.objects.get(username='viewer')
            viewer.user_permissions.add(
                Permission.objects.get(codename='can_review'))
            self.assertEqual(self.save().status_code, 200)
        self.assertEqual(load_engagement(HASH)['updated_by'], 'viewer')

    def test_page_shows_record_and_form_for_reviewers(self):
        self.save()
        page = self.client.get(f'{self.base}/')
        self.assertContains(page, 'Pixel 7')
        self.assertContains(page, 'Android 14')
        self.assertContains(page, '<form id="cl-engagement-form"')
        self.assertContains(page, 'Never type real passwords')

    def test_read_only_without_permission(self):
        self.save()
        with self.settings(DISABLE_AUTHENTICATION='0'):
            User.objects.create_user('viewer', password='pw-for-test-7')
            self.client.login(username='viewer', password='pw-for-test-7')
            page = self.client.get(f'{self.base}/')
        self.assertContains(page, 'Pixel 7')
        self.assertNotContains(page, '<form id="cl-engagement-form"')

    def test_page_escapes_user_text(self):
        self.save(scope='<script>alert(1)</script>')
        page = self.client.get(f'{self.base}/')
        self.assertNotContains(page, '<script>alert(1)</script>')
        self.assertContains(page, '&lt;script&gt;alert(1)&lt;/script&gt;')

    def test_page_has_no_template_errors(self):
        for saved in (False, True):
            if saved:
                self.save()
            with self.assertNoLogs('django.template', level='DEBUG'):
                page = self.client.get(f'{self.base}/')
            self.assertEqual(page.status_code, 200)

    def test_exports_and_scorecard_data(self):
        self.save()
        export = self.client.get(
            f'{self.base}/export/', {'format': 'json'}).json()
        self.assertEqual(export['engagement']['device'], 'Pixel 7')
        with mock.patch.object(appsec, 'common_fields'):
            findings = appsec.get_android_dashboard(
                {'md5': HASH}, from_ctx=True)
        self.assertEqual(findings['engagement']['testers'], 'alice, bob')

    def test_deleted_with_the_scan(self):
        self.save()
        delete_checklist_data(HASH)
        self.assertEqual(ChecklistEngagement.objects.count(), 0)


class EngagementApiTests(WorkflowBase):
    """REST endpoint for the engagement record."""

    def post(self, data, key=True):
        headers = {}
        if key:
            headers['HTTP_X_MOBSF_API_KEY'] = api_key(settings.MOBSF_HOME)
        return self.client.post('/api/v1/checklist_engagement', data,
                                **headers)

    def test_requires_key_and_hash(self):
        self.assertEqual(self.post(dict(FORM, hash=HASH), key=False)
                         .status_code, 401)
        self.assertEqual(self.post(dict(FORM)).status_code, 422)

    def test_save_through_api(self):
        response = self.post(dict(FORM, hash=HASH))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(load_engagement(HASH)['updated_by'], 'api')
        data = self.client.post(
            '/api/v1/checklist', {'hash': HASH},
            HTTP_X_MOBSF_API_KEY=api_key(settings.MOBSF_HOME)).json()
        self.assertEqual(data['engagement']['profiles_text'], 'L1, L2, R')

    def test_api_validation(self):
        bad = self.post(dict(FORM, hash=HASH, profiles=['L9']))
        self.assertEqual(bad.status_code, 400)
        self.assertEqual(
            self.post(dict(FORM, hash='zz')).status_code, 400)
