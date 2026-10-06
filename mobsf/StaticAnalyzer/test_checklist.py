# -*- coding: utf_8 -*-
"""Tests for the OWASP MAS standards data and checklist builder."""
import json
from datetime import datetime, timedelta, timezone
from unittest import mock

from django.conf import settings
from django.test import SimpleTestCase, TestCase

from mobsf.MobSF.init import api_key
from mobsf.StaticAnalyzer.views.common import checklist as checklist_module
from mobsf.StaticAnalyzer.views.common import mas_standards
from mobsf.StaticAnalyzer.views.common.checklist import build_checklist

FIXTURE = {
    'meta': {
        'source': 'OWASP MAS',
        'source_url': mas_standards.SOURCE_URL,
        'retrieved_at': datetime.now(timezone.utc).isoformat(),
        'counts': {'masvs': 2, 'maswe': 3, 'mastg': 3},
    },
    'masvs': [
        {'id': 'MASVS-STORAGE-1', 'category': 'MASVS-STORAGE',
         'title': 'Stores data securely.',
         'weaknesses': ['MASWE-0001'], 'url': ''},
        {'id': 'MASVS-AUTH-1', 'category': 'MASVS-AUTH',
         'title': 'Secure auth.', 'weaknesses': ['MASWE-0018'], 'url': ''},
    ],
    'maswe': [
        {'id': 'MASWE-0001', 'title': 'Unencrypted storage',
         'category': 'MASVS-STORAGE', 'masvs_v1': ['MSTG-STORAGE-2'],
         'masvs_v2': ['MASVS-STORAGE-1'], 'tests': ['MASTG-TEST-0207'],
         'url': ''},
        {'id': 'MASWE-0018', 'title': 'Missing authz',
         'category': 'MASVS-AUTH', 'masvs_v1': ['MSTG-AUTH-3'],
         'masvs_v2': ['MASVS-AUTH-1'], 'tests': [], 'url': ''},
        {'id': 'MASWE-0099', 'title': 'No legacy mapping',
         'category': 'MASVS-CODE', 'masvs_v1': [],
         'masvs_v2': [], 'tests': [], 'url': ''},
    ],
    'mastg': [
        {'id': 'MASTG-TEST-0207', 'title': 'Android storage test',
         'platform': 'android', 'category': 'MASVS-STORAGE',
         'deprecated': False, 'url': ''},
        {'id': 'MASTG-TEST-0208', 'title': 'iOS storage test',
         'platform': 'ios', 'category': 'MASVS-STORAGE',
         'deprecated': False, 'url': ''},
        {'id': 'MASTG-TEST-0001', 'title': 'Old test',
         'platform': 'android', 'category': 'MASVS-STORAGE',
         'deprecated': True, 'url': ''},
    ],
}


def _ctx(masvs, sev):
    return {
        'code_analysis': {
            'findings': {
                'rule': {
                    'metadata': {
                        'masvs': masvs,
                        'severity': sev,
                        'description': 'bad thing',
                    },
                },
            },
        },
    }


class ChecklistTests(SimpleTestCase):
    """Status mapping for each standard and platform."""

    def status(self, checklist, std, item_id):
        return next(
            i['status'] for i in checklist[std]['items']
            if i['id'] == item_id)

    def build(self, data, platform='android'):
        return build_checklist(data, platform, FIXTURE)

    def test_failed_propagates_to_masvs(self):
        cl = self.build(_ctx('storage-2', 'high'))
        self.assertEqual(self.status(cl, 'MASWE', 'MASWE-0001'), 'Failed')
        self.assertEqual(
            self.status(cl, 'MASVS', 'MASVS-STORAGE-1'), 'Failed')
        self.assertEqual(self.status(cl, 'MASVS', 'MASVS-AUTH-1'), 'ToBeTest')

    def test_failed_weakness_is_evidence_on_its_tests(self):
        cl = self.build(_ctx('storage-2', 'high'))
        test = next(i for i in cl['MASTG']['items']
                    if i['id'] == 'MASTG-TEST-0207')
        self.assertEqual(test['status'], 'ToBeTest')
        self.assertIn('MASWE-0001', test['evidence'][0])

    def test_success_needs_every_tag_covered_and_clean(self):
        cl = self.build({})
        self.assertEqual(self.status(cl, 'MASWE', 'MASWE-0001'), 'Success')
        self.assertEqual(self.status(cl, 'MASVS', 'MASVS-STORAGE-1'),
                         'Success')
        self.assertEqual(self.status(cl, 'MASWE', 'MASWE-0099'), 'ToBeTest')

    def test_info_finding_needs_manual_review(self):
        cl = self.build(_ctx('storage-2', 'info'))
        self.assertEqual(self.status(cl, 'MASWE', 'MASWE-0001'), 'ToBeTest')

    def test_mastg_platform_and_deprecation(self):
        cl = self.build({}, 'android')
        ids = [i['id'] for i in cl['MASTG']['items']]
        self.assertNotIn('MASTG-TEST-0001', ids)
        self.assertEqual(
            self.status(cl, 'MASTG', 'MASTG-TEST-0207'), 'ToBeTest')
        self.assertEqual(
            self.status(cl, 'MASTG', 'MASTG-TEST-0208'), 'NotApplicable')

    def test_not_applicable_for_other_scan_types(self):
        cl = self.build({}, 'windows')
        for std in ('MASVS', 'MASWE', 'MASTG'):
            self.assertTrue(all(i['status'] == 'NotApplicable'
                                for i in cl[std]['items']))

    def test_ios_string_form(self):
        cl = self.build(_ctx('MSTG-CRYPTO-3', 'warning'), 'ios')
        self.assertEqual(cl['MASWE']['summary']['Failed'], 0)

    def test_source_info_included(self):
        cl = self.build({})
        self.assertEqual(cl['source']['source'], 'OWASP MAS')
        self.assertFalse(cl['source']['stale'])
        self.assertEqual(cl['source']['age_days'], 0)


class StandardsTests(SimpleTestCase):
    """Parsing, freshness and update safety."""

    INDEX = {'docs': [
        {'location': 'MASVS/controls/MASVS-STORAGE-1/',
         'title': 'MASVS-STORAGE-1',
         'text': '<p>The app stores data securely.</p>'},
        {'location': 'MASVS/controls/MASVS-STORAGE-1/#related-weaknesses',
         'title': 'Related Weaknesses',
         'text': '<p>MASWE-0001: Unencrypted</p>'},
        {'location': 'MASWE/MASVS-STORAGE/MASWE-0001/',
         'title': 'MASWE-0001: Unencrypted',
         'text': '<p>Mappings</p><p>MASVS V1: MSTG-STORAGE-2</p>'
                 '<p>MASVS V2: MASVS-STORAGE-1</p><p>CWE: CWE-311</p>'},
        {'location': 'MASWE/MASVS-STORAGE/MASWE-0001/#tests',
         'title': 'Tests', 'text': '<p>MASTG-TEST-0207: Test</p>'},
        {'location': 'MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0207/',
         'title': 'MASTG-TEST-0207: Test', 'text': '<p>Overview</p>'},
        {'location': 'MASTG/tests/ios/MASVS-STORAGE/MASTG-TEST-0001/',
         'title': 'MASTG-TEST-0001: Old',
         'text': '<p>Deprecated Test</p>'},
        {'location': 'some/<script>/', 'title': 'ignored', 'text': ''},
    ]}

    def test_parse_search_index(self):
        data = mas_standards.parse_search_index(self.INDEX)
        self.assertTrue(mas_standards.is_valid(data))
        self.assertEqual(data['meta']['counts'],
                         {'masvs': 1, 'maswe': 1, 'mastg': 2})
        self.assertEqual(data['masvs'][0]['weaknesses'], ['MASWE-0001'])
        weak = data['maswe'][0]
        self.assertEqual(weak['masvs_v1'], ['MSTG-STORAGE-2'])
        self.assertEqual(weak['masvs_v2'], ['MASVS-STORAGE-1'])
        self.assertEqual(weak['tests'], ['MASTG-TEST-0207'])
        old = next(t for t in data['mastg']
                   if t['id'] == 'MASTG-TEST-0001')
        self.assertTrue(old['deprecated'])
        self.assertTrue(data['masvs'][0]['url'].startswith(
            'https://mas.owasp.org/'))

    def test_invalid_data_rejected(self):
        self.assertFalse(mas_standards.is_valid({}))
        self.assertFalse(mas_standards.is_valid({'masvs': []}))
        self.assertFalse(mas_standards.is_valid(None))

    def test_bundled_snapshot_is_valid(self):
        with open(mas_standards.SNAPSHOT, encoding='utf-8') as fp:
            data = json.load(fp)
        self.assertTrue(mas_standards.is_valid(data))
        self.assertTrue(data['meta']['retrieved_at'])

    def test_stale_detection(self):
        old = dict(FIXTURE)
        old['meta'] = dict(FIXTURE['meta'])
        stamp = datetime.now(timezone.utc) - timedelta(days=40)
        old['meta']['retrieved_at'] = stamp.isoformat()
        info = mas_standards.standards_info(old)
        self.assertTrue(info['stale'])
        self.assertEqual(info['age_days'], 40)

    def test_refresh_skipped_when_disabled_or_fresh(self):
        with self.settings(MAS_AUTO_UPDATE=False):
            self.assertFalse(mas_standards.refresh_if_stale())
        with mock.patch.object(
                mas_standards, 'standards_info',
                return_value={'stale': False}):
            self.assertFalse(mas_standards.refresh_if_stale())

    def test_refresh_runs_once_a_day_when_stale(self):
        with mock.patch.object(
                mas_standards, 'standards_info',
                return_value={'stale': True}), \
                mock.patch.object(mas_standards, '_refresh') as refresh, \
                mock.patch.dict(mas_standards._state, {'last_attempt': 0.0}):
            self.assertTrue(mas_standards.refresh_if_stale())
            self.assertFalse(mas_standards.refresh_if_stale())
        self.assertLessEqual(refresh.call_count, 1)

    def test_update_only_uses_fixed_https_source(self):
        self.assertEqual(
            mas_standards.SOURCE_URL,
            'https://mas.owasp.org/search/search_index.json')
        response = mock.Mock(status_code=500)
        with mock.patch.object(
                mas_standards, 'safe_request',
                return_value=response) as req:
            with self.assertRaises(ValueError):
                mas_standards.update_standards()
        self.assertEqual(req.call_args[0][1], mas_standards.SOURCE_URL)
        self.assertEqual(req.call_args[1]['allowed_ports'], (443,))
        self.assertEqual(req.call_args[1]['max_redirects'], 0)


HASH = 'a' * 32
SCAN_DATA = {'app_name': 'Demo', 'file_name': 'demo.apk'}


def _patch_scan(found=True, platform='android'):
    """Patch DB lookups so no real scan is needed."""
    row = mock.Mock() if found else None
    android = mock.patch.object(
        checklist_module.StaticAnalyzerAndroid.objects, 'filter',
        return_value=mock.Mock(first=lambda: row if platform == 'android'
                               else None))
    ios = mock.patch.object(
        checklist_module.StaticAnalyzerIOS.objects, 'filter',
        return_value=mock.Mock(first=lambda: row if platform == 'ios'
                               else None))
    reader = mock.patch.object(
        checklist_module, 'adb', return_value=dict(SCAN_DATA))
    ios_reader = mock.patch.object(
        checklist_module, 'idb', return_value=dict(SCAN_DATA))
    refresh = mock.patch.object(checklist_module, 'refresh_if_stale')
    return (android, ios, reader, ios_reader, refresh)


class ChecklistViewTests(TestCase):
    """Web page: methods, authentication, errors and content."""

    url = f'/checklist/{HASH}/'

    def run_with_scan(self, func, found=True, platform='android'):
        patches = _patch_scan(found, platform)
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        return func()

    def test_post_is_rejected(self):
        with self.settings(DISABLE_AUTHENTICATION='1'):
            self.assertEqual(self.client.post(self.url).status_code, 405)

    def test_login_required(self):
        with self.settings(DISABLE_AUTHENTICATION='0'):
            response = self.client.get(self.url)
        self.assertEqual(response.status_code, 302)
        self.assertIn('login', response['Location'])

    def test_unknown_scan(self):
        with self.settings(DISABLE_AUTHENTICATION='1'):
            response = self.run_with_scan(
                lambda: self.client.get(self.url), found=False)
        self.assertContains(
            response, 'Report not found', status_code=500)

    def test_android_page_shows_retrieval_info(self):
        with self.settings(DISABLE_AUTHENTICATION='1'):
            response = self.run_with_scan(lambda: self.client.get(self.url))
        self.assertContains(response, 'retrieved on')
        self.assertContains(response, 'MASVS-STORAGE-1')

    def test_ios_page(self):
        with self.settings(DISABLE_AUTHENTICATION='1'):
            response = self.run_with_scan(
                lambda: self.client.get(self.url), platform='ios')
        self.assertEqual(response.status_code, 200)

    def test_invalid_hash_not_routed(self):
        with self.settings(DISABLE_AUTHENTICATION='1'):
            self.assertEqual(
                self.client.get('/checklist/not-a-hash/').status_code, 404)


class ChecklistApiTests(TestCase):
    """REST API: key, parameters and response shape."""

    url = '/api/v1/checklist'

    def post(self, data, key=True):
        headers = {}
        if key:
            headers['HTTP_X_MOBSF_API_KEY'] = api_key(settings.MOBSF_HOME)
        return self.client.post(self.url, data, **headers)

    def test_requires_api_key(self):
        self.assertEqual(self.post({'hash': HASH}, key=False).status_code, 401)

    def test_get_not_allowed(self):
        response = self.client.get(
            self.url, HTTP_X_MOBSF_API_KEY=api_key(settings.MOBSF_HOME))
        self.assertEqual(response.status_code, 405)

    def test_missing_hash(self):
        self.assertEqual(self.post({}).status_code, 422)

    def test_invalid_hash(self):
        self.assertEqual(self.post({'hash': 'zz'}).status_code, 400)

    def test_not_found(self):
        patches = _patch_scan(found=False)
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.assertEqual(self.post({'hash': HASH}).status_code, 404)

    def test_checklist_response(self):
        patches = _patch_scan()
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        response = self.post({'hash': HASH})
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body['platform'], 'android')
        self.assertIn('retrieved_at', body['checklist']['source'])
        for std in ('MASVS', 'MASWE', 'MASTG'):
            self.assertIn(std, body['checklist'])
