# -*- coding: utf_8 -*-
"""Tests for the OWASP MAS standards data and checklist builder."""
import json
from datetime import datetime, timedelta, timezone
from unittest import mock

from django.conf import settings
from django.contrib.auth.models import Permission, User
from django.test import SimpleTestCase, TestCase

from mobsf.MobSF.init import api_key
from mobsf.StaticAnalyzer.models import ChecklistReview
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
        {'id': 'MASWE-0030', 'title': 'Improper clipboard use',
         'category': 'MASVS-PLATFORM', 'masvs_v1': [],
         'masvs_v2': [], 'cwe': ['CWE-200', 'CWE-668'],
         'tests': [], 'url': ''},
        {'id': 'MASWE-0049', 'title': 'Unsafe dynamic code loading',
         'category': 'MASVS-CODE', 'masvs_v1': [],
         'masvs_v2': [], 'cwe': ['CWE-494'], 'tests': [], 'url': ''},
        {'id': 'MASWE-0098', 'title': 'Certificate validation',
         'category': 'MASVS-NETWORK', 'masvs_v1': [],
         'masvs_v2': [], 'cwe': ['CWE-295'], 'tests': [], 'url': ''},
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


def _ctx_maswe(maswe, sev):
    return {
        'android_api': {
            'api_dexloading': {
                'metadata': {
                    'maswe': maswe,
                    'severity': sev,
                    'description': 'Dynamic Class and Dexloading',
                },
            },
        },
    }


def _ctx_cwe(cwe, sev):
    return {
        'code_analysis': {
            'findings': {
                'rule': {
                    'metadata': {
                        'cwe': cwe,
                        'severity': sev,
                        'description': 'cert problem',
                    },
                },
            },
        },
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

    def test_cwe_fallback_fails_weakness_without_legacy_tag(self):
        cl = self.build(_ctx_cwe('cwe-295', 'high'))
        item = next(i for i in cl['MASWE']['items']
                    if i['id'] == 'MASWE-0098')
        self.assertEqual(item['status'], 'Failed')
        self.assertIn('CWE-295', item['evidence'][0])

    def test_cwe_fallback_success_when_rule_covers_it(self):
        cl = self.build({})
        self.assertEqual(self.status(cl, 'MASWE', 'MASWE-0098'), 'Success')

    def test_cwe_info_finding_needs_review(self):
        cl = self.build(_ctx_cwe('cwe-295', 'info'))
        self.assertEqual(self.status(cl, 'MASWE', 'MASWE-0098'), 'ToBeTest')

    def test_cwe_does_not_affect_weakness_with_legacy_tag(self):
        cl = self.build(_ctx_cwe('cwe-311', 'high'))
        self.assertEqual(self.status(cl, 'MASWE', 'MASWE-0001'), 'Success')

    def test_uncovered_cwe_stays_to_be_tested(self):
        cl = self.build({}, 'ios')
        item = next(i for i in cl['MASWE']['items']
                    if i['id'] == 'MASWE-0099')
        self.assertEqual(item['status'], 'ToBeTest')

    def test_rule_naming_weakness_decides_it(self):
        clean = self.build({})
        self.assertEqual(
            self.status(clean, 'MASWE', 'MASWE-0049'), 'Success')
        used = self.build(_ctx_maswe('MASWE-0049', 'info'))
        item = next(i for i in used['MASWE']['items']
                    if i['id'] == 'MASWE-0049')
        self.assertEqual(item['status'], 'ToBeTest')
        self.assertTrue(item['evidence'][0].startswith(
            'Dynamic Class and Dexloading'))
        bad = self.build(_ctx_maswe('MASWE-0049', 'high'))
        self.assertEqual(self.status(bad, 'MASWE', 'MASWE-0049'), 'Failed')

    def test_rule_naming_weakness_ignored_on_other_platform(self):
        ios = self.build({}, 'ios')
        self.assertEqual(self.status(ios, 'MASWE', 'MASWE-0049'), 'ToBeTest')

    def test_ios_api_rules_count_only_for_source_scans(self):
        zip_scan = {'file_name': 'App.zip'}
        ipa_scan = {'file_name': 'App.ipa'}
        source = self.build(zip_scan, 'ios')
        binary = self.build(ipa_scan, 'ios')
        self.assertEqual(
            self.status(source, 'MASWE', 'MASWE-0030'), 'Success')
        self.assertEqual(
            self.status(binary, 'MASWE', 'MASWE-0030'), 'ToBeTest')

    def test_android_api_rules_count_for_apk(self):
        cl = self.build({'file_name': 'app.apk'}, 'android')
        self.assertEqual(self.status(cl, 'MASWE', 'MASWE-0030'), 'Success')

    def test_evidence_explains_every_status(self):
        clean = self.build({'file_name': 'app.apk'})
        success = next(i for i in clean['MASWE']['items']
                       if i['id'] == 'MASWE-0049')
        self.assertIn('no findings from', success['evidence'][0])
        self.assertIn('Dynamic Class and Dexloading', success['evidence'][0])
        manual = next(i for i in clean['MASWE']['items']
                      if i['id'] == 'MASWE-0099')
        self.assertIn('No automated rule covers', manual['evidence'][0])
        test = next(i for i in clean['MASTG']['items']
                    if i['id'] == 'MASTG-TEST-0207')
        self.assertIn('Manual test procedure', test['evidence'][-1])
        other = next(i for i in clean['MASTG']['items']
                     if i['id'] == 'MASTG-TEST-0208')
        self.assertIn('ios apps only', other['evidence'][0])
        control = next(i for i in clean['MASVS']['items']
                       if i['id'] == 'MASVS-STORAGE-1')
        self.assertIn('related weaknesses', control['evidence'][0])

    def test_failed_evidence_names_files_and_severity(self):
        data = _ctx('storage-2', 'high')
        rule = data['code_analysis']['findings']['rule']
        rule['files'] = {'com/app/Util.java': '12,30'}
        cl = self.build(data)
        item = next(i for i in cl['MASWE']['items']
                    if i['id'] == 'MASWE-0001')
        text = item['evidence'][0]
        self.assertIn('[high]', text)
        self.assertIn('com/app/Util.java (12,30)', text)

    def test_failed_masvs_evidence_lists_weaknesses(self):
        cl = self.build(_ctx('storage-2', 'high'))
        control = next(i for i in cl['MASVS']['items']
                       if i['id'] == 'MASVS-STORAGE-1')
        self.assertIn('MASWE-0001', control['evidence'][0])

    def test_source_info_included(self):
        cl = self.build({})
        self.assertEqual(cl['source']['source'], 'OWASP MAS')
        self.assertFalse(cl['source']['stale'])
        self.assertEqual(cl['source']['age_days'], 0)


class GuideTests(SimpleTestCase):
    """How-to-test guidance built from the bundled OWASP data."""

    def build(self, platform='android'):
        with open(mas_standards.SNAPSHOT, encoding='utf-8') as fp:
            standards = json.load(fp)
        data = {'file_name': 'app.apk'}
        cl = build_checklist(data, platform, standards)
        checklist_module.attach_guides(cl, standards, platform)
        return cl

    def test_every_live_item_has_a_guide(self):
        cl = self.build()
        for std in ('MASVS', 'MASWE'):
            self.assertTrue(all('guide' in i for i in cl[std]['items']))
        self.assertTrue(all('guide' in i for i in cl['MASTG']['items']))

    def test_mastg_guide_has_steps_tools_and_expected_result(self):
        cl = self.build()
        item = next(i for i in cl['MASTG']['items']
                    if i['id'] == 'MASTG-TEST-0207')
        guide = item['guide']
        self.assertIn('Use Installing Apps', guide['how'])
        self.assertTrue(guide['techniques'])
        self.assertIn('fails if', guide['expect'])
        self.assertTrue(guide['what'])
        self.assertTrue(guide['when'])

    def test_maswe_guide_lists_platform_tests_and_fix(self):
        cl = self.build('android')
        item = next(i for i in cl['MASWE']['items']
                    if i['id'] == 'MASWE-0001')
        guide = item['guide']
        self.assertTrue(guide['links'])
        self.assertIn('Run the MASTG tests', guide['how'])
        self.assertTrue(guide['fix'])
        ids = {t['id'] for t in guide['links']}
        ios = {i['id'] for i in self.build('ios')['MASTG']['items']
               if i['status'] != 'NotApplicable'}
        self.assertFalse(ids & ios)

    def test_weakness_without_tests_says_so(self):
        cl = self.build()
        item = next(i for i in cl['MASWE']['items']
                    if i['id'] == 'MASWE-0049')
        self.assertIn('no MASTG test', item['guide']['how'])

    def test_masvs_guide_links_related_weaknesses(self):
        cl = self.build()
        item = next(i for i in cl['MASVS']['items']
                    if i['id'] == 'MASVS-STORAGE-1')
        self.assertTrue(item['guide']['links'])
        self.assertTrue(all(
            link['url'].startswith('https://mas.owasp.org/')
            for link in item['guide']['links']))


class RuleTagTests(SimpleTestCase):
    """Rule files only reference real OWASP weakness ids."""

    def test_maswe_tags_in_rules_exist_in_standards(self):
        with open(mas_standards.SNAPSHOT, encoding='utf-8') as fp:
            known = {w['id'] for w in json.load(fp)['maswe']}
        used = set()
        for paths in checklist_module.RULE_FILES.values():
            for path in paths:
                used |= checklist_module._maswe_tags(
                    '\n'.join(
                        line for line in path.read_text(
                            encoding='utf-8').splitlines()
                        if 'maswe' in line.lower()))
        self.assertTrue(used)
        self.assertEqual(used - known, set())


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
                 '<p>MASVS V2: MASVS-STORAGE-1</p><p>CWE: CWE-311: Missing '
                 'Encryption, CWE-312: Cleartext</p>'},
        {'location': 'MASWE/MASVS-STORAGE/MASWE-0001/#tests',
         'title': 'Tests', 'text': '<p>MASTG-TEST-0207: Test</p>'},
        {'location': 'MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0207/',
         'title': 'MASTG-TEST-0207: Test', 'text': '<p>Overview</p>'},
        {'location': 'MASTG/tests/ios/MASVS-STORAGE/MASTG-TEST-0001/',
         'title': 'MASTG-TEST-0001: Old',
         'text': '<p>Deprecated Test</p>'},
        {'location': 'MASTG/techniques/android/MASTG-TECH-0005/',
         'title': 'MASTG-TECH-0005: Installing Apps', 'text': ''},
        {'location': 'MASTG/techniques/ios/MASTG-TECH-0056/',
         'title': 'MASTG-TECH-0056: Installing Apps', 'text': ''},
        {'location': 'MASTG/tools/android/MASTG-TOOL-0001/',
         'title': 'MASTG-TOOL-0001: Frida (Android)', 'text': ''},
        {'location': 'MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0207/'
                     '#steps',
         'title': 'Steps',
         'text': '<ol><li>Use  Installing Apps to install the app.</li>'
                 '<li>Run Frida to hook the app.</li></ol>'},
        {'location': 'MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0207/'
                     '#observation',
         'title': 'Observation', 'text': '<p>A list of files.</p>'},
        {'location': 'MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0207/'
                     '#evaluation',
         'title': 'Evaluation', 'text': '<p>Fails if secrets are found.</p>'},
        {'location': 'MASWE/MASVS-STORAGE/MASWE-0001/#overview',
         'title': 'Overview', 'text': '<p>Data is stored unencrypted.</p>'},
        {'location': 'MASWE/MASVS-STORAGE/MASWE-0001/#modes-of-introduction',
         'title': 'Modes', 'text': '<ul><li>Writing files in plain text</li>'
                                   '</ul>'},
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
        self.assertEqual(weak['cwe'], ['CWE-311', 'CWE-312'])
        old = next(t for t in data['mastg']
                   if t['id'] == 'MASTG-TEST-0001')
        self.assertTrue(old['deprecated'])
        self.assertTrue(data['masvs'][0]['url'].startswith(
            'https://mas.owasp.org/'))

    def test_how_to_test_guidance_is_parsed(self):
        data = mas_standards.parse_search_index(self.INDEX)
        test = next(t for t in data['mastg']
                    if t['id'] == 'MASTG-TEST-0207')
        self.assertTrue(test['steps'].startswith(
            '- Use Installing Apps to install the app.'))
        self.assertIn('\n- Run Frida', test['steps'])
        self.assertEqual([t['id'] for t in test['techniques']],
                         ['MASTG-TECH-0005'])
        self.assertEqual([t['id'] for t in test['tools']],
                         ['MASTG-TOOL-0001'])
        self.assertEqual(test['observation'], 'A list of files.')
        self.assertEqual(test['evaluation'], 'Fails if secrets are found.')
        weak = data['maswe'][0]
        self.assertEqual(weak['overview'], 'Data is stored unencrypted.')
        self.assertEqual(weak['modes'], '- Writing files in plain text')

    def test_old_schema_data_is_rejected(self):
        data = mas_standards.parse_search_index(self.INDEX)
        self.assertTrue(mas_standards.is_valid(data))
        data['meta']['schema'] = 1
        self.assertFalse(mas_standards.is_valid(data))

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

    def test_page_shows_why_and_how_to_test(self):
        with self.settings(DISABLE_AUTHENTICATION='1'):
            response = self.run_with_scan(lambda: self.client.get(self.url))
        self.assertContains(response, 'Why this status')
        self.assertContains(response, 'How to test')
        self.assertContains(response, 'Manual test procedure')
        self.assertContains(response, 'MobSF does not run them')

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


def _review(status, note='checked'):
    return {
        'status': status,
        'note': note,
        'reviewer': 'tester',
        'updated_at': '2026-10-06 10:00 UTC',
    }


class ReviewMergeTests(SimpleTestCase):
    """Tester decisions merged into the automated checklist."""

    def build(self, data, reviews, platform='android'):
        return build_checklist(data, platform, FIXTURE, reviews)

    def item(self, cl, std, item_id):
        return next(i for i in cl[std]['items'] if i['id'] == item_id)

    def test_review_replaces_to_be_test(self):
        cl = self.build({}, {('MASWE', 'MASWE-0099'): _review('Success')})
        item = self.item(cl, 'MASWE', 'MASWE-0099')
        self.assertEqual(item['status'], 'Success')
        self.assertEqual(item['automated_status'], 'ToBeTest')
        self.assertEqual(item['review']['reviewer'], 'tester')

    def test_review_never_hides_automated_failed(self):
        data = _ctx('storage-2', 'high')
        cl = self.build(data, {('MASWE', 'MASWE-0001'): _review('Success')})
        item = self.item(cl, 'MASWE', 'MASWE-0001')
        self.assertEqual(item['status'], 'Failed')
        self.assertEqual(item['review']['status'], 'Success')

    def test_review_rolls_up_to_masvs(self):
        cl = self.build(
            {}, {('MASWE', 'MASWE-0018'): _review('Success')})
        self.assertEqual(
            self.item(cl, 'MASVS', 'MASVS-AUTH-1')['status'], 'Success')

    def test_summary_counts_effective_status(self):
        cl = self.build({}, {('MASTG', 'MASTG-TEST-0207'): _review('Failed')})
        self.assertEqual(cl['MASTG']['summary']['Failed'], 1)


class ReviewEndpointTests(TestCase):
    """Saving, clearing and exporting tester decisions."""

    base = f'/checklist/{HASH}'

    def setUp(self):
        self.patches = _patch_scan()
        for patch in self.patches:
            patch.start()
            self.addCleanup(patch.stop)
        std_patch = mock.patch.object(
            checklist_module, 'load_standards', return_value=FIXTURE)
        std_patch.start()
        self.addCleanup(std_patch.stop)

    def save(self, **fields):
        data = {'standard': 'MASWE', 'item_id': 'MASWE-0099',
                'status': 'Success', 'note': 'verified'}
        data.update(fields)
        with self.settings(DISABLE_AUTHENTICATION='1'):
            return self.client.post(f'{self.base}/review/', data)

    def test_save_and_clear(self):
        response = self.save()
        self.assertEqual(response.status_code, 200)
        row = ChecklistReview.objects.get(MD5=HASH, ITEM_ID='MASWE-0099')
        self.assertEqual((row.STATUS, row.NOTE), ('Success', 'verified'))
        self.assertEqual(response.json()['review']['reviewer'], 'anonymous')
        self.save(status='Failed', note='again')
        self.assertEqual(ChecklistReview.objects.count(), 1)
        self.assertEqual(ChecklistReview.objects.get().STATUS, 'Failed')
        self.assertEqual(self.save(status='').status_code, 200)
        self.assertEqual(ChecklistReview.objects.count(), 0)

    def test_rejects_bad_input(self):
        self.assertEqual(self.save(standard='OTHER').status_code, 400)
        self.assertEqual(self.save(status='Maybe').status_code, 400)
        self.assertEqual(self.save(item_id='../etc').status_code, 400)
        self.assertEqual(self.save(note='x' * 2001).status_code, 400)
        # Valid format but not part of this checklist
        self.assertEqual(self.save(item_id='MASWE-7777').status_code, 400)
        self.assertEqual(ChecklistReview.objects.count(), 0)

    def test_get_not_allowed(self):
        with self.settings(DISABLE_AUTHENTICATION='1'):
            response = self.client.get(f'{self.base}/review/')
        self.assertEqual(response.status_code, 405)

    def test_requires_login_and_permission(self):
        data = {'standard': 'MASWE', 'item_id': 'MASWE-0099',
                'status': 'Success'}
        with self.settings(DISABLE_AUTHENTICATION='0'):
            anon = self.client.post(f'{self.base}/review/', data)
            self.assertEqual(anon.status_code, 302)
            User.objects.create_user('viewer', password='pw-for-test-1')
            self.client.login(username='viewer', password='pw-for-test-1')
            viewer = self.client.post(f'{self.base}/review/', data)
            self.assertEqual(viewer.status_code, 403)
            user = User.objects.get(username='viewer')
            user.user_permissions.add(
                Permission.objects.get(codename='can_review'))
            allowed = self.client.post(f'{self.base}/review/', data)
            self.assertEqual(allowed.status_code, 200)
            self.assertEqual(allowed.json()['review']['reviewer'], 'viewer')

    def test_review_shown_on_page_and_in_api(self):
        self.save(note='manual proof')
        with self.settings(DISABLE_AUTHENTICATION='1'):
            page = self.client.get(f'{self.base}/')
        self.assertContains(page, 'manual proof')
        self.assertContains(page, 'cl-save')

    def test_export_csv_neutralizes_formulas(self):
        self.save(note='=HYPERLINK("http://evil")')
        with self.settings(DISABLE_AUTHENTICATION='1'):
            response = self.client.get(
                f'{self.base}/export/', {'format': 'csv'})
        self.assertEqual(response.status_code, 200)
        self.assertIn('text/csv', response['Content-Type'])
        self.assertIn('attachment', response['Content-Disposition'])
        body = response.content.decode()
        self.assertIn("'=HYPERLINK", body)
        self.assertNotIn(',=HYPERLINK', body)

    def test_export_json_and_bad_format(self):
        with self.settings(DISABLE_AUTHENTICATION='1'):
            ok = self.client.get(f'{self.base}/export/', {'format': 'json'})
            bad = self.client.get(f'{self.base}/export/', {'format': 'xml'})
        self.assertEqual(ok.status_code, 200)
        self.assertIn('source', ok.json()['checklist'])
        self.assertEqual(bad.status_code, 400)
