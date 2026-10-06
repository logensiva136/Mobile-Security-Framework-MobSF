# -*- coding: utf_8 -*-
"""Tests for the MASVS/MASTG/MASWE checklist builder."""
from django.test import SimpleTestCase

from mobsf.StaticAnalyzer.views.common.checklist import build_checklist


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
    """Status mapping for each platform."""

    def status(self, checklist, std, item_id):
        return next(
            i['status'] for i in checklist[std]['items']
            if i['id'] == item_id)

    def test_failed_propagates_to_masvs_and_maswe(self):
        cl = build_checklist(_ctx('storage-2', 'high'), 'android')
        self.assertEqual(self.status(cl, 'MASTG', 'MSTG-STORAGE-2'), 'Failed')
        self.assertEqual(self.status(cl, 'MASVS', 'MASVS-STORAGE-1'), 'Failed')
        self.assertTrue(
            any(i['status'] == 'Failed' for i in cl['MASWE']['items']))

    def test_info_finding_needs_manual_review(self):
        cl = build_checklist(_ctx('storage-3', 'info'), 'android')
        self.assertEqual(
            self.status(cl, 'MASTG', 'MSTG-STORAGE-3'), 'ToBeTest')

    def test_success_and_to_be_test(self):
        cl = build_checklist({}, 'android')
        self.assertEqual(self.status(cl, 'MASTG', 'MSTG-STORAGE-2'), 'Success')
        self.assertEqual(self.status(cl, 'MASTG', 'MSTG-AUTH-12'), 'ToBeTest')

    def test_not_applicable_for_other_scan_types(self):
        cl = build_checklist({}, 'windows')
        self.assertTrue(all(
            i['status'] == 'NotApplicable' for i in cl['MASTG']['items']))

    def test_ios_string_form(self):
        cl = build_checklist(_ctx('MSTG-CRYPTO-3', 'warning'), 'ios')
        self.assertEqual(self.status(cl, 'MASTG', 'MSTG-CRYPTO-3'), 'Failed')
