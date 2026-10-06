import unittest

from mobsf.StaticAnalyzer.views.common.checklist import build_checklist


def _ctx(masvs, sev):
    return {'code_analysis': {'findings': {'r': {'metadata': {
        'masvs': masvs, 'severity': sev, 'description': 'bad thing'}}}}}


class TestChecklist(unittest.TestCase):
    def status(self, cl, std, item_id):
        return next(i['status'] for i in cl[std]['items']
                    if i['id'] == item_id)

    def test_failed_and_propagation(self):
        cl = build_checklist(_ctx('storage-2', 'high'), 'android')
        self.assertEqual(self.status(cl, 'MASTG', 'MSTG-STORAGE-2'), 'Failed')
        self.assertEqual(self.status(cl, 'MASVS', 'MASVS-STORAGE-1'), 'Failed')
        self.assertTrue(any(i['status'] == 'Failed'
                            for i in cl['MASWE']['items']))

    def test_to_be_test_and_success(self):
        cl = build_checklist({}, 'android')
        self.assertEqual(self.status(cl, 'MASTG', 'MSTG-STORAGE-2'), 'Success')
        self.assertEqual(self.status(cl, 'MASTG', 'MSTG-AUTH-12'), 'ToBeTest')

    def test_not_applicable(self):
        cl = build_checklist({}, 'windows')
        self.assertTrue(all(i['status'] == 'NotApplicable'
                            for i in cl['MASTG']['items']))

    def test_ios_string_form(self):
        cl = build_checklist(_ctx('MSTG-CRYPTO-3', 'warning'), 'ios')
        self.assertEqual(self.status(cl, 'MASTG', 'MSTG-CRYPTO-3'), 'Failed')


if __name__ == '__main__':
    unittest.main()
