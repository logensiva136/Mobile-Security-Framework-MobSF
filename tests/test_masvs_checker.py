import unittest

from mobsf.DynamicAnalyzer.checks.masvs_checker import MASVSChecker
from mobsf.DynamicAnalyzer.models import AnalysisContext


class TestMASVSChecker(unittest.TestCase):
    """Unit tests for the MASVSChecker."""

    def setUp(self):
        self.checker = MASVSChecker()
        self.good = AnalysisContext(
            runtime_vars={'mock': 1},
            credentials={'password_strength': 5},
            local_storage={'is_encrypted': True},
            mfa_enabled=True,
            session_tokens={'expiry_seconds': 7200},
            api_endpoint_details={'rate_limited': True},
            retention_policy_active=True)
        self.bad = AnalysisContext(
            runtime_vars={'mock': 1},
            credentials={'password_strength': 2},
            local_storage={'is_encrypted': False},
            mfa_enabled=False,
            session_tokens={'expiry_seconds': 3600},
            api_endpoint_details={'rate_limited': False},
            retention_policy_active=False)

    def test_good_state(self):
        findings = self.checker.check(self.good)
        self.assertEqual(len(findings), 6)
        self.assertTrue(all(f.status == 'PASS' for f in findings))

    def test_bad_state(self):
        findings = self.checker.check(self.bad)
        bad = [f for f in findings if f.status in ('FAIL', 'WARN')]
        self.assertGreaterEqual(len(bad), 5)

    def test_empty_context(self):
        findings = self.checker.check(AnalysisContext(runtime_vars={}))
        self.assertEqual(findings[0].control_id, 'CORE-001')
        self.assertEqual(findings[0].status, 'FAIL')


if __name__ == '__main__':
    unittest.main()
