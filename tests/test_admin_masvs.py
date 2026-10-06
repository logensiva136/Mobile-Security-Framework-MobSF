import unittest

from mobsf.DynamicAnalyzer.admin import DynamicAnalyzer
from mobsf.DynamicAnalyzer.models import AnalysisContext, OverallStatus


class TestDynamicAnalyzerMASVS(unittest.TestCase):
    def test_good_context_scores_100(self):
        ctx = AnalysisContext(
            runtime_vars={'x': 1},
            credentials={'password_strength': 5},
            local_storage={'is_encrypted': True},
            mfa_enabled=True,
            session_tokens={'expiry_seconds': 7200},
            api_endpoint_details={'rate_limited': True},
            retention_policy_active=True)
        report = DynamicAnalyzer({'app_name': 'a'}, ctx).run_analysis()
        summary = report.generate_summary()
        self.assertEqual(summary['masvs']['compliance_score'], 100.0)
        self.assertEqual(report.overall_status, OverallStatus.PASS)

    def test_bad_context_fails(self):
        ctx = AnalysisContext(runtime_vars={'x': 1}, mfa_enabled=False)
        report = DynamicAnalyzer({'app_name': 'a'}, ctx).run_analysis()
        self.assertEqual(report.overall_status, OverallStatus.FAIL)
        self.assertLess(report.scan_result.compliance_score, 100)


if __name__ == '__main__':
    unittest.main()
