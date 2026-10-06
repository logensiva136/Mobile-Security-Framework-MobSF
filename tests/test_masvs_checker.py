import unittest
from mobsf.DynamicAnalyzer.checks.masvs_checker import MASVSChecker
# Assuming AnalysisContext, Finding, and ScanResult are available/imported
from mobsf.DynamicAnalyzer.models import AnalysisContext, Finding, ScanResult

class TestMASVSChecker(unittest.TestCase):
    """
    Unit tests for the MASVSChecker component, ensuring rules are correctly applied.
    """

    def setUp(self):
        # Initialize the checker for each test
        # Passing a dummy path is expected by the updated __init__
        self.checker = MASVSChecker(pdf_path="OWASP_MASVS.pdf")

        # --- Mock Context Setup ---
        # We need to instantiate AnalysisContext with all relevant properties used in the checker logic.

        # Mocking a passing state
        self.mock_context_good = AnalysisContext(
            runtime_vars={"mock_data": "..." },
            credentials={"password_strength": 5},
            local_storage={"plaintext": False, "is_encrypted": True},
            mfa_enabled=True,
            session_tokens={"expiry_seconds": 7200},
            api_endpoint_details={"rate_limited": True},
            retention_policy_active=True
        )

        # Mocking a failing state
        self.mock_context_bad = AnalysisContext(
            runtime_vars={"mock_data": "..." },
            credentials={"password_strength": 2}, # Weak
            local_storage={"plaintext": True, "is_encrypted": False}, # Plaintext
            mfa_enabled=False, # Missing
            session_tokens={"expiry_seconds": 3600}, # Short
            api_endpoint_details={"rate_limited": False}, # Missing
            retention_policy_active=False # Missing
        )

        # Mocking an empty context state
        self.mock_context_empty = AnalysisContext(runtime_vars={})

    def test_full_scan_good_state(self):
        """
        Test case where all checks are expected to pass or warn appropriately.
        Checks for the expected number of findings and their status.
        """
        findings = self.checker.check(self.mock_context_good)

        # Assert that at least the critical checks are present
        self.assertGreater(len(findings), 5, "Should report multiple findings across different categories.")

        # Specific check assertions (can be made more granular if specific ID mappings are known)
        pass_count = sum(1 for f in findings if f.status == "PASS")
        self.assertGreaterEqual(pass_count, 3, "Expected at least 3 passing checks.")

    def test_full_scan_bad_state(self):
        """
        Test case where multiple critical controls are failing or warn.
        Checks for the expected failure patterns.
        """
        findings = self.checker.check(self.mock_context_bad)

        # Assert that at least the failure/warning checks are triggered
        fail_count = sum(1 for f in findings if f.status == "FAIL")
        warn_count = sum(1 for f in findings if f.status == "WARN")
        self.assertGreater(fail_count + warn_count, 4, "Expected several failures or warnings in the bad state.")

    def test_mock_context_empty(self):
        """
        Test case with minimal or empty context data.
        """
        findings = self.checker.check(self.mock_context_empty)

        # Should definitely return the CORE-001 missing variable finding
        core_finding = next((f for f in findings if f.control_id == "CORE-001"), None)
        self.assertIsNotNone(core_finding)
        self.assertEqual(core_finding.status, "FAIL")


if __name__ == '__main__':
    unittest.main()