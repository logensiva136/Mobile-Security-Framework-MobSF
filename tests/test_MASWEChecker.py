import unittest
from unittest.mock import MagicMock
from mobsf.DynamicAnalyzer.checks.MASWEChecker import MASWEChecker
# Assuming the models module is importable relative to the tests package
from mobsf.DynamicAnalyzer.models import ChecklistResult

class TestMASWEChecker(unittest.TestCase):
    """Tests for the MASWEChecker component."""

    def setUp(self):
        # Mock context data passed to the checker
        self.mock_context = {
            "components": {"root_activity_visible": True},
            "network_stack": {},
            "local_storage": {}
        }
        self.checker = MASWEChecker(self.mock_context)

    def test_successful_check(self):
        """Tests the scenario where MASWE passes."""
        # Override the mock implementation to simulate a pass state for testing
        self.checker.result = ChecklistResult("MASWE", True, "Test pass condition met.", "INFO")
        result = self.checker.get_result()

        self.assertTrue(result['passed'])
        self.assertEqual(result['name'], "MASWE")
        self.assertIn("Test pass condition met.", result['details'])

    def test_failed_check(self):
        """Tests the scenario where MASWE fails critically."""
        self.checker.result = ChecklistResult("MASWE", False, "Critical dependency missing.", "CRITICAL")
        result = self.checker.get_result()

        self.assertFalse(result['passed'])
        self.assertEqual(result['name'], "MASWE")
        self.assertIn("Critical dependency missing", result['details'])

    def test_initial_state(self):
        """Tests the default state initialization."""
        # Re-instantiate to test default state
        temp_checker = MASWEChecker(self.mock_context)
        default_result = temp_checker.get_result()
        self.assertFalse(default_result['passed'])
        self.assertEqual(default_result["severity"], "INFO")

if __name__ == '__main__':
    unittest.main()