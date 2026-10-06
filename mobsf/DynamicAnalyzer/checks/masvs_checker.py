from typing import Any, Dict, List
# Assuming AnalysisContext and Finding are defined/imported from a shared utility module
from mobsf.DynamicAnalyzer.models import AnalysisContext, Finding
# Import the newly created parser utility
from mobsf.utils.masvs_parser import MASVSParser

class MASVSChecker:
    """
    Implements the OWASP Mobile Application Security Verification Standard (MASVS) checklist.
    This module encapsulates all logic related to checking the analyzed state against MASVS controls.
    """
    def __init__(self, pdf_path: str = None):
        """
        Initializes the checker with optional PDF path to load rules.
        :param pdf_path: Optional absolute path to the OWASP MASVS PDF.
        """
        self.parser = MASVSParser(pdf_path)
        self.masvs_rules = self.parser.get_check_items()

    def check(self, context: AnalysisContext) -> List[Finding]:
        """
        Performs the full MASVS compliance check against the provided analysis context.

        :param context: The aggregated context object containing all runtime data.
        :return: A list of Finding objects, one for each checked control, detailing status and evidence.
        """

        if not context.runtime_vars:
            return [Finding(control_id="CORE-001", summary="AnalysisContext missing runtime variables.", failure_scenario="Context data is empty or malformed.", description="AnalysisContext missing runtime variables.", masvs_id="CORE", status="FAIL")]

        all_findings = []

        # Iterate over the structured rules provided by the parser
        for category, checks in self.masvs_rules.items():
            for check_item in checks:
                # We pass the check_item metadata to the specific check method

                # Generic dispatcher: In a real system, we'd map 'check_type' to a method.
                # For now, we execute a dispatcher logic based on the description or type.

                finding = self._run_single_check(context, check_item)
                if finding:
                    all_findings.append(finding)

        return all_findings

    def _run_single_check(self, context: AnalysisContext, check_item: Dict[str, Any]) -> Finding:
        """
        Internal dispatcher to run a single check based on its type.
        """
        check_type = check_item.get('check_type')
        check_id = check_item.get('id')

        if check_type == "credential_strength":
            # Delegate to specialized method
            return self._check_authentication_strength(context, check_item)
        elif check_type == "mfa":
            return self._check_mfa(context, check_item)
        elif check_type == "session_management":
            return self._check_session(context, check_item)
        elif check_type == "encryption_at_rest":
            return self._check_data_at_rest(context, check_item)
        elif check_type == "rate_limiting":
            return self._check_rate_limiting(context, check_item)
        elif check_type == "retention_policy":
            return self._check_retention(context, check_item)
        else:
            # Fallback finding
            return Finding(
                control_id=f"{check_id} (Unknown)",
                summary=f"Unsupported check type: {check_type}",
                failure_scenario=f"Check type '{check_type}' is not implemented.",
                description=f"Check '{check_id}' description: {check_item.get('description', 'No description provided')}",
                masvs_id=check_item.get('severity', 'UNKNOWN'),
                status="SKIP"
            )


    def _check_authentication_strength(self, context: AnalysisContext, check_item: Dict[str, Any]) -> Finding:
        """
        Implements the logic for checking password strength based on the context.
        """
        # Check logic based on context.credentials available in AnalysisContext
        if not context.credentials:
             return Finding(
                control_id=check_item['id'],
                summary="Authentication context missing.",
                failure_scenario="Cannot assess password strength.",
                description="The analysis context does not provide credential details.",
                masvs_id=check_item['severity'],
                status="FAIL"
            )

        # Mocking the actual strength check against the required MASVS standard
        strength = context.credentials.get('password_strength', 0)

        if strength < 3:
            return Finding(
                control_id=check_item['id'],
                summary="Weak password detected.",
                failure_scenario="Password strength is below minimum required threshold.",
                description=f"Detected password strength score: {strength}",
                masvs_id=check_item['severity'],
                status="WARN"
            )

        return Finding(
            control_id=check_item['id'],
            summary="Password strength compliant.",
            failure_scenario=None,
            description="Password strength meets the required minimum.",
            masvs_id=check_item['severity'],
            status="PASS"
        )

    def _check_mfa(self, context: AnalysisContext, check_item: Dict[str, Any]) -> Finding:
        """
        Checks for the presence and implementation of MFA.
        """
        # Placeholder: Assume MFA status is available in context.
        if context.mfa_enabled is None:
            return Finding(
                control_id=check_item['id'],
                summary="MFA status unknown.",
                failure_scenario="MFA status is not available in context.",
                description="MFA status needs to be explicitly captured during scanning.",
                masvs_id=check_item['severity'],
                status="WARN"
            )

        if context.mfa_enabled:
            return Finding(
                control_id=check_item['id'],
                summary="MFA is implemented.",
                failure_scenario=None,
                description="Multi-Factor Authentication is successfully integrated.",
                masvs_id=check_item['severity'],
                status="PASS"
            )
        else:
            return Finding(
                control_id=check_item['id'],
                summary="MFA is missing.",
                failure_scenario="Multi-Factor Authentication is not implemented.",
                description="Critical control for account security is missing.",
                masvs_id=check_item['severity'],
                status="FAIL"
            )

    def _check_session(self, context: AnalysisContext, check_item: Dict[str, Any]) -> Finding:
        """
        Checks for secure session management practices.
        """
        # Placeholder logic based on context.session_tokens
        if context.session_tokens and context.session_tokens.get('expiry_seconds', 0) < 3600:
            return Finding(
                control_id=check_item['id'],
                summary="Short-lived session tokens are detected.",
                failure_scenario="Session tokens expire too quickly or are not properly managed.",
                description="Potential session hijacking risk due to short TTL.",
                masvs_id=check_item['severity'],
                status="WARN"
            )

        return Finding(
            control_id=check_item['id'],
            summary="Session management compliant.",
            failure_scenario=None,
            description="Session tokens appear to be handled securely with appropriate TTL.",
            masvs_id=check_item['severity'],
            status="PASS"
        )

    def _check_data_at_rest(self, context: AnalysisContext, check_item: Dict[str, Any]) -> Finding:
        """
        Checks for encryption of sensitive data at rest.
        """
        # Check logic based on context.local_storage
        if not context.local_storage.get('is_encrypted'):
            return Finding(
                control_id=check_item['id'],
                summary="Encryption at rest missing.",
                failure_scenario="Sensitive data is stored unencrypted.",
                description="Recommend implementing encryption for all local data stores.",
                masvs_id=check_item['severity'],
                status="FAIL"
            )

        return Finding(
            control_id=check_item['id'],
            summary="Data at rest is encrypted.",
            failure_scenario=None,
            description="Encryption mechanism for local data stores is detected.",
            masvs_id=check_item['severity'],
            status="PASS"
        )

    def _check_rate_limiting(self, context: AnalysisContext, check_item: Dict[str, Any]) -> Finding:
        """
        Checks if rate limiting is implemented on critical APIs.
        """
        # Placeholder logic based on context.api_endpoint_details
        endpoint_details = context.api_endpoint_details
        if endpoint_details.get('rate_limited', False):
             return Finding(
                control_id=check_item['id'],
                summary="Rate limiting is enforced on API endpoints.",
                failure_scenario=None,
                description="Rate limiting controls are active, mitigating brute force and abuse.",
                masvs_id=check_item['severity'],
                status="PASS"
            )
        else:
            return Finding(
                control_id=check_item['id'],
                summary="Rate limiting is missing.",
                failure_scenario="Rate limiting mechanism is not detected on key endpoints.",
                description="Implement rate limiting to protect APIs from overuse and brute-force attacks.",
                masvs_id=check_item['severity'],
                status="FAIL"
            )

    def _check_retention(self, context: AnalysisContext, check_item: Dict[str, Any]) -> Finding:
        """
        Checks if proper data retention policies are in place.
        """
        # Placeholder logic
        if context.retention_policy_active:
            return Finding(
                control_id=check_item['id'],
                summary="Data retention policy is active.",
                failure_scenario=None,
                description="Policy to automatically purge or archive old data is implemented.",
                masvs_id=check_item['severity'],
                status="PASS"
            )
        else:
            return Finding(
                control_id=check_item['id'],
                summary="Data retention policy is missing.",
                failure_scenario="No automated policy for data lifecycle management found.",
                description="Implement a process to purge or archive data after its useful life.",
                masvs_id=check_item['severity'],
                status="WARN"
            )
