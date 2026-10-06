# -*- coding: utf_8 -*-
"""OWASP MASVS compliance checker."""
from typing import Any, Dict, List, Optional

from mobsf.DynamicAnalyzer.models import AnalysisContext, Finding
from mobsf.utils.masvs_parser import MASVSParser


def _finding(item, status, summary, description, failure=None):
    return Finding(
        control_id=item['id'],
        summary=summary,
        status=status,
        description=description,
        failure_scenario=failure,
        masvs_id=item['severity'],
    )


class MASVSChecker:
    """Check an analysis context against MASVS controls."""

    def __init__(self, pdf_path: Optional[str] = None):
        self.masvs_rules = MASVSParser(pdf_path).get_check_items()
        self.dispatch = {
            'credential_strength': self._check_credentials,
            'mfa': self._check_mfa,
            'session_management': self._check_session,
            'encryption_at_rest': self._check_data_at_rest,
            'rate_limiting': self._check_rate_limiting,
            'retention_policy': self._check_retention,
        }

    def check(self, context: AnalysisContext) -> List[Finding]:
        """Return one finding per MASVS control."""
        if not context.runtime_vars:
            return [Finding(
                control_id='CORE-001',
                summary='AnalysisContext missing runtime variables.',
                status='FAIL',
                description='AnalysisContext missing runtime variables.',
                failure_scenario='Context data is empty or malformed.',
                masvs_id='CORE',
            )]
        findings = []
        for checks in self.masvs_rules.values():
            for item in checks:
                findings.append(self._run_single_check(context, item))
        return findings

    def _run_single_check(
            self, context: AnalysisContext, item: Dict[str, Any]) -> Finding:
        """Dispatch a control to its check method."""
        check_type = item.get('check_type')
        method = self.dispatch.get(check_type)
        if method:
            return method(context, item)
        return _finding(
            item,
            'SKIP',
            f'Unsupported check type: {check_type}',
            item.get('description', 'No description provided'),
            f'Check type {check_type} is not implemented.')

    def _check_credentials(self, context, item):
        if not context.credentials:
            return _finding(
                item, 'FAIL', 'Authentication context missing.',
                'The analysis context does not provide credential details.',
                'Cannot assess password strength.')
        strength = context.credentials.get('password_strength', 0)
        if strength < 3:
            return _finding(
                item, 'WARN', 'Weak password detected.',
                f'Detected password strength score: {strength}',
                'Password strength is below the minimum threshold.')
        return _finding(
            item, 'PASS', 'Password strength compliant.',
            'Password strength meets the required minimum.')

    def _check_mfa(self, context, item):
        if context.mfa_enabled is None:
            return _finding(
                item, 'WARN', 'MFA status unknown.',
                'MFA status needs to be captured during scanning.',
                'MFA status is not available in context.')
        if context.mfa_enabled:
            return _finding(
                item, 'PASS', 'MFA is implemented.',
                'Multi-Factor Authentication is integrated.')
        return _finding(
            item, 'FAIL', 'MFA is missing.',
            'Critical control for account security is missing.',
            'Multi-Factor Authentication is not implemented.')

    def _check_session(self, context, item):
        expiry = context.session_tokens.get('expiry_seconds', 0)
        if context.session_tokens and expiry < 3600:
            return _finding(
                item, 'WARN', 'Short-lived session tokens are detected.',
                'Session tokens expire quickly or are not well managed.',
                'Session tokens expire too quickly.')
        return _finding(
            item, 'PASS', 'Session management compliant.',
            'Session tokens are handled with an appropriate TTL.')

    def _check_data_at_rest(self, context, item):
        if not context.local_storage.get('is_encrypted'):
            return _finding(
                item, 'FAIL', 'Encryption at rest missing.',
                'Encrypt all local data stores.',
                'Sensitive data is stored unencrypted.')
        return _finding(
            item, 'PASS', 'Data at rest is encrypted.',
            'Encryption for local data stores is detected.')

    def _check_rate_limiting(self, context, item):
        if context.api_endpoint_details.get('rate_limited', False):
            return _finding(
                item, 'PASS', 'Rate limiting is enforced on API endpoints.',
                'Rate limiting mitigates brute force and abuse.')
        return _finding(
            item, 'FAIL', 'Rate limiting is missing.',
            'Implement rate limiting to protect APIs from abuse.',
            'No rate limiting detected on key endpoints.')

    def _check_retention(self, context, item):
        if context.retention_policy_active:
            return _finding(
                item, 'PASS', 'Data retention policy is active.',
                'Old data is purged or archived automatically.')
        return _finding(
            item, 'WARN', 'Data retention policy is missing.',
            'Purge or archive data after its useful life.',
            'No automated data lifecycle policy found.')
