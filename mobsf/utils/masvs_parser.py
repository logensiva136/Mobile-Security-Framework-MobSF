# -*- coding: utf_8 -*-
"""MASVS rule catalog used by the dynamic analyzer checker."""
import json
from typing import Any, Dict, List

# Sample MASVS controls, keyed by category.
MASVS_RULES: Dict[str, List[Dict[str, str]]] = {
    'Authentication': [
        {
            'id': 'A1.1',
            'description': 'Verify username/password combination strength.',
            'check_type': 'credential_strength',
            'severity': 'High',
        },
        {
            'id': 'A1.2',
            'description': 'Implement MFA support.',
            'check_type': 'mfa',
            'severity': 'Critical',
        },
        {
            'id': 'A1.3',
            'description': 'Use secure session tokens.',
            'check_type': 'session_management',
            'severity': 'Medium',
        },
    ],
    'Data Storage': [
        {
            'id': 'A2.1',
            'description': 'Encrypt sensitive data at rest.',
            'check_type': 'encryption_at_rest',
            'severity': 'High',
        },
        {
            'id': 'A2.2',
            'description': 'Implement proper data retention policies.',
            'check_type': 'retention_policy',
            'severity': 'Medium',
        },
    ],
    'API Security': [
        {
            'id': 'A3.1',
            'description': 'Implement rate limiting.',
            'check_type': 'rate_limiting',
            'severity': 'Medium',
        },
    ],
}


class MASVSParser:
    """Provide the MASVS checklist as a structured dictionary.

    The PDF path is accepted for forward compatibility, the rules are
    currently served from the built-in catalog.
    """

    def __init__(self, pdf_path: str = None):
        self.pdf_path = pdf_path
        self._parsed_data: Dict[str, Any] = MASVS_RULES

    def get_check_items(self) -> Dict[str, list]:
        """Return categories mapped to their list of check items."""
        return self._parsed_data

    def save_to_json(self, output_path: str) -> str:
        """Save the checklist to a JSON file and return a status message."""
        try:
            with open(output_path, 'w', encoding='utf-8') as fp:
                json.dump(self.get_check_items(), fp, indent=4)
            return f'Saved MASVS checklist to {output_path}.'
        except OSError as exp:
            return f'Error saving MASVS data to JSON: {exp}'
