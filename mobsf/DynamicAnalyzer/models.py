"""Data models for the dynamic analyzer compliance checks."""
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class CheckStatus(Enum):
    SUCCESS = 'Success'
    FAILED = 'Failed'
    TO_BE_TEST = 'ToBeTest'
    NOT_APPLICABLE = 'NotApplicable'
    IN_PROGRESS = 'InProgress'


class OverallStatus(Enum):
    PASS = 'PASS'
    FAIL = 'FAIL'
    WARNING = 'WARNING'
    UNKNOWN = 'UNKNOWN'


class ChecklistResult:
    """Result of a single checklist."""

    def __init__(self, name: str, passed: bool,
                 details: str = '', severity: str = 'INFO'):
        self.name = name
        self.passed = passed
        self.details = details
        self.severity = severity  # INFO, WARNING, CRITICAL

    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'passed': self.passed,
            'details': self.details,
            'severity': self.severity,
        }


@dataclass
class AnalysisContext:
    """Data gathered by scanners, consumed by the compliance checkers."""
    runtime_vars: Dict[str, Any] = field(default_factory=dict)
    credentials: Dict[str, Any] = field(default_factory=dict)
    local_storage: Dict[str, Any] = field(default_factory=dict)
    mfa_enabled: Optional[bool] = None
    session_tokens: Dict[str, Any] = field(default_factory=dict)
    api_endpoint_details: Dict[str, Any] = field(default_factory=dict)
    retention_policy_active: bool = False


@dataclass
class Finding:
    """One evaluated MASVS control. status: PASS|FAIL|WARN|SKIP."""
    control_id: str
    summary: str
    status: str
    description: str = ''
    failure_scenario: Optional[str] = None
    masvs_id: str = ''

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    """MASVS findings plus a summary compliance score."""
    masvs_findings: List[Finding] = field(default_factory=list)

    @property
    def compliance_score(self) -> float:
        """Percent of evaluated (non-SKIP) controls that passed."""
        scored = [f for f in self.masvs_findings if f.status != 'SKIP']
        if not scored:
            return 0.0
        passed = sum(1 for f in scored if f.status == 'PASS')
        return round(100.0 * passed / len(scored), 1)

    @property
    def summary_status(self) -> OverallStatus:
        statuses = {f.status for f in self.masvs_findings}
        if 'FAIL' in statuses:
            return OverallStatus.FAIL
        if 'WARN' in statuses:
            return OverallStatus.WARNING
        if 'PASS' in statuses:
            return OverallStatus.PASS
        return OverallStatus.UNKNOWN

    def to_dict(self) -> Dict[str, Any]:
        return {
            'masvs_findings': [f.to_dict() for f in self.masvs_findings],
            'compliance_score': self.compliance_score,
            'status': self.summary_status.value,
        }


class AnalysisReport:
    """Aggregated report of all security checks."""

    def __init__(self, app_name: str):
        self.app_name = app_name
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.checklist_results: Dict[str, Any] = {}
        self.scan_result = ScanResult()
        self.overall_status: OverallStatus = OverallStatus.UNKNOWN

    def add_checklist_result(self, result: Dict[str, Any]):
        self.checklist_results[result.get('name')] = result

    def generate_summary(self) -> Dict[str, Any]:
        return {
            'app_name': self.app_name,
            'timestamp': self.timestamp,
            'status': self.overall_status.value,
            'checklist_details': self.checklist_results,
            'masvs': self.scan_result.to_dict(),
        }
