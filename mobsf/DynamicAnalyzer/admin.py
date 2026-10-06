"""Orchestrates compliance checks for the dynamic analyzer."""
import logging
from typing import Any, Dict, Optional

from .checks.masvs_checker import MASVSChecker
from .models import AnalysisContext, AnalysisReport, OverallStatus

logger = logging.getLogger(__name__)


class DynamicAnalyzer:
    """Runs all compliance checks and aggregates the results."""

    def __init__(self, app_context: Dict[str, Any],
                 analysis_context: Optional[AnalysisContext] = None):
        self.app_context = app_context
        self.analysis_context = analysis_context or AnalysisContext()
        self.report = AnalysisReport(app_context.get('app_name', 'UnknownApp'))

    def run_analysis(self) -> AnalysisReport:
        logger.info('Starting compliance analysis')
        self.run_masvs()
        self.report.overall_status = self._calculate_overall_status()
        return self.report

    def run_masvs(self):
        """Run the MASVS checker and store findings on the report."""
        try:
            findings = MASVSChecker().check(self.analysis_context)
            self.report.scan_result.masvs_findings = findings
        except Exception as exp:
            logger.exception('MASVS check failed')
            self.report.add_checklist_result({
                'name': 'MASVS (Error)',
                'passed': False,
                'details': f'Failed to execute check: {exp}',
                'severity': 'CRITICAL',
            })

    def _calculate_overall_status(self) -> OverallStatus:
        if any(not r.get('passed') and r.get('severity') == 'CRITICAL'
               for r in self.report.checklist_results.values()):
            return OverallStatus.FAIL
        return self.report.scan_result.summary_status
