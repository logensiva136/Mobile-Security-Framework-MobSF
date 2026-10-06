# -*- coding: utf_8 -*-
"""Refresh the OWASP MAS checklists from mas.owasp.org."""
from django.core.management.base import BaseCommand, CommandError

from mobsf.StaticAnalyzer.views.common.mas_standards import (
    standards_info,
    update_standards,
)


class Command(BaseCommand):
    """Download MASVS, MASWE and MASTG data and store it under MOBSF_HOME."""

    help = 'Update OWASP MASVS/MASWE/MASTG checklists'  # noqa: A003

    def handle(self, *args, **kwargs):
        """Run the update and report what was retrieved."""
        before = standards_info()
        self.stdout.write(
            f'Current data retrieved at {before["retrieved_at"]}')
        try:
            meta = update_standards()
        except Exception as exp:
            raise CommandError(f'Update failed: {exp}') from exp
        self.stdout.write(self.style.SUCCESS(
            f'Updated at {meta["retrieved_at"]}: {meta["counts"]}'))
