# -*- coding: utf_8 -*-
"""MASVS / MASTG / MASWE checklist page."""
from django.shortcuts import render
from django.views.decorators.http import require_http_methods

from mobsf.MobSF import settings
from mobsf.MobSF.utils import (
    is_md5,
    print_n_send_error_response,
)
from mobsf.MobSF.views.authentication import (
    login_required,
)
from mobsf.StaticAnalyzer.models import (
    StaticAnalyzerAndroid,
    StaticAnalyzerIOS,
)
from mobsf.StaticAnalyzer.views.android.db_interaction import (
    get_context_from_db_entry as adb)
from mobsf.StaticAnalyzer.views.common.checklist import build_checklist
from mobsf.StaticAnalyzer.views.ios.db_interaction import (
    get_context_from_db_entry as idb)


@login_required
@require_http_methods(['GET'])
def checklist_page(request, checksum, api=False):
    """Dedicated MASVS/MASTG/MASWE checklist page for a scanned app."""
    if not is_md5(checksum):
        return print_n_send_error_response(request, 'Invalid Hash', api)
    android = StaticAnalyzerAndroid.objects.filter(MD5=checksum).first()
    ios = StaticAnalyzerIOS.objects.filter(MD5=checksum).first()
    if android:
        data, platform = adb([android]), 'android'
    elif ios:
        data, platform = idb([ios]), 'ios'
    else:
        msg = 'Report not found or supported'
        if api:
            return {'not_found': msg}
        return print_n_send_error_response(request, msg, api)
    checklist = build_checklist(data, platform)
    context = {
        'checklist': checklist,
        'summary': {k: v['summary'] for k, v in checklist.items()},
        'platform': platform,
        'hash': checksum,
        'file_name': data.get('file_name', ''),
        'app_name': data.get('app_name', ''),
        'version': settings.MOBSF_VER,
        'title': 'Security Checklist',
    }
    if api:
        return context
    return render(request, 'static_analysis/checklist.html', context)
