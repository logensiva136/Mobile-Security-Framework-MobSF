# -*- coding: utf_8 -*-
"""Tests for the user choice to try unsupported Android versions."""
from unittest import mock

from django.test import SimpleTestCase, TestCase

from mobsf.DynamicAnalyzer.views.android import (
    dynamic_analyzer,
    environment,
    operations,
)
from mobsf.DynamicAnalyzer.views.android.environment import (
    ANDROID_API_SUPPORTED,
    Environment,
)

HASH = 'a' * 32


def _popen(stderr=b''):
    proc = mock.Mock()
    proc.communicate.return_value = (b'', stderr)
    return mock.Mock(return_value=proc)


class SystemCheckTests(SimpleTestCase):
    """The Android API level gate in Environment.system_check."""

    def check(self, api, allow=False, stderr=b''):
        env = Environment('127.0.0.1:5555', allow_unsupported=allow)
        with mock.patch.object(env, 'get_android_sdk', return_value=str(api)):
            with mock.patch.object(environment.subprocess, 'Popen',
                                   _popen(stderr)):
                return env, env.system_check('emulator')

    def test_default_is_the_supported_limit(self):
        self.assertEqual(ANDROID_API_SUPPORTED, 30)
        self.assertFalse(Environment('x').allow_unsupported)
        self.assertEqual(Environment('x').last_error, '')

    def test_supported_levels_pass_by_default(self):
        for api in (21, 29, ANDROID_API_SUPPORTED):
            _, ok = self.check(api)
            self.assertTrue(ok, api)

    def test_newer_level_is_blocked_by_default_with_a_clear_message(self):
        env, ok = self.check(33)
        self.assertFalse(ok)
        self.assertIn('API level 33', env.last_error)
        self.assertIn('Try unsupported Android versions', env.last_error)

    def test_user_can_opt_in_to_a_newer_level(self):
        env, ok = self.check(33, allow=True)
        self.assertTrue(ok)
        self.assertEqual(env.last_error, '')

    def test_opt_in_does_not_bypass_the_writable_check(self):
        env, ok = self.check(33, allow=True, stderr=b'Read-only file system')
        self.assertFalse(ok)
        self.assertIn('not writable', env.last_error)


class MobsfyViewTests(TestCase):
    """The MobSFy request passes the user's choice on."""

    def post(self, **extra):
        data = {'identifier': '127.0.0.1:5555'}
        data.update(extra)
        with self.settings(DISABLE_AUTHENTICATION='1'):
            return self.client.post('/mobsfy/', data)

    def fake_env(self, connected=True, error=''):
        env = mock.Mock()
        env.connect_n_mount.return_value = connected
        env.mobsfy_init.return_value = 33
        env.last_error = error
        return env

    def test_default_does_not_allow_unsupported(self):
        env = self.fake_env()
        with mock.patch.object(operations, 'Environment',
                               return_value=env) as cls:
            self.post()
        self.assertFalse(cls.call_args.kwargs['allow_unsupported'])

    def test_checkbox_value_is_passed(self):
        env = self.fake_env()
        for value, expected in (('1', True), ('0', False), ('yes', False)):
            with mock.patch.object(operations, 'Environment',
                                   return_value=env) as cls:
                self.post(allow_unsupported=value)
            self.assertEqual(
                cls.call_args.kwargs['allow_unsupported'], expected, value)

    def test_failure_message_explains_the_reason(self):
        env = self.fake_env(connected=False, error='API 33 is too new')
        with mock.patch.object(operations, 'Environment', return_value=env):
            response = self.post()
        self.assertEqual(response.json()['message'], 'API 33 is too new')

    def test_failure_without_reason_keeps_the_old_message(self):
        env = self.fake_env(connected=False)
        with mock.patch.object(operations, 'Environment', return_value=env):
            response = self.post()
        self.assertEqual(response.json()['message'], 'Connection failed')


class StartAnalysisViewTests(TestCase):
    """Starting an analysis passes the choice and shows the reason."""

    def post(self, env, **extra):
        with self.settings(DISABLE_AUTHENTICATION='1'), \
                mock.patch.object(dynamic_analyzer, 'Environment',
                                  return_value=env) as cls, \
                mock.patch.object(dynamic_analyzer, 'get_device',
                                  return_value='127.0.0.1:5555'), \
                mock.patch.object(dynamic_analyzer, 'get_package_name',
                                  return_value='com.demo.app'):
            response = self.client.post(f'/android_dynamic/{HASH}', extra)
        return response, cls

    def test_choice_is_passed_and_reason_is_shown(self):
        env = mock.Mock()
        env.connect_n_mount.return_value = False
        env.last_error = 'API level 33 is above the limit'
        response, cls = self.post(env, allow_unsupported='1')
        self.assertTrue(cls.call_args.kwargs['allow_unsupported'])
        self.assertContains(
            response, 'API level 33 is above the limit', status_code=500)

    def test_default_blocks_and_falls_back_to_the_old_message(self):
        env = mock.Mock()
        env.connect_n_mount.return_value = False
        env.last_error = ''
        response, cls = self.post(env)
        self.assertFalse(cls.call_args.kwargs['allow_unsupported'])
        self.assertContains(
            response, 'Cannot Connect to 127.0.0.1:5555', status_code=500)
