"""Exercise first-run setup with a fake Gameforge session; no network."""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, call, patch

import start_clientless as launcher
import login_current_account as login


class LauncherProfileTests(unittest.TestCase):
    def test_first_run_selects_account_and_saves_only_profile_data(self):
        auth = Mock()
        auth.authenticate.side_effect = [{'ok': False, 'errors': ['OTP_REQUIRED']}, {'ok': True}]
        auth.get_accounts_full.return_value = {
            'first': {'displayName': 'First', 'accountNumericId': 123},
            'second': {'displayName': 'Second', 'accountNumericId': 456},
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'test_profile.json'
            with patch('builtins.input', side_effect=[
                'user@example.test', '123456', '9', '2', '99', '11',
            ]), patch.object(login.getpass, 'getpass', return_value='secret-fixture'):
                profile, account = launcher.create_profile(path, auth)
            saved = json.loads(path.read_text(encoding='utf-8'))
            self.assertEqual(saved, {
                'email': 'user@example.test', 'account_id': 'second', 'display_name': 'Second',
                'numeric_id': 456,
                'server_name': 'Dandanakan', 'host': '79.110.92.131', 'auth_port': 11151,
                'channel_host': '79.110.92.131', 'login_port': 12105,
            })
            self.assertEqual(profile, saved)
            self.assertEqual(account['displayName'], 'Second')
            self.assertEqual(launcher.load_profile(path, 'Override')['character'], 'Override')
        self.assertEqual(auth.authenticate.call_args_list, [
            call('user@example.test', 'secret-fixture'),
            call('user@example.test', 'secret-fixture', '123456'),
        ])

    def test_failed_login_does_not_create_profile(self):
        auth = Mock()
        auth.authenticate.return_value = {'ok': False, 'errors': ['REJECTED']}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'test_profile.json'
            with patch('builtins.input', return_value='user@example.test'), \
                    patch.object(login.getpass, 'getpass', return_value='secret-fixture'):
                self.assertEqual(launcher.create_profile(path, auth), (None, None))
            self.assertFalse(path.exists())
        auth.get_accounts_full.assert_not_called()

    def test_created_profile_continues_and_existing_profile_is_reused(self):
        auth = Mock(email='user@example.test')
        auth.get_accounts_full.return_value = {'one': {'displayName': 'One', 'accountNumericId': 1}}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'test_profile.json'
            token = Mock(return_value='fixture-ticket')
            session_valid = Mock(return_value=True)
            world_args = []
            def capture_world_args(argv, *, token, confirm_selection, diagnostics):
                self.assertEqual(token, 'fixture-ticket')
                self.assertFalse(diagnostics)
                self.assertNotIn(token, argv)
                self.assertNotIn('--character-name', argv)
                self.assertIs(confirm_selection, launcher.confirm_character)
                world_args.append(dict(zip(argv[1::2], argv[2::2])))
                return 0
            world_main = Mock(side_effect=capture_world_args)
            modules = {
                'gf_auth': SimpleNamespace(GfAuth=Mock(return_value=auth)),
                'auto_token': SimpleNamespace(get_token=token, session_valid=session_valid),
                'world_login': SimpleNamespace(main=world_main),
            }
            cwd = Path.cwd()
            try:
                with patch.dict(sys.modules, modules), patch.object(launcher, 'ROOT', root), \
                        patch.object(login, 'authenticate_interactively', return_value=True) as sign_in, \
                        patch('builtins.input', side_effect=['user@example.test', '0', 'server.example.test', '11']):
                    for _ in range(2):
                        with patch.object(sys, 'argv', ['start_clientless.py', '--profile', str(path)]):
                            self.assertEqual(launcher.main(), 0)
                    original_profile = path.read_bytes()
                    with patch.object(sys, 'argv', ['start_clientless.py', '--profile', str(path), '--choose-server']):
                        self.assertEqual(launcher.main(), 0)
                    self.assertEqual(path.read_bytes(), original_profile)
                    sign_in.assert_called_once_with(auth, 'user@example.test')
                    token.side_effect = RuntimeError('fixture ticket failure')
                    with patch.object(sys, 'argv', ['start_clientless.py', '--profile', str(path)]), \
                            patch('builtins.print') as output:
                        self.assertEqual(launcher.main(), 1)
                    self.assertTrue(any('Oyun bileti alinamadi.' in str(item) for item in output.call_args_list))
            finally:
                os.chdir(cwd)
            self.assertEqual(world_main.call_count, 3)
            self.assertEqual(list(root.glob('*.json')), [path])
            self.assertEqual([args.args[1] for args in token.call_args_list], ['one'] * 4)
            self.assertEqual(world_args[0]['--channel-host'], 'server.example.test')
            self.assertEqual(world_args[-1]['--auth-host'], '79.110.92.131')
            self.assertEqual(world_args[-1]['--auth-port'], '11151')
            self.assertEqual(world_args[-1]['--login-port'], '12105')

    def test_character_confirmation_displays_the_server_name_and_can_cancel(self):
        with patch('builtins.input', side_effect=['', '0']), patch('builtins.print') as output:
            self.assertFalse(launcher.confirm_character('ObservedCharacter'))
        output.assert_any_call('Sunucudan gelen ilk karakter: ObservedCharacter')
        with patch('builtins.input', return_value='1'):
            self.assertTrue(launcher.confirm_character('ObservedCharacter'))


if __name__ == '__main__':
    unittest.main()
