"""Offline auth transaction consistency. No network or real session access."""
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import Mock,patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src/mt2gf'))
import gf_auth
import auto_token

class FlowTests(unittest.TestCase):
    def test_registry_falls_back_to_machine_32bit_view(self):
        value='12345678-1234-1234-1234-123456789abc'
        key=Mock();key.__enter__=Mock(return_value=key);key.__exit__=Mock(return_value=False)
        calls=[]
        def open_key(hive,path,reserved,access):
            calls.append((hive,access))
            if hive=='user':raise FileNotFoundError()
            return key
        registry=types.SimpleNamespace(HKEY_CURRENT_USER='user',HKEY_LOCAL_MACHINE='machine',
            KEY_READ=1,KEY_WOW64_32KEY=512,OpenKey=open_key,QueryValueEx=lambda k,n:(value,1))
        with patch.dict(sys.modules,{'winreg':registry}):
            self.assertEqual(gf_auth.GfAuth._registry_installation_id(),value)
        self.assertEqual(calls,[('user',1),('machine',513)])
    def test_one_transaction_does_not_retry_rejection(self):
        auth=gf_auth.GfAuth.__new__(gf_auth.GfAuth)
        auth._get_game_token_once=Mock(return_value=None)
        self.assertIsNone(auth.get_game_token('fixture-account',retries=5))
        auth._get_game_token_once.assert_called_once_with('fixture-account',gf_auth.METIN2_GAME_ID,allow_iovation=True)

    def test_current_context_and_session_are_shared(self):
        auth=gf_auth.GfAuth.__new__(gf_auth.GfAuth)
        auth.installation_id='fixture-install';auth.installation_source='test'
        auth.chrome_version='C-fixture';auth.token='fixture-token';auth.proxy=None
        auth._dbg=gf_auth._NullDbg();auth._third_type_magic=Mock(return_value='fixture-magic')
        auth._captured_thin_ua=Mock(side_effect=AssertionError('stale UA must not be read'))
        sessions=[]
        auth.send_iovation=lambda aid:sessions.append(auth.game_session_id) or True
        auth._make_encrypted_blackbox=Mock(return_value='fixture-box')
        response=Mock(status_code=403,text='fixture rejection')
        with patch.object(gf_auth.requests,'post',return_value=response) as post,patch.object(gf_auth.time,'sleep'):
            self.assertIsNone(auth.get_game_token('fixture-account'))
        kwargs=post.call_args.kwargs;body=kwargs['json']
        self.assertEqual(body['gsid'].rsplit('-',1)[0],sessions[0])
        self.assertEqual(kwargs['headers']['User-Agent'],'Chrome/C-fixture (fixture-magic)')
        auth._make_encrypted_blackbox.assert_called_once_with(body['gsid'],'fixture-account')
        auth._captured_thin_ua.assert_not_called()

    def test_installation_is_saved_with_session(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(gf_auth,'SESSION_FILE',str(Path(tmp)/'session.json')):
            auth=gf_auth.GfAuth.__new__(gf_auth.GfAuth)
            auth.token='fixture';auth.email='fixture@example.test';auth.installation_id='stable-fixture'
            auth._save_session()
            other=gf_auth.GfAuth.__new__(gf_auth.GfAuth)
            other._explicit_installation_id=False;other.installation_id='wrong-default'
            other._load_session()
            self.assertEqual(other.installation_id,'stable-fixture')
            self.assertEqual(other.installation_source,'saved_auth_session')

    def test_local_wait_is_not_a_default_server_requirement(self):
        auth=Mock();auth._iovation_ok=True;auth.get_game_token.return_value=None
        with patch.object(auto_token,'cached_token',return_value=None),patch.object(auto_token,'_in_cooldown') as cooldown,patch.object(auto_token,'_set_cooldown') as set_wait:
            self.assertIsNone(auto_token.get_token(auth,'fixture-account'))
        cooldown.assert_not_called();set_wait.assert_not_called()

if __name__=='__main__':unittest.main()
