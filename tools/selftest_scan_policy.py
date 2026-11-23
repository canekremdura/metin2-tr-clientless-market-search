"""Rare cadence persistence, successful-group accounting and account isolation."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src/clientless'))
from trade_catalog import load_scopes
from scan_policy import RareCadence,load_policy,scope_key,ledger_path


class ScanPolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.now=100000.;self.scopes=load_scopes();self.policy=load_policy()
        self.path=Path(self.tmp.name)/'cadence.json'
        self.cadence=RareCadence(self.path,self.scopes,self.policy,
            clock=lambda:self.now,uniform=lambda low,high:19)

    def finish_group(self):
        for scope in self.scopes:self.cadence.completed_scope(scope)

    def test_normal_scope_policy(self):
        regular=self.cadence.select('regular')
        self.assertEqual(len(regular),75)
        self.assertEqual(len(self.cadence.rare_keys),9)
        keys={scope_key(s) for s in regular}
        for key in ['0/1/0','0/1/1','0/1/2','0/6/1','0/12/1','0/12/2','0/12/3','0/12/4','0/12/6']:
            self.assertNotIn(key,keys)
        self.assertIn('0/1/3',keys)
        self.assertEqual(self.policy['request_gap_ms'],[50,150])

    def test_first_run_then_due_again(self):
        self.assertEqual(len(self.cadence.select()),84)
        self.finish_group()
        self.assertEqual(len(self.cadence.select()),75)
        self.assertEqual(self.cadence.state['next_due_unix'],self.now+19*3600)
        self.now+=19*3600
        self.assertEqual(len(self.cadence.select()),84)

    def test_partial_group_does_not_advance(self):
        self.finish_group();previous=self.path.read_text()
        for scope in self.scopes:
            if scope_key(scope) in self.cadence.rare_keys:
                self.cadence.completed_scope(scope);break
        self.assertEqual(previous,self.path.read_text())

    def test_restart_keeps_same_due_time(self):
        self.finish_group();previous=json.loads(self.path.read_text())
        restarted=RareCadence(self.path,self.scopes,self.policy,clock=lambda:self.now,
                             uniform=lambda *_:(_ for _ in ()).throw(AssertionError('rescheduled')))
        self.assertEqual(len(restarted.select()),75)
        self.assertEqual(restarted.state,previous)

    def test_completed_snapshot_seeds_but_partial_does_not(self):
        snapshot={'success':False,'updated_utc':'2026-11-14T00:00:00+00:00',
                  'trade_benchmark':{'complete':False,'completed_scopes':self.scopes}}
        with self.assertRaises(ValueError):self.cadence.seed_snapshot(snapshot,'test')
        snapshot['success']=True;snapshot['trade_benchmark']['complete']=True
        self.assertTrue(self.cadence.seed_snapshot(snapshot,'test'))
        previous=self.path.read_text()
        self.assertFalse(self.cadence.seed_snapshot(snapshot,'test'))
        self.assertEqual(self.path.read_text(),previous)

    def test_identity_isolation(self):
        args=(ROOT,'host',12102,'account','FixtureCharacter')
        self.assertNotEqual(ledger_path(*args),ledger_path(ROOT,'other_host',12102,'account','FixtureCharacter'))
        self.assertNotEqual(ledger_path(*args),ledger_path(ROOT,'host',12102,'other_account','FixtureCharacter'))


if __name__=='__main__':unittest.main()
