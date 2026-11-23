"""Scheduling priority, recent evidence guard and bounded-prefix accounting."""
import sys
import tempfile
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'src/clientless'),str(ROOT/'src/ecdh-lab')]
from run_market_daemon import choose_job,validate_recent_proof,request_gap_ms,nightly_pause,midnight_retry_at,ISTANBUL,configure_deadline
import datetime
from zoneinfo import ZoneInfo
from trade_benchmark import PageBenchmark
from full_scan import FullScan


class MarketWorkerTests(unittest.TestCase):
    def test_unlimited_clears_old_expired_deadline(self):
        state={'trial_deadline_unix':1,'runs':[{'success':True}]}
        self.assertIsNone(configure_deadline(state,0,100))
        self.assertNotIn('trial_deadline_unix',state)
        self.assertEqual(len(state['runs']),1)
        self.assertEqual(configure_deadline({},2,100),7300)
        for invalid in [-1,float('inf'),float('nan')]:
            with self.assertRaises(ValueError):configure_deadline({},invalid,100)

    def test_midnight_pause_and_bounded_transport_recovery(self):
        def ts(s):return datetime.datetime.fromisoformat(s).replace(tzinfo=ISTANBUL).timestamp()
        start=ts('2026-11-15T23:58:00');failed=ts('2026-11-16T00:01:00')
        self.assertFalse(nightly_pause(start))
        self.assertTrue(nightly_pause(ts('2026-11-15T23:59:00')))
        self.assertTrue(nightly_pause(failed))
        self.assertFalse(nightly_pause(ts('2026-11-16T00:02:00')))
        self.assertIsNone(choose_job({'next_full_unix':0},failed))
        self.assertEqual(midnight_retry_at(start,failed,'TimeoutError: search page response timeout'),ts('2026-11-16T00:02:00'))
        self.assertIsNone(midnight_retry_at(start,failed,'ProtocolError: login rejected'))
        self.assertIsNone(midnight_retry_at(start,ts('2026-11-16T03:00:00'),'TimeoutError: search page response timeout'))

    def test_recent_delay_does_not_slow_full_scan(self):
        policy={'request_gap_ms':[50,150]}
        self.assertEqual(request_gap_ms('recent',policy),[350,550])
        self.assertEqual(request_gap_ms('full',policy),[50,150])

    def test_full_scan_has_priority(self):
        self.assertEqual(choose_job({'next_full_unix':100,'next_recent_unix':80},100),'full')
        self.assertEqual(choose_job({'next_full_unix':200,'next_recent_unix':80},100),'recent')
        self.assertIsNone(choose_job({'next_full_unix':200,'next_recent_unix':180},100))

    def test_unverified_or_wrong_build_sort_is_blocked(self):
        session={'build_sha256':'current'}
        for proof in [{},{'verified':True,'sort_offset':55,'sort_value':1,'build_sha256':'old'}]:
            with self.assertRaises(ValueError):validate_recent_proof(session,proof)
        validate_recent_proof(session,{'verified':True,'sort_offset':55,'sort_value':1,'build_sha256':'current'})

    def test_recent_prefix_stops_at_three_and_is_not_full_coverage(self):
        with tempfile.TemporaryDirectory() as d:
            b=PageBenchmark(Path(d),page_limit=3)
            for page in [1,2,3]:b.accept(dict(page=page,count=11,total=99,items=[]))
            self.assertTrue(b.done)
            self.assertFalse(b.summary['full_category_complete'])
            self.assertEqual(b.summary['coverage'],'recent_prefix')

    def test_prefix_does_not_complete_rare_scope(self):
        with tempfile.TemporaryDirectory() as d:
            completed=[];scope=dict(job=0,category=2,sub=0,label='test')
            scan=FullScan(Path(d),bytes.fromhex('1f380000000000')+bytes(49),[scope],
                          page_limit=1,scope_complete_fn=completed.append)
            scan.accept(dict(page=1,count=11,total=99,items=[]))
            self.assertTrue(scan.done);self.assertEqual(completed,[])


if __name__=='__main__':unittest.main()
