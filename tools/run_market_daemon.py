"""VPS worker: full scan every two hours, verified recent prefixes between full runs."""
import argparse
import contextlib
import json
import os
import random
import sys
import time
import datetime
import math
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
try:
    ISTANBUL=ZoneInfo("Europe/Istanbul")
except ZoneInfoNotFoundError:
    ISTANBUL=datetime.timezone(datetime.timedelta(hours=3), "Europe/Istanbul")
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src/clientless'),str(ROOT/'src/ecdh-lab')]
from scan_policy import RareCadence,ledger_path,load_policy
from trade_catalog import load_scopes
from world_login import Logger,open_session
from world_session import run_native_world


def nightly_pause(now):
    local=datetime.datetime.fromtimestamp(now,ISTANBUL)
    return local.hour==23 and local.minute>=59 or local.hour==0 and local.minute<2


def midnight_retry_at(started, finished, error):
    local=datetime.datetime.fromtimestamp(finished,ISTANBUL)
    transport=any(s in (error or '') for s in ('TimeoutError:', 'closed world connection', 'ConnectionResetError:', 'BrokenPipeError:'))
    if not transport or not (nightly_pause(started) or nightly_pause(finished) or local.hour==0 and local.minute<5):
        return None
    target=local.replace(hour=0,minute=2,second=0,microsecond=0)
    if local.hour==23:target+=datetime.timedelta(days=1)
    return max(finished+30,target.timestamp())


def choose_job(state, now):
    if nightly_pause(now) or now<state.get('retry_not_before_unix',0):return None
    if now>=state.get('next_full_unix',0):return 'full'
    if now>=state.get('next_recent_unix',0):return 'recent'
    return None


def request_gap_ms(mode, policy):
    return [350, 550] if mode == 'recent' else policy['request_gap_ms']


def configure_deadline(state, hours, now):
    if not math.isfinite(hours) or hours<0:raise ValueError('run hours must be finite and nonnegative')
    if hours==0:
        state.pop('trial_deadline_unix',None)
        return None
    return state.setdefault('trial_deadline_unix',now+hours*3600)


def validate_recent_proof(session, proof):
    if (not proof.get('verified') or proof.get('sort_offset')!=55
            or proof.get('build_sha256')!=session['build_sha256']
            or type(proof.get('sort_value')) is not int or not 0<=proof['sort_value']<=255):
        raise ValueError('current-build native recent-sort evidence is required')


def run_scan(session, state_dir, mode, proof, deadline):
    policy=load_policy();scopes=load_scopes()
    gap_ms=request_gap_ms(mode,policy)
    cadence=RareCadence(ledger_path(state_dir,session['host'],session['port'],
                       session['account'],session['character']),scopes,policy)
    if not cadence.path.exists() and session.get('cadence_state'):
        cadence.state=session['cadence_state'];cadence.save()
    scopes=cadence.select('auto' if mode=='full' else 'regular')
    body=bytearray.fromhex(session['search_body_hex'])
    if mode=='recent':
        validate_recent_proof(session,proof)
        body[proof['sort_offset']]=proof['sort_value']
    stamp=time.strftime('%Y%m%dT%H%M%SZ',time.gmtime())+'_%09d'%(time.time_ns()%1000000000)
    out=state_dir/'runs'/(stamp+'_'+mode);out.mkdir(parents=True)
    (out/'scan_plan.json').write_text(json.dumps({'mode':mode,'scopes':scopes,
        'page_limit':3 if mode=='recent' else None,'request_gap_ms':gap_ms,
        'coverage':'full' if mode=='full' else 'recent_prefix'},ensure_ascii=False,indent=2),encoding='utf-8')
    publisher=None
    if os.environ.get('CLIENTLESS_SITE_PUBLISH')=='1':
        from site_outbox import ScopeOutbox
        publisher=ScopeOutbox(state_dir,out.name,scopes,load_scopes(),mode)
    with (out/'console.log').open('w',encoding='utf-8') as console,contextlib.redirect_stdout(console):
        log=Logger(str(out/'run.log'))
        try:
            result=run_native_world(log,session['host'],session['port'],session['account'].encode('ascii'),
                bytes.fromhex(session['login_key_hex']),bytes.fromhex(session['client_key_hex']),out,
                expected_name=session['character'],stay_seconds=14400 if deadline is None else max(.1,min(14400,deadline-time.time())),
                open_session_fn=open_session,trade_search_once=True,trade_scopes=scopes,
                trade_open_body=bytes.fromhex(session['activation_body_hex']),trade_search_body=body,
                trade_request_jitter=tuple(v/1000 for v in gap_ms),
                trade_scope_complete_fn=cadence.completed_scope if mode=='full' else None,
                trade_page_limit=3 if mode=='recent' else None,stop_path=state_dir/'STOP',
                trade_pause_fn=lambda:nightly_pause(time.time()),
                trade_scope_result_fn=publisher.completed_scope if publisher else None)
        finally:log.summary();log.close()
    return out,result


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--session-file',type=Path,required=True)
    ap.add_argument('--state-dir',type=Path,required=True)
    ap.add_argument('--recent-proof',type=Path,required=True)
    ap.add_argument('--run-hours',type=float,default=0,help='0: unlimited (default); positive: bounded trial')
    args=ap.parse_args();os.umask(0o077)
    session=json.loads(args.session_file.read_text(encoding='utf-8'))
    proof=json.loads(args.recent_proof.read_text(encoding='utf-8'))
    validate_recent_proof(session,proof)
    state_dir=args.state_dir;state_dir.mkdir(parents=True,exist_ok=True)
    import fcntl
    lock=(state_dir/'worker.lock').open('a')
    fcntl.flock(lock.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
    state_path=state_dir/'worker_state.json'
    state=json.loads(state_path.read_text(encoding='utf-8')) if state_path.exists() else {}
    deadline=configure_deadline(state,args.run_hours,time.time())
    state.update(running=True,stopped_reason=None)
    def save():
        state['updated_unix']=time.time()
        temp=state_path.with_suffix('.tmp');temp.write_text(json.dumps(state,ensure_ascii=False,indent=2),encoding='utf-8');temp.replace(state_path)
    save()
    try:
        while (deadline is None or time.time()<deadline) and not (state_dir/'STOP').exists():
            mode=choose_job(state,time.time())
            if mode is None:
                time.sleep(5)
                continue
            started=time.time();state.update(current_mode=mode,current_started_unix=started);save()
            print(json.dumps({'event':'scan_started','mode':mode,'started_unix':started}),flush=True)
            out,result=run_scan(session,state_dir,mode,proof,deadline)
            record={'mode':mode,'started_unix':started,'finished_unix':time.time(),
                    'state_file':str(out/'world_state.json'),'success':result.get('success'),
                    'benchmark':{k:v for k,v in result.get('trade_benchmark',{}).items()
                                 if k not in ('completed_scopes','current_scope')},'error':result.get('error')}
            state.setdefault('runs',[]).append(record);state['runs']=state['runs'][-100:]
            print(json.dumps({'event':'scan_finished',**record},ensure_ascii=False),flush=True)
            if not result.get('success') or not result.get('trade_benchmark',{}).get('complete'):
                retry_at=midnight_retry_at(started,time.time(),result.get('error'))
                day=datetime.datetime.now(ISTANBUL).date().isoformat()
                if retry_at is not None and state.get('midnight_retry_day')!=day:
                    state.update(midnight_retry_day=day,retry_not_before_unix=retry_at,current_mode=None)
                    state['next_'+mode+'_unix']=retry_at
                    save();continue
                state['stopped_reason']='scan failed or interrupted; no automatic retry';save();return 1
            if mode=='full':state['next_full_unix']=started+2*3600
            state['next_recent_unix']=time.time()+random.uniform(5*60,15*60)
            state['current_mode']=None;save()
        state['stopped_reason']='requested stop' if (state_dir/'STOP').exists() else 'trial deadline reached'
        return 0
    finally:
        state['running']=False;save();lock.close()


if __name__=='__main__':raise SystemExit(main())
