"""Persistent rare-category cadence; failed/partial groups never advance the timer."""
import hashlib
import json
import random
import time
from pathlib import Path

DATA=Path(__file__).with_name('protocol_data')


def load_policy():
    policy=json.loads((DATA/'scan_policy.json').read_text(encoding='utf-8'))
    low,high=policy['request_gap_ms']
    first,last=policy['rare_interval_hours']
    if not 0<=low<=high<=10000 or not 0<first<=last:
        raise ValueError('invalid scan policy intervals')
    return policy


def scope_key(scope):
    return '%d/%d/%d'%(scope['job'],scope['category'],scope['sub'])


def ledger_path(root, host, port, account, character):
    identity=json.dumps([host,port,account,character],ensure_ascii=False).encode('utf-8')
    return Path(root)/'work/trade_cadence'/(hashlib.sha256(identity).hexdigest()[:24]+'.json')


class RareCadence:
    def __init__(self, path, scopes, policy, clock=time.time, uniform=random.uniform):
        self.path=Path(path);self.scopes=scopes;self.policy=policy
        self.clock=clock;self.uniform=uniform;self.completed=set()
        pairs={tuple(v) for v in policy['rare_category_subtypes']}
        self.rare_keys={scope_key(s) for s in scopes if (s['category'],s['sub']) in pairs}
        self.state=json.loads(self.path.read_text(encoding='utf-8')) if self.path.exists() else {}

    def due(self):
        return (not self.rare_keys.issubset(set(self.state.get('covered_keys',[])))
                or self.clock()>=self.state.get('next_due_unix',0))

    def select(self, mode='auto'):
        if mode not in ('auto','regular','include'):raise ValueError('invalid rare mode')
        include=mode=='include' or (mode=='auto' and self.due())
        return [s for s in self.scopes if include or scope_key(s) not in self.rare_keys]

    def save(self):
        self.path.parent.mkdir(parents=True,exist_ok=True)
        temp=self.path.with_suffix('.tmp')
        temp.write_text(json.dumps(self.state,ensure_ascii=False,indent=2),encoding='utf-8')
        temp.replace(self.path)

    def _finish(self, completed_at, keys, source):
        first,last=self.policy['rare_interval_hours']
        self.state={'version':1,'last_complete_unix':completed_at,
                    'next_due_unix':completed_at+self.uniform(first,last)*3600,
                    'covered_keys':sorted(keys),'source':source}
        self.save()

    def seed_snapshot(self, snapshot, source):
        if self.path.exists():return False
        benchmark=snapshot.get('trade_benchmark',{})
        keys={scope_key(s) for s in benchmark.get('completed_scopes',[])}
        if not snapshot.get('success') or not benchmark.get('complete') or not self.rare_keys.issubset(keys):
            raise ValueError('baseline is not a verified completed rare group')
        from datetime import datetime
        self._finish(datetime.fromisoformat(snapshot['updated_utc']).timestamp(),keys,source)
        return True

    def completed_scope(self, scope):
        key=scope_key(scope)
        if key not in self.rare_keys:return
        self.completed.add(key)
        if self.rare_keys and self.rare_keys.issubset(self.completed):
            self._finish(self.clock(),self.rare_keys,'all rare scopes completed in live scan')
            self.completed.clear()
