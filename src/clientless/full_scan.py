"""Finite catalog traversal; one outstanding query and no incomplete success."""
import time
import random
from trade_benchmark import PageBenchmark
from trade_probe import category_search_body


class FullScan:
    def __init__(self, out, template, scopes, category_gap=5, scope_complete_fn=None,page_limit=None,
                 scope_result_fn=None):
        gap_range=tuple(category_gap) if isinstance(category_gap,(tuple,list)) else (category_gap,category_gap)
        if not scopes or len(gap_range)!=2 or not 0<=gap_range[0]<=gap_range[1]:
            raise ValueError('catalog and nonnegative category gap required')
        self.out=out; self.template=template; self.scopes=scopes
        self.category_gap=gap_range; self.index=0; self.done=False
        self.scope_complete_fn=scope_complete_fn
        self.page_limit=page_limit
        self.scope_result_fn=scope_result_fn
        self.started=time.monotonic(); self.wait_until=None
        self.summary={'complete':False,'scopes_total':len(scopes),'scopes_complete':0,
                      'pages':0,'items':0,'category_gap_seconds_range':list(gap_range),
                      'completed_scopes':[],'coverage':'full' if page_limit is None else 'recent_prefix'}
        self._start_page()

    def _start_page(self):
        scope=self.scopes[self.index]
        directory=self.out/('scope_%03d_%d_%d_%d'%(
            self.index,scope['job'],scope['category'],scope['sub']))
        directory.mkdir()
        self.page=PageBenchmark(directory,max_pages=5000,page_limit=self.page_limit)
        self.summary['current_scope']=dict(scope,index=self.index)

    def accept(self, result):
        if self.done or self.wait_until is not None:
            raise ValueError('unsolicited category response')
        next_body=self.page.accept(result)
        if not self.page.done:
            return next_body
        self.summary['completed_scopes'].append(dict(self.scopes[self.index],**self.page.summary))
        if self.scope_complete_fn is not None and self.page.summary.get('full_category_complete'):
            self.scope_complete_fn(self.scopes[self.index])
        if self.scope_result_fn is not None:
            self.scope_result_fn(self.scopes[self.index],self.page.out,self.page.summary)
        self.summary['scopes_complete']+=1
        self.summary['pages']+=self.page.summary['pages']
        self.summary['items']+=self.page.summary['items']
        self.summary['elapsed_seconds']=round(time.monotonic()-self.started,3)
        self.index+=1
        if self.index==len(self.scopes):
            self.done=True;self.summary['complete']=True
        else:
            self.wait_until=time.monotonic()+random.uniform(*self.category_gap)
        return None

    def poll(self):
        if self.wait_until is None or time.monotonic()<self.wait_until:
            return None
        self.wait_until=None;self._start_page()
        return category_search_body(self.template,self.scopes[self.index])

    def check_timeout(self):
        if not self.done and self.wait_until is None:
            self.page.check_timeout()
