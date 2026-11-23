"""Sequential, bounded pagination of one recorded legitimate search."""
import json
import math
import struct
import time
import datetime


class PageBenchmark:
    def __init__(self, out, timeout=20, max_pages=500, page_limit=None):
        if page_limit is not None and (type(page_limit) is not int or page_limit<1):
            raise ValueError('invalid page limit')
        self.out = out
        self.timeout = timeout
        self.max_pages = max_pages
        self.page_limit = page_limit
        self.started = self.sent_at = time.monotonic()
        self.expected = 1
        self.initial_total = None
        self.done = False
        self.summary = {'complete': False, 'pages': 0, 'items': 0,
                        'total_changed': False, 'intentional_gap_seconds': 0}

    def accept(self, result):
        if self.done or result['page'] != self.expected:
            raise ValueError('unexpected search result page')
        total = result['total']
        if self.initial_total is None:
            self.initial_total = total
        self.summary['total_changed'] |= total != self.initial_total
        pages = max(1, math.ceil(total / 11))
        if pages > self.max_pages or result['count'] != min(11, max(0, total - (self.expected-1)*11)):
            raise ValueError('page count or item count outside verified limits')
        now = time.monotonic()
        row = dict(result, response_seconds=round(now-self.sent_at, 6),
                   elapsed_seconds=round(now-self.started, 6),
                   observed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
        with (self.out/'trade_pages.jsonl').open('a', encoding='utf-8') as f:
            f.write(json.dumps(row, ensure_ascii=False)+'\n')
        self.summary.update(pages=self.expected, items=self.summary['items']+result['count'],
                            initial_total=self.initial_total, final_total=total,
                            elapsed_seconds=round(now-self.started, 6))
        if self.expected >= pages or (self.page_limit is not None and self.expected>=self.page_limit):
            self.done = True
            self.summary['complete'] = True
            self.summary['full_category_complete'] = self.expected>=pages
            self.summary['coverage'] = 'full' if self.page_limit is None else 'recent_prefix'
            return None
        self.expected += 1
        self.sent_at = now
        return struct.pack('<BHII', 0x1f, 11, 2, self.expected)

    def check_timeout(self):
        if not self.done and time.monotonic()-self.sent_at > self.timeout:
            raise TimeoutError('search page response timeout')
