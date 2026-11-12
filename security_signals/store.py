"""Run state kept in R2: cursors, count series, seen sets, open signals, undelivered messages (SPEC-001 R4-R8).

Series hold counts per bucket and are assigned, never added, so pulling a bucket twice gives the same
state (AC9). No raw IP is ever kept here (R3).
"""
import json

from .model import BUCKET, DAY

VERSION = 1
# series name -> retention in buckets
RETENTION = {
    'auth_fail': 8 * DAY,   # SIG-01 7-day mean
    'ip_401': 4,            # SIG-02 one hour
    'ip_429': 4,
    'src_total': 8 * DAY,   # SIG-07 same hour on the previous 7 days
    'bypass': DAY,          # SIG-05 per day
}
SEEN_RETENTION = 30 * DAY
MAX_PENDING = 5


class State:
    def __init__(self, data):
        self.cursors = data.get('cursors', {})
        self.first = data.get('first', {})
        self.series = data.get('series', {})
        self.seen = data.get('seen', {})
        self.signals = data.get('signals', {})
        self.pending = data.get('pending', [])
        self.acks = data.get('acks', [])

    @classmethod
    def new(cls):
        return cls({})

    @classmethod
    def load(cls, text):
        """None when there is no state yet (first run, R4)."""
        if not text or not text.strip():
            return None
        data = json.loads(text)
        if data.get('version') != VERSION:
            raise ValueError(f'unknown state version {data.get("version")}')
        return cls(data)

    def dump(self):
        pending = self.pending
        if len(pending) > MAX_PENDING:
            pending = [f'Security signals: {len(pending) - MAX_PENDING + 1} older undelivered alerts were dropped.',
                       *pending[-(MAX_PENDING - 1):]]
        return json.dumps({'version': VERSION, 'cursors': self.cursors, 'first': self.first, 'series': self.series,
                           'seen': self.seen, 'signals': self.signals, 'pending': pending, 'acks': self.acks},
                          sort_keys=True, separators=(',', ':')) + '\n'

    # count series -----------------------------------------------------------------------------
    def put(self, name, key, bucket, count):
        if count:
            self.series.setdefault(name, {}).setdefault(key, {})[str(bucket)] = count
        else:
            self.series.get(name, {}).get(key, {}).pop(str(bucket), None)

    def total(self, name, key, start, end):
        """Sum of buckets start..end inclusive."""
        points = self.series.get(name, {}).get(key, {})
        return sum(v for b, v in points.items() if start <= int(b) <= end)

    def keys(self, name):
        return list(self.series.get(name, {}))

    # seen sets ---------------------------------------------------------------------------------
    def was_seen(self, name, key):
        return key in self.seen.get(name, {})

    def mark_seen(self, name, key, bucket):
        self.seen.setdefault(name, {})[key] = bucket

    # housekeeping ------------------------------------------------------------------------------
    def trim(self, now_bucket):
        for name, keep in RETENTION.items():
            cutoff = now_bucket - keep * BUCKET
            for key in list(self.series.get(name, {})):
                points = self.series[name][key]
                for b in [b for b in points if int(b) < cutoff]:
                    del points[b]
                if not points:
                    del self.series[name][key]
            if name in self.series and not self.series[name]:
                del self.series[name]
        cutoff = now_bucket - SEEN_RETENTION * BUCKET
        for name in list(self.seen):
            self.seen[name] = {k: v for k, v in self.seen[name].items() if v >= cutoff}
            if not self.seen[name]:
                del self.seen[name]
        self.acks = [a for a in self.acks if a in self.signals]
