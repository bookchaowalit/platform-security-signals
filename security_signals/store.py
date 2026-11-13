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
    'partial': 4,           # cut buckets of the last hour, so SIG-07 "quiet" never judges an incomplete window
}
SEEN_RETENTION = 30 * DAY
MAX_PENDING = 5
# Audit events kept for the next run (R8, R11). Past this the oldest go, but never silently: a marker
# `SIG-07:audit-dropped-<running total>` takes their place at the front and is posted first.
MAX_AUDIT = 2000


class State:
    def __init__(self, data):
        self.cursors = data.get('cursors', {})
        self.first = data.get('first', {})
        self.series = data.get('series', {})
        self.seen = data.get('seen', {})
        self.signals = data.get('signals', {})
        self.pending = data.get('pending', [])
        self.acks = data.get('acks', [])
        self.audit = data.get('audit', [])  # [{change, id, at}] not yet in security-api
        self.audit_dropped = data.get('audit_dropped', 0)  # running total of events lost to MAX_AUDIT

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

    def _bound_audit(self):
        if len(self.audit) <= MAX_AUDIT:
            return
        markers = [e for e in self.audit if e['change'] == 'dropped']
        real = [e for e in self.audit if e['change'] != 'dropped']
        keep = real[-(MAX_AUDIT - 1):]
        self.audit_dropped += len(real) - len(keep)
        # an older marker is covered by the new running total, so it is replaced rather than kept
        self.audit = [{'change': 'dropped', 'id': f'SIG-07:audit-dropped-{self.audit_dropped}',
                       'at': self.audit_dropped}, *keep] if markers or len(real) > len(keep) else keep

    def dump(self):
        self._bound_audit()
        pending = self.pending
        if len(pending) > MAX_PENDING:
            pending = [f'Security signals: {len(pending) - MAX_PENDING + 1} older undelivered alerts were dropped.',
                       *pending[-(MAX_PENDING - 1):]]
        return json.dumps({'version': VERSION, 'cursors': self.cursors, 'first': self.first, 'series': self.series,
                           'seen': self.seen, 'signals': self.signals, 'pending': pending, 'acks': self.acks,
                           'audit': self.audit, 'audit_dropped': self.audit_dropped},
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
    def was_seen(self, name, key, bucket):
        """Seen within the 30 days before `bucket`, not just still in the set (trim runs at the end)."""
        last = self.seen.get(name, {}).get(key)
        return last is not None and last >= bucket - SEEN_RETENTION * BUCKET

    def mark_seen(self, name, key, bucket):
        self.seen.setdefault(name, {})[key] = bucket

    # housekeeping ------------------------------------------------------------------------------
    def _trim_partial(self, now_bucket, keep):
        series = self.series.get('partial', {})
        for source in list(series):
            cutoff = min(now_bucket, self.cursors.get(source, now_bucket)) - keep * BUCKET
            series[source] = {b: v for b, v in series[source].items() if int(b) >= cutoff}
            if not series[source]:
                del series[source]
        if 'partial' in self.series and not self.series['partial']:
            del self.series['partial']

    def trim(self, now_bucket):
        for name, keep in RETENTION.items():
            cutoff = now_bucket - keep * BUCKET
            if name == 'partial':  # per source: a lagging cursor (failed pulls) still needs its markers
                self._trim_partial(now_bucket, keep)
                continue
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
