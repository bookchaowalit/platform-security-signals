"""Open/resolve bookkeeping per source (SPEC-001 R4, R5, R6).

Every rule reads exactly one source, so each source runs on its own cursor: a failed source leaves its
signals and cursor untouched while the others carry on.
"""
from . import rules
from .model import BUCKET

SIG07_SEVERITY = 'medium'


def _rules_of(source):
    return [r for r, (src, _) in rules.RULES.items() if src == source]


def _hold(rule):
    return rules.RULES[rule][1] if rule in rules.RULES else 1


def _audit_at(state, sid, bucket):
    """The audit identity of a new signal lifetime (R11).

    Inside a run the anchor is the source's stored cursor, which a replay of the same state repeats exactly,
    even when the 24 h catch-up window has moved and the signal would open in another bucket (reviews on
    47a493f, 8930831). A per-run sequence keeps two lifetimes of one id in a single run apart.
    """
    if state.audit_anchor is None:
        return bucket
    n = state.audit_seq[sid] = state.audit_seq.get(sid, 0) + 1
    return f'{state.audit_anchor}.{n}'


def _open(state, s, bucket, opened):
    known = state.signals.get(s['id'])
    if known is None:
        at = _audit_at(state, s['id'], bucket)
        state.signals[s['id']] = {k: v for k, v in s.items() if k != 'ip'} | {'opened': bucket, 'last_active': bucket,
                                                                              'audit_at': at}
        state.audit.append({'change': 'opened', 'id': s['id'], 'at': at})  # R11
        opened.append(s)
    else:
        known['last_active'] = bucket
        if s['severity'] != known['severity']:
            known['severity'] = s['severity']


def _resolve(state, sid, resolved):
    s = state.signals.pop(sid)
    state.audit.append({'change': 'resolved', 'id': sid, 'at': s.get('audit_at', s['opened'])})  # R11: this lifetime
    if sid in state.acks:
        state.acks.remove(sid)
    resolved.append({k: v for k, v in s.items() if k not in ('opened', 'last_active', 'audit_at')} | {'id': sid})


def process_source(state, source, bucket_rows, baseline=False, partial=()):
    """bucket_rows: {bucket start: [normalized rows]} for every bucket in the pulled range, empty ones included.

    partial: buckets whose rows are a lower bound (a cut page). Signals may open there but nothing
    resolves and SIG-07 "quiet" is not judged, because missing rows are not evidence of calm (R5).
    Returns (opened, resolved): opened signals may carry the raw `ip` for the message only.
    """
    opened, resolved = [], []
    mine = set(_rules_of(source))
    for bucket in sorted(bucket_rows):
        rows = bucket_rows[bucket]
        state.first.setdefault(source, bucket)
        rules.ingest(state, source, bucket, rows)
        active = [] if baseline else rules.evaluate(state, source, bucket, rows)
        cut = bucket in partial
        state.put('partial', source, bucket, 1 if cut else 0)  # kept across runs for the 1-hour window
        quiet = not baseline and not cut and rules.gone_quiet(state, source, bucket)
        if quiet:
            active.append(rules.sig('SIG-07', source, SIG07_SEVERITY, f'{source} has had no rows for 1 h'))
        for s in active:
            _open(state, s, bucket, opened)
        for sid, s in list(state.signals.items()):
            if s['rule'] not in mine:
                continue
            if cut:  # unknown is not calm: the hold restarts after the last cut bucket
                s['last_active'] = bucket
            elif sid in state.acks or bucket - s['last_active'] >= _hold(s['rule']) * BUCKET:
                _resolve(state, sid, resolved)
        sig07 = f'SIG-07:{source}'
        window_complete = state.total('partial', source, bucket - 3 * BUCKET, bucket) == 0
        if not quiet and window_complete and sig07 in state.signals:
            _resolve(state, sig07, resolved)  # a complete good hour ends it; a cut one proves nothing
        rules.after(state, source, bucket, rows)
        state.cursors[source] = bucket
    return opened, resolved


def source_failed(state, source, bucket, error_kind):
    """The pull failed: keep the source's signals and cursor (R5), open SIG-07 once."""
    opened = []
    _open(state, rules.sig('SIG-07', source, SIG07_SEVERITY, f'{source} pull failed ({error_kind})'), bucket, opened)
    return opened
