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
    47a493f, 8930831). A sequence per anchor, kept in the state, numbers every lifetime of one id: inside one
    run and across runs whose cursor did not move (a failed source), so no two lifetimes share a key
    (review on a05b213).
    """
    if state.audit_anchor is None:
        return bucket
    seq = state.audit_seq.setdefault(state.audit_anchor, {})
    n = seq[sid] = seq.get(sid, 0) + 1
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
        if s.get('cause') == 'quiet':  # a silence merged into a failed-pull SIG-07 still needs rows to end
            known['cause'] = 'quiet'


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
            hours = rules.quiet_buckets(source) // 4
            silent = rules.sig('SIG-07', source, SIG07_SEVERITY, f'{source} ไม่มีข้อมูลเกิน {hours} ชม.')
            silent['cause'] = 'quiet'
            active.append(silent)
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
        # A silence ends only when rows came back in a complete hour: "not quiet" alone can also mean a
        # cut bucket inside the longer quiet window (fw 6 h), which proves nothing. A failed pull ends
        # with any complete good hour, rows or not.
        rows_back = state.total('src_total', source, bucket - 3 * BUCKET, bucket) > 0
        open_sig = state.signals.get(sig07)
        # Fail closed: only a SIG-07 known to come from a failed pull ends without rows (older ones carry no cause).
        needs_rows = bool(open_sig) and open_sig.get('cause') != 'failed'
        if not quiet and window_complete and open_sig and (rows_back or not needs_rows):
            _resolve(state, sig07, resolved)
        rules.after(state, source, bucket, rows)
        state.cursors[source] = bucket
    return opened, resolved


def source_failed(state, source, bucket, error_kind):
    """The pull failed: keep the source's signals and cursor (R5), open SIG-07 once."""
    opened = []
    failed = rules.sig('SIG-07', source, SIG07_SEVERITY, f'{source} ดึงข้อมูลไม่สำเร็จ ({error_kind})')
    failed['cause'] = 'failed'
    _open(state, failed, bucket, opened)
    return opened
