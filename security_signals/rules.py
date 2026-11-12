"""Rules SIG-01..SIG-07 (SPEC-001 "Rules (v1)").

Each source has one ingest step (record counts for this bucket), its rules (active signals in this
bucket) and an after step (update seen sets, so a "new" thing is compared with what came before).
"""
from collections import Counter

from .model import BUCKET, DAY

BLOCK_ACTIONS = {'block', 'challenge', 'managed_challenge', 'jschallenge', 'connectionclose'}
KNOWN_CLIENT_REASONS = {'invalid_grant', 'invalid_scope', 'unauthorized_client'}

SIG01_MIN, SIG01_FACTOR, SIG01_WINDOW = 50, 5, 7 * DAY
SIG02_MIN = 30
SIG03_MIN = 200
SIG06_MIN = 20

# rule -> (source, hold buckets after the last active bucket before it resolves)
RULES = {
    'SIG-01': ('gw', 4),
    'SIG-02': ('http', 4),
    'SIG-03': ('fw', 4),
    'SIG-04': ('access', 7 * DAY),
    'SIG-05': ('bypass', DAY),
    'SIG-06': ('idp', 4),
}
SOURCES = ('fw', 'http', 'access', 'gw', 'idp', 'bypass')


def sig(rule, subject, severity, detail, ip=None):
    out = {'id': f'{rule}:{subject}', 'rule': rule, 'subject': subject, 'severity': severity, 'detail': detail}
    if ip:
        out['ip'] = ip
    return out


def _short(h):
    return h[:12]


# -- ingest ---------------------------------------------------------------------------------------
def ingest(state, source, bucket, rows):
    state.put('src_total', source, bucket, sum(r.get('count', 1) for r in rows))
    if source == 'gw':
        fails = Counter()
        for r in rows:
            if r['status'] in (401, 403):
                fails[r['system']] += r['count']
        for system in set(state.keys('auth_fail')) | set(fails):
            state.put('auth_fail', system, bucket, fails.get(system, 0))
    elif source == 'http':
        for status in (401, 429):
            counts = Counter()
            for r in rows:
                if r['status'] == status:
                    counts[r['ip_hash']] += r['count']
            for key in set(state.keys(f'ip_{status}')) | set(counts):
                state.put(f'ip_{status}', key, bucket, counts.get(key, 0))
    elif source == 'bypass':
        counts = Counter()
        for r in rows:
            counts[r['system']] += r['count']
        for system in set(state.keys('bypass')) | set(counts):
            state.put('bypass', system, bucket, counts.get(system, 0))


# -- rules ----------------------------------------------------------------------------------------
def evaluate(state, source, bucket, rows):
    return {'gw': _sig01, 'http': _sig02, 'fw': _sig03, 'access': _sig04, 'bypass': _sig05,
            'idp': _sig06}[source](state, bucket, rows)


def _sig01(state, bucket, rows):
    out = []
    first = state.first.get('gw', bucket)
    start = max(first, bucket - SIG01_WINDOW * BUCKET)
    n_prev = (bucket - start) // BUCKET
    for system in state.keys('auth_fail'):
        now = state.total('auth_fail', system, bucket, bucket)
        if now < SIG01_MIN:
            continue
        mean = state.total('auth_fail', system, start, bucket - BUCKET) / n_prev if n_prev else 0
        if now >= SIG01_FACTOR * mean:
            out.append(sig('SIG-01', system, 'high',
                           f'{now}× 401/403 in 15 min on {system} (7-day mean {mean:.1f})'))
    return out


def _sig02(state, bucket, rows):
    ips = {r['ip_hash']: r for r in rows}
    out = []
    for status in (401, 429):
        for key in state.keys(f'ip_{status}'):
            n = state.total(f'ip_{status}', key, bucket - 3 * BUCKET, bucket)
            if n >= SIG02_MIN:
                row = ips.get(key, {})
                country = row.get('country') or '?'
                out.append(sig('SIG-02', _short(key), 'high', f'{n}× {status} in 1 h on the gateway ({country})',
                               ip=row.get('ip')))
    seen, unique = set(), []
    for s in out:  # 401 and 429 from one address are one signal
        if s['id'] not in seen:
            seen.add(s['id'])
            unique.append(s)
    return unique


def _blocks(rows):
    return [r for r in rows if str(r.get('action', '')).lower() in BLOCK_ACTIONS]


def _sig03(state, bucket, rows):
    blocks = _blocks(rows)
    out = []
    total = sum(r['count'] for r in blocks)
    if total >= SIG03_MIN:
        paths = Counter()
        for r in blocks:
            paths[r['path_prefix']] += r['count']
        top = ', '.join(p for p, _ in paths.most_common(3))
        out.append(sig('SIG-03', 'zone', 'medium', f'{total} blocks in 15 min, top paths {top}'))
    hosts = Counter()
    for r in blocks:
        hosts[r['host']] += r['count']
    for host, n in sorted(hosts.items()):
        if not state.was_seen('fw_host', host, bucket):
            out.append(sig('SIG-03', host, 'medium', f'first blocks on {host} in 30 days ({n} in 15 min)'))
    return out


def _sig04(state, bucket, rows):
    out = []
    for r in rows:
        if not r['success']:
            continue
        if not state.was_seen('access_country', r['country'], bucket):
            out.append(sig('SIG-04', f'country:{r["country"]}', 'high',
                           f'Access login from a new country {r["country"]} (app {r["app"]})', ip=r.get('ip')))
        if r['device_hash'] and not state.was_seen('access_device', r['device_hash'], bucket):
            out.append(sig('SIG-04', f'device:{r["device_hash"]}', 'high',
                           f'Access login from a new device ({r["country"]}, app {r["app"]})', ip=r.get('ip')))
    return out


def _sig05(state, bucket, rows):
    modes = {r['system']: r['mode'] for r in rows}
    out = []
    for system in state.keys('bypass'):
        day = state.total('bypass', system, bucket - (DAY - 1) * BUCKET, bucket)
        now = state.total('bypass', system, bucket, bucket)
        mode = modes.get(system, 'report')
        if mode == 'enforce' and now > 0:
            out.append(sig('SIG-05', system, 'high', f'{now} direct calls to {system} (enforce) in 15 min'))
        elif mode != 'enforce' and day > 0:
            out.append(sig('SIG-05', system, 'medium', f'{day} direct calls to {system} (report) in 24 h'))
    return out


def _sig06(state, bucket, rows):
    out = []
    total = sum(r['count'] for r in rows)
    if total >= SIG06_MIN:
        reasons = Counter()
        for r in rows:
            reasons[r['reason']] += r['count']
        top = ', '.join(f'{k} {v}' for k, v in reasons.most_common(3))
        out.append(sig('SIG-06', 'identity', 'high', f'{total} failed token requests in 15 min ({top})'))
    for r in rows:
        if r['reason'] in KNOWN_CLIENT_REASONS and not state.was_seen('idp_client', r['client_hash'], bucket):
            out.append(sig('SIG-06', f'client:{_short(r["client_hash"])}', 'high',
                           f'a client not seen in 30 days is failing token requests ({r["reason"]})'))
    return out


# -- after ----------------------------------------------------------------------------------------
def after(state, source, bucket, rows):
    if source == 'fw':
        for r in _blocks(rows):
            state.mark_seen('fw_host', r['host'], bucket)
    elif source == 'access':
        for r in rows:
            if r['success']:
                state.mark_seen('access_country', r['country'], bucket)
                if r['device_hash']:
                    state.mark_seen('access_device', r['device_hash'], bucket)
    elif source == 'idp':
        for r in rows:
            if r['reason'] in KNOWN_CLIENT_REASONS:
                state.mark_seen('idp_client', r['client_hash'], bucket)


# -- SIG-07 ---------------------------------------------------------------------------------------
def gone_quiet(state, source, bucket):
    """No rows for a complete hour where the same hour on any of the previous 7 days had some."""
    if state.total('partial', source, bucket - 3 * BUCKET, bucket) > 0:  # an empty cut bucket proves nothing
        return False
    if state.total('src_total', source, bucket - 3 * BUCKET, bucket) > 0:
        return False
    for d in range(1, 8):
        shift = d * DAY * BUCKET
        if state.total('src_total', source, bucket - 3 * BUCKET - shift, bucket - shift) > 0:
            return True
    return False
