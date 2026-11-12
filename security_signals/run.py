"""One run: pull new buckets per source, evaluate, alert, write state and bronze (SPEC-001 R4-R8, R10)."""
import argparse
import json
import os
import sys
import time
import urllib.request
from pathlib import Path

from .engine import process_source, source_failed
from .model import BUCKET, DAY, SelfIPs, SelfTraffic, drop_self, iso
from .report import message, public_summary
from .rules import SOURCES
from .sources import Cloudflare, ProviderError, Railway, github_actions_ranges
from .store import State

OK, SOURCE_FAILED, NOTIFY_FAILED, CONFIG_FAILED = 0, 2, 3, 4
LAG = 600  # analytics and log indexing lag; only buckets that ended 10 min ago are pulled
CATCH_UP = DAY  # R6: at most 24 h back after an outage
IP_SOURCES = {'fw', 'http', 'access'}


def _capacity(state, source, bucket, cut):
    """A full page we kept or a slice we skipped: likely a flood, so say so instead of failing (R5)."""
    from .engine import _open
    from .rules import sig
    opened = []
    _open(state, sig('SIG-07', f'{source}-capacity', 'high',
                     f'{source} hit the collector page limit {cut}× (flood?); counts are a lower bound'), bucket, opened)
    return opened


class Pull:
    """A collector call that also reports how many Cloudflare pages were cut (see Cloudflare._zone_rows)."""

    def __init__(self, fn, cf):
        self.fn, self.cf = fn, cf
        self.truncated, self.partial, self.skipped = 0, [], []

    def __call__(self, start, end):
        t, p, s = self.cf.truncated, len(self.cf.partial), len(self.cf.skipped)
        rows = self.fn(start, end)
        self.truncated = self.cf.truncated - t
        self.partial, self.skipped = self.cf.partial[p:], self.cf.skipped[s:]
        return rows


def _buckets_in(ranges):
    out = set()
    for a, b in ranges:
        out.update(range(a // BUCKET * BUCKET, b, BUCKET))
    return out


def bronze_files(source, bucket_rows, keep_raw_ip):
    """{key: bytes}; rows sorted so a re-pull writes the same object (AC9). Raw IPs only under raw-ip/ (R3)."""
    out = {}
    for b, rows in bucket_rows.items():
        if not rows:
            continue
        day, stamp = iso(b)[:10], iso(b + BUCKET)
        public = [{k: v for k, v in r.items() if k != 'ip'} for r in rows]
        out[f'bronze/{source}/dt={day}/{stamp}.jsonl'] = ''.join(
            json.dumps(r, sort_keys=True) + '\n' for r in sorted(public, key=lambda r: json.dumps(r, sort_keys=True))
        ).encode()
        if keep_raw_ip and source in IP_SOURCES:
            raw = sorted({r['ip']: r['ip_hash'] for r in rows if r.get('ip')}.items())
            out[f'raw-ip/dt={day}/{source}-{stamp}.jsonl'] = ''.join(
                json.dumps({'ip': ip, 'ip_hash': h}) + '\n' for ip, h in raw).encode()
    return out


def run(state_text, now, collectors, own, send, keep_raw_ip=False):
    """collectors: {source: fn(start, end) -> [(bucket, row)]}; a missing source is off.

    own: SelfTraffic, or None when the GitHub ranges could not be read (then `http` counts as failed,
    because SIG-02 without SIG-00 would alert on our own runners).
    Returns (exit code, new state text, bronze {key: bytes}, public summary).
    """
    state = State.load(state_text)
    baseline = state is None
    state = state or State.new()
    end = (int(now) - LAG) // BUCKET * BUCKET
    opened, resolved, bronze, rows_n, status, truncated = [], [], {}, {}, {}, {}
    for source in SOURCES:
        fn = collectors.get(source)
        if fn is None:
            status[source] = 'off'
            continue
        cursor = state.cursors.get(source)
        start = cursor + BUCKET if cursor is not None else end - CATCH_UP * BUCKET
        start = max(start, end - CATCH_UP * BUCKET)
        if start >= end:
            status[source] = 'ok'
            continue
        try:
            if source == 'http' and own is None:
                raise ProviderError('github meta')
            pulled = fn(start, end)
        except ProviderError as exc:
            opened += source_failed(state, source, end - BUCKET, str(exc))
            status[source] = 'failed'
            continue
        # Never move the cursor past a slice that was not pulled; it is pulled again next run.
        skipped = getattr(fn, 'skipped', [])
        limit = min([end, *(a // BUCKET * BUCKET for a, _ in skipped)])
        partial = _buckets_in(getattr(fn, 'partial', []))
        bucket_rows = {b: [] for b in range(start, limit, BUCKET)}
        allow = own.for_source(source) if own else None
        kept = drop_self([r for _, r in pulled], allow) if allow else [r for _, r in pulled]
        kept_ids = {id(r) for r in kept}
        for b, r in pulled:
            if start <= b < limit and id(r) in kept_ids:
                bucket_rows[b].append(r)
        cut = getattr(fn, 'truncated', 0)
        capacity = f'SIG-07:{source}-capacity'
        if cut:
            truncated[source] = cut
            opened += _capacity(state, source, end - BUCKET, cut)
        elif capacity in state.signals:
            resolved.append(state.signals.pop(capacity) | {'id': capacity})
        rows_n[source] = sum(r.get('count', 1) for rs in bucket_rows.values() for r in rs)
        bronze.update(bronze_files(source, bucket_rows, keep_raw_ip))
        o, r = process_source(state, source, bucket_rows, baseline=baseline, partial=partial)
        opened += o
        resolved += r
        status[source] = 'ok'
    state.trim(end)

    open_count = {}
    for s in state.signals.values():
        open_count[s['severity']] = open_count.get(s['severity'], 0) + 1
    args = (opened, resolved, open_count, rows_n if baseline else None)
    text = message(*args)
    # (text to send now, copy to keep if it fails): the kept copy has no raw IP (R3); old pending ones never had one
    queue = [(p, p) for p in state.pending] + ([(text, message(*args, show_ip=False))] if text else [])
    state.pending = []
    for n, (item, _) in enumerate(queue):
        try:
            send(item)
        except Exception:  # noqa: BLE001  kept in state, retried next run (R8)
            state.pending = [keep for _, keep in queue[n:]]
            break

    summary = json.loads(public_summary(rows_n, status, list(state.signals.values()), opened, resolved))
    if state.pending:
        summary['alerts_pending'] = len(state.pending)
    if truncated:
        summary['truncated'] = truncated
    code = SOURCE_FAILED if 'failed' in status.values() else NOTIFY_FAILED if state.pending else OK
    summary['exit'] = code
    return code, state.dump(), bronze, json.dumps(summary, sort_keys=True)


# -- wiring ---------------------------------------------------------------------------------------
def telegram(env):
    def send(text):
        data = json.dumps({'chat_id': env['TELEGRAM_CHAT_ID'], 'text': text, 'disable_web_page_preview': True}).encode()
        req = urllib.request.Request(f'https://api.telegram.org/bot{env["TELEGRAM_BOT_TOKEN"]}/sendMessage', data=data,
                                     headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=20) as resp:
            if not json.load(resp).get('ok'):
                raise OSError('telegram refused the message')
    return send


def collectors_from_env(env):
    key = env['SIGNALS_IP_KEY'].encode()
    out = {}
    if env.get('SIGNALS_CF_TOKEN'):
        cf = Cloudflare(env['SIGNALS_CF_TOKEN'], env['SIGNALS_CF_ZONE_ID'], env['SIGNALS_CF_ACCOUNT_ID'], key)
        host = env.get('SIGNALS_GATEWAY_HOST', 'gateway.bookchaowalit.com')
        out['fw'] = Pull(cf.firewall, cf)
        out['http'] = Pull(lambda a, b: cf.gateway_http(a, b, host), cf)
        out['access'] = Pull(cf.access, cf)

    def railway(token_var):
        token = env.get(token_var) or env.get('SIGNALS_RAILWAY_TOKEN')
        return Railway(token, project_token=bool(env.get(token_var))) if token else None

    gw = railway('SIGNALS_RAILWAY_GW_TOKEN')
    if gw and env.get('SIGNALS_GW_ENV_ID'):
        out['gw'] = lambda a, b: gw.gateway(env['SIGNALS_GW_ENV_ID'], a, b)
    idp = railway('SIGNALS_RAILWAY_IDP_TOKEN')
    if idp and env.get('SIGNALS_IDP_ENV_ID'):
        out['idp'] = lambda a, b: idp.identity(env['SIGNALS_IDP_ENV_ID'], a, b)
    return out  # 'bypass' has no collector in v1 (fed by WS3 later)


def self_ips(env):
    try:
        ranges = github_actions_ranges()
    except ProviderError:
        return None
    explicit = [a for a in env.get('SIGNALS_SELF_IPS', '').replace('\n', ',').split(',') if a.strip()]
    return SelfTraffic(SelfIPs([], explicit), SelfIPs(ranges))


def main(argv=None, env=os.environ):
    p = argparse.ArgumentParser(prog='security_signals')
    p.add_argument('--state-in', type=Path, required=True)
    p.add_argument('--state-out', type=Path, required=True)
    p.add_argument('--bronze-dir', type=Path, required=True)
    p.add_argument('--no-notify', action='store_true', help='print alerts to stderr instead of Telegram')
    args = p.parse_args(argv)
    if not env.get('SIGNALS_IP_KEY'):
        print(json.dumps({'exit': CONFIG_FAILED, 'error': 'missing SIGNALS_IP_KEY'}))
        return CONFIG_FAILED
    send = (lambda text: print(text, file=sys.stderr)) if args.no_notify else telegram(env)
    state_text = args.state_in.read_text() if args.state_in.exists() else ''
    code, new_state, bronze, summary = run(state_text, time.time(), collectors_from_env(env), self_ips(env), send,
                                           keep_raw_ip=env.get('SIGNALS_KEEP_RAW_IP') == '1')
    args.state_out.write_text(new_state)
    for key, body in bronze.items():
        path = args.bronze_dir / key
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
    print(summary)
    return code
