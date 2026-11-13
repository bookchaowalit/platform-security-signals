"""security-api audit events for opened and resolved signals (R8, R11)."""
import base64
import json
import os
import shutil
import subprocess
import tempfile
import unittest

from security_signals.audit import AuditSink, assertion, event_target, idempotency_key
from security_signals.model import BUCKET
from security_signals.run import NOTIFY_FAILED, OK, run
from security_signals.sources import ProviderError
from security_signals.store import MAX_AUDIT, State

from .helpers import b, fw, http
from .test_run import NOW, OWN, Sent, collector


class Sink:
    """Records posted events; `fail_at` makes the n-th post (0-based) and every later one fail."""

    def __init__(self, fail_at=None, token_error=False):
        self.posted, self.fail_at, self.token_error = [], fail_at, token_error

    def __call__(self, events):
        def token():
            if self.token_error:
                raise ProviderError('/v1/token: HTTPError')
            return 't'

        def post(body, key, _token):
            if self.fail_at is not None and len(self.posted) >= self.fail_at:
                raise ProviderError('/v1/audit: HTTPError')
            self.posted.append((body, key))
        return AuditSink(token, post)(events)


def opened_run(audit):
    """Baseline, then one run where SIG-02 opens for 203.0.113.9."""
    _, state, _, _ = run('', NOW, {'http': collector()}, OWN, Sent(), audit=audit)
    return run(state, NOW + BUCKET, {'http': collector({b(200): [http(count=40)]})}, OWN, Sent(), audit=audit)


class Targets(unittest.TestCase):
    def test_target_keeps_rule_and_subject(self):
        self.assertEqual(event_target('SIG-07:fw-capacity'), 'sig-07.fw-capacity')
        self.assertEqual(event_target('SIG-03:zone'), 'sig-03.zone')

    def test_odd_subject_becomes_a_hash(self):
        t = event_target('SIG-04:TH/dev 1+x')
        self.assertRegex(t, r'^sig-04\.h[0-9a-f]{16}$')

    def test_key_is_stable_per_lifetime_and_change(self):
        e = {'change': 'opened', 'id': 'SIG-02:h1', 'at': 10}
        self.assertEqual(idempotency_key(e), idempotency_key(dict(e)))
        self.assertNotEqual(idempotency_key(e), idempotency_key(e | {'change': 'resolved'}))
        self.assertNotEqual(idempotency_key(e), idempotency_key(e | {'at': 11}))  # reopened later: a new event


class Runs(unittest.TestCase):
    def test_opened_and_resolved_signals_are_posted_once(self):
        sink = Sink()
        code, state, _, summary = opened_run(sink)
        self.assertEqual(code, OK)
        self.assertEqual([body for body, _ in sink.posted], [{'action': 'signal.opened', 'target': 'sig-02.h20301139'}])
        self.assertEqual(State.load(state).audit, [])
        self.assertNotIn('audit_pending', json.loads(summary))
        self.assertNotIn('203.0.113.9', json.dumps(sink.posted))  # R3: the target carries the hash only
        later = NOW + 8 * BUCKET  # quiet for longer than the SIG-02 hold
        run(state, later, {'http': collector()}, OWN, Sent(), audit=sink)
        self.assertEqual([body['action'] for body, _ in sink.posted], ['signal.opened', 'signal.resolved'])
        opened_key, resolved_key = (k for _, k in sink.posted)
        self.assertNotEqual(opened_key, resolved_key)

    def test_refused_events_wait_and_keep_their_key(self):  # R8
        down = Sink(fail_at=0)
        code, state, _, summary = opened_run(down)
        self.assertEqual(code, NOTIFY_FAILED)
        self.assertEqual(json.loads(summary)['audit_pending'], 1)
        kept = State.load(state).audit
        self.assertEqual(kept[0]['change'], 'opened')
        up = Sink()
        code, state, _, _ = run(state, NOW + BUCKET, {'http': collector()}, OWN, Sent(), audit=up)
        self.assertEqual(code, OK)
        self.assertEqual(up.posted[0][1], idempotency_key(kept[0]))
        self.assertEqual(State.load(state).audit, [])

    def test_identity_down_keeps_every_event(self):
        code, state, _, _ = opened_run(Sink(token_error=True))
        self.assertEqual(code, NOTIFY_FAILED)
        self.assertEqual(len(State.load(state).audit), 1)

    def test_no_sink_keeps_events_without_failing_the_run(self):  # local runs
        code, state, _, _ = opened_run(None)
        self.assertEqual(code, OK)
        self.assertEqual(len(State.load(state).audit), 1)

    def test_partial_failure_keeps_the_tail_in_order(self):
        events = [{'change': 'opened', 'id': f'SIG-03:h{n}', 'at': n} for n in range(3)]
        sink = Sink(fail_at=1)
        self.assertEqual(sink(events), events[1:])

    def test_post_cap_and_time_budget_leave_the_rest_for_next_run(self):  # review P1 on 36c4ba3
        events = [{'change': 'opened', 'id': f'SIG-03:h{n}', 'at': n} for n in range(5)]
        posted = []
        capped = AuditSink(lambda: 't', lambda body, key, tok: posted.append(key), max_posts=2)
        self.assertEqual(capped(events), events[2:])
        ticks = iter([0, 0, 50, 100, 150])  # start, then one reading per event
        slow = AuditSink(lambda: 't', lambda body, key, tok: None, clock=lambda: next(ticks), budget=90)
        self.assertEqual(slow(events), events[2:])

    def test_replayed_run_reuses_the_capacity_and_failure_keys(self):  # review P2 on 36c4ba3
        _, state, _, _ = run('', NOW, {'fw': collector(), 'http': collector()}, OWN, Sent())
        keys = []
        for later in (NOW + 2 * BUCKET, NOW + 3 * BUCKET):  # the first result is lost (bronze upload failed)
            flood = collector({b(200): [fw(count=5)]})
            flood.truncated, flood.partial = 1, [(b(200), b(201))]
            _, out, _, _ = run(state, later, {'fw': flood, 'http': collector(error='http 500')}, OWN, Sent())
            keys.append(sorted(idempotency_key(e) for e in State.load(out).audit))
        self.assertEqual(len(keys[0]), 3)  # SIG-07 capacity, SIG-07 http failed, SIG-03 new host
        self.assertEqual(keys[0], keys[1])

    def test_kept_events_are_capped(self):
        s = State.new()
        s.audit = [{'change': 'opened', 'id': f'SIG-03:h{n}', 'at': n} for n in range(MAX_AUDIT + 20)]
        kept = State.load(s.dump()).audit
        self.assertEqual(len(kept), MAX_AUDIT)
        self.assertEqual(kept[0]['at'], 20)  # the oldest go first


@unittest.skipUnless(shutil.which('openssl'), 'openssl not installed')
class Assertion(unittest.TestCase):
    def test_assertion_verifies_with_the_public_key(self):
        with tempfile.TemporaryDirectory() as d:
            priv, pub = os.path.join(d, 'k.pem'), os.path.join(d, 'p.pem')
            subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', priv],
                           check=True, capture_output=True)
            subprocess.run(['openssl', 'pkey', '-in', priv, '-pubout', '-out', pub], check=True, capture_output=True)
            with open(priv) as f:
                jwt = assertion('security-signals', 'https://idp.example/v1/token', f.read(), now=1000)
            head, claims, sig = jwt.split('.')
            pad = lambda s: base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))  # noqa: E731
            body = json.loads(pad(claims))
            self.assertEqual((body['iss'], body['sub'], body['aud'], body['exp']),
                             ('security-signals', 'security-signals', 'https://idp.example/v1/token', 1120))
            sig_path = os.path.join(d, 'sig')
            with open(sig_path, 'wb') as f:
                f.write(pad(sig))
            ok = subprocess.run(['openssl', 'dgst', '-sha256', '-verify', pub, '-signature', sig_path],
                                input=f'{head}.{claims}'.encode(), capture_output=True)
            self.assertEqual(ok.returncode, 0)


if __name__ == '__main__':
    unittest.main()
