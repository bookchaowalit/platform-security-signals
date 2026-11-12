"""Whole runs with fake collectors (R4, R5, R6, R8, AC6, AC8, AC9, AC10)."""
import json
import unittest

from security_signals.model import BUCKET, SelfIPs, SelfTraffic
from security_signals.run import CATCH_UP, LAG, NOTIFY_FAILED, OK, SOURCE_FAILED, run
from security_signals.sources import ProviderError
from security_signals.store import State

from .helpers import access, b, fw, http

NOW = b(200) + LAG + 1  # buckets up to b(199) are complete
OWN = SelfTraffic(SelfIPs([], ['192.0.2.0/24']), SelfIPs(['198.18.0.0/15']))  # explicit, 'GitHub Actions'


def collector(rows_by_bucket=None, error=None, calls=None):
    def fn(start, end):
        if calls is not None:
            calls.append((start, end))
        if error:
            raise ProviderError(error)
        return [(bk, r) for bk, rows in (rows_by_bucket or {}).items() for r in rows]
    return fn


class Sent(list):
    def __call__(self, text):
        self.append(text)


class Runs(unittest.TestCase):
    def test_first_run_is_a_baseline(self):  # R4
        sent = Sent()
        code, state, _, summary = run('', NOW, {'http': collector({b(199): [http(count=500)]})}, OWN, sent)
        self.assertEqual(code, OK)
        self.assertEqual(len(sent), 1)
        self.assertIn('baseline', sent[0])
        self.assertEqual(json.loads(state)['signals'], {})

    def test_second_run_alerts_once_and_only_on_change(self):
        sent = Sent()
        _, state, _, _ = run('', NOW, {'http': collector()}, OWN, sent)
        _, state, _, _ = run(state, NOW + BUCKET, {'http': collector({b(200): [http(count=40)]})}, OWN, sent)
        self.assertIn('SIG-02', sent[-1])
        self.assertIn('203.0.113.9', sent[-1])
        n = len(sent)
        run(state, NOW + BUCKET, {'http': collector()}, OWN, sent)  # nothing new to pull
        self.assertEqual(len(sent), n)

    def test_self_traffic_never_alerts(self):  # AC1
        sent = Sent()
        _, state, _, _ = run('', NOW, {'http': collector()}, OWN, sent)
        run(state, NOW + BUCKET, {'http': collector({b(200): [http(ip='192.0.2.5', count=500)]})}, OWN, sent)
        self.assertEqual(len(sent), 1)

    def test_one_failed_source_does_not_stop_the_others(self):  # R5, AC6
        sent = Sent()
        _, state, _, _ = run('', NOW, {'http': collector(), 'fw': collector()}, OWN, sent)
        code, state, _, summary = run(state, NOW + BUCKET, {'http': collector({b(200): [http(count=40)]}),
                                                            'fw': collector(error='http 500')}, OWN, sent)
        self.assertEqual(code, SOURCE_FAILED)
        s = State.load(state)
        self.assertEqual(s.cursors['http'], b(200))
        self.assertEqual(s.cursors['fw'], b(199))  # not moved
        self.assertIn('SIG-07:fw', s.signals)
        self.assertEqual(json.loads(summary)['sources'], {'access': 'off', 'bypass': 'off', 'fw': 'failed',
                                                          'gw': 'off', 'http': 'ok', 'idp': 'off'})

    def test_missing_github_ranges_fail_http_only(self):
        sent = Sent()
        _, state, _, _ = run('', NOW, {'http': collector(), 'fw': collector()}, OWN, sent)
        code, state, _, summary = run(state, NOW + BUCKET, {'http': collector(), 'fw': collector()}, None, sent)
        self.assertEqual(json.loads(summary)['sources']['http'], 'failed')
        self.assertEqual(json.loads(summary)['sources']['fw'], 'ok')

    def test_refused_message_is_kept_and_sent_next_time(self):  # R8
        def refuse(text):
            raise OSError('no')
        code, state, _, _ = run('', NOW, {'http': collector()}, OWN, refuse)
        self.assertEqual(code, NOTIFY_FAILED)
        self.assertEqual(len(State.load(state).pending), 1)
        sent = Sent()
        code, state, _, _ = run(state, NOW, {'http': collector()}, OWN, sent)
        self.assertEqual((code, len(sent)), (OK, 1))
        self.assertEqual(State.load(state).pending, [])

    def test_catch_up_is_capped_at_24h(self):  # R6, AC10
        calls = []
        _, state, _, _ = run('', NOW, {'http': collector()}, OWN, Sent())
        run(state, NOW + 3 * 96 * BUCKET, {'http': collector(calls=calls)}, OWN, Sent())
        start, end = calls[0]
        self.assertEqual(end - start, CATCH_UP * BUCKET)

    def test_bronze_has_no_raw_ip_unless_asked(self):  # R3, AC8
        _, _, bronze, summary = run('', NOW, {'http': collector({b(199): [http(count=3)]})}, OWN, Sent())
        blob = b''.join(bronze.values()).decode()
        self.assertNotIn('203.0.113.9', blob)
        self.assertTrue(all(k.startswith('bronze/http/dt=') for k in bronze))
        self.assertNotIn('203.0.113.9', summary)
        _, _, bronze, _ = run('', NOW, {'http': collector({b(199): [http(count=3)]})}, OWN, Sent(), keep_raw_ip=True)
        self.assertTrue(any(k.startswith('raw-ip/') for k in bronze))

    def test_same_bucket_same_bronze(self):  # AC9
        rows = {b(199): [http(count=3), http(ip='198.51.100.1', count=1)]}
        _, _, a, _ = run('', NOW, {'http': collector(rows)}, OWN, Sent())
        _, _, c, _ = run('', NOW, {'http': collector({b(199): list(reversed(rows[b(199)]))})}, OWN, Sent())
        self.assertEqual(a, c)

    def test_cut_pages_open_a_capacity_signal(self):  # security review: a flood is reported, not hidden
        sent = Sent()
        _, state, _, _ = run('', NOW, {'fw': collector()}, OWN, sent)
        flood = collector({b(200): [fw(count=5)]})
        flood.truncated = 2
        _, state, _, summary = run(state, NOW + BUCKET, {'fw': flood}, OWN, sent)
        self.assertIn('SIG-07', sent[-1])
        self.assertEqual(json.loads(summary)['truncated'], {'fw': 2})
        _, _, _, _ = run(state, NOW + 2 * BUCKET, {'fw': collector()}, OWN, sent)
        self.assertIn('✅ SIG-07', sent[-1])

    def test_kept_message_has_no_raw_ip(self):  # review P1: R3
        def refuse(text):
            raise OSError('no')
        _, state, _, _ = run('', NOW, {'http': collector()}, OWN, Sent())
        code, state, _, _ = run(state, NOW + BUCKET, {'http': collector({b(200): [http(count=40)]})}, OWN, refuse)
        self.assertEqual(code, NOTIFY_FAILED)
        self.assertIn('SIG-02', state)
        self.assertNotIn('203.0.113.9', state)

    def test_first_run_reports_a_failing_source(self):  # review P2
        sent = Sent()
        code, _, _, _ = run('', NOW, {'http': collector(), 'fw': collector(error='http 403')}, OWN, sent)
        self.assertEqual(code, SOURCE_FAILED)
        self.assertIn('baseline', sent[0])
        self.assertIn('SIG-07', sent[0])

    def test_github_ranges_quiet_only_the_gateway_http_source(self):  # security review: allowlist scope
        sent = Sent()
        gh = '198.18.0.7'
        _, state, _, _ = run('', NOW, {'http': collector(), 'fw': collector(), 'access': collector()}, OWN, sent)
        run(state, NOW + BUCKET, {'http': collector({b(200): [http(ip=gh, count=500)]}),
                                  'fw': collector({b(200): [fw(ip=gh, count=300)]}),
                                  'access': collector({b(200): [access(ip=gh, country='RU')]})}, OWN, sent)
        self.assertNotIn('SIG-02', sent[-1])
        self.assertIn('SIG-03', sent[-1])
        self.assertIn('SIG-04', sent[-1])


if __name__ == '__main__':
    unittest.main()
