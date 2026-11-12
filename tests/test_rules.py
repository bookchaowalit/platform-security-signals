"""SPEC-001 rules SIG-00..SIG-07 and the open/resolve engine (AC1-AC7, AC9)."""
import json
import unittest

from security_signals.engine import process_source, source_failed
from security_signals.model import SelfIPs
from security_signals.store import State

from .helpers import access, b, fw, gw, http, idp


def run(state, source, buckets, baseline=False):
    """buckets: {n: rows}; returns (opened ids, resolved ids)."""
    opened, resolved = process_source(state, source, {b(n): rows for n, rows in buckets.items()}, baseline=baseline)
    return sorted(s['id'] for s in opened), sorted(s['id'] for s in resolved)


class SelfTraffic(unittest.TestCase):  # AC1
    def test_cidr_and_single_addresses(self):
        own = SelfIPs(['192.0.2.0/24', '2001:db8::/32'], ['198.51.100.10'])
        self.assertTrue(own.contains('192.0.2.200'))
        self.assertTrue(own.contains('2001:db8::1'))
        self.assertTrue(own.contains('198.51.100.10'))
        self.assertFalse(own.contains('198.51.100.11'))
        self.assertFalse(own.contains('not-an-ip'))

    def test_self_rows_are_dropped_before_rules(self):
        from security_signals.model import drop_self
        own = SelfIPs(['203.0.113.0/24'], [])
        rows = [http(ip='203.0.113.9', count=99), http(ip='198.51.100.1', count=1)]
        self.assertEqual([r['ip'] for r in drop_self(rows, own)], ['198.51.100.1'])


class Sig01AuthSpike(unittest.TestCase):  # AC2
    def test_needs_absolute_and_relative_threshold(self):
        s = State.new()
        # steady 20 failures per bucket for 8 buckets: mean 20, so 60 (< 5x) must not open
        run(s, 'gw', {n: [gw(count=20)] for n in range(8)})
        self.assertEqual(run(s, 'gw', {8: [gw(count=60)]})[0], [])
        # 49 failures on a quiet system: above 5x mean but below 50
        self.assertEqual(run(s, 'gw', {9: [gw(system='diary', count=49)]})[0], [])
        opened, _ = run(s, 'gw', {10: [gw(system='diary', count=50)]})
        self.assertEqual(opened, ['SIG-01:diary'])

    def test_403_counts_and_404_does_not(self):
        s = State.new()
        self.assertEqual(run(s, 'gw', {0: [gw(status=404, count=500)]})[0], [])
        self.assertEqual(run(s, 'gw', {1: [gw(status=403, count=30), gw(status=401, count=30)]})[0], ['SIG-01:habits'])

    def test_resolves_after_four_quiet_buckets(self):
        s = State.new()
        run(s, 'gw', {0: [gw(count=80)]})
        self.assertEqual(run(s, 'gw', {1: [], 2: [], 3: []})[1], [])
        self.assertEqual(run(s, 'gw', {4: []})[1], ['SIG-01:habits'])


class Sig02BruteForce(unittest.TestCase):  # AC3
    def test_thirty_401_within_an_hour_opens_once(self):
        s = State.new()
        opened, _ = run(s, 'http', {0: [http(count=10)], 1: [http(count=10)], 2: [http(count=10)]})
        self.assertEqual(opened, ['SIG-02:h20301139'])
        self.assertEqual(run(s, 'http', {3: [http(count=10)]})[0], [])  # same attacker, no re-alert

    def test_counts_outside_the_hour_do_not_add_up(self):
        s = State.new()
        self.assertEqual(run(s, 'http', {0: [http(count=20)], 4: [http(count=20)]})[0], [])

    def test_429_and_401_are_separate_counts(self):
        s = State.new()
        self.assertEqual(run(s, 'http', {0: [http(status=401, count=20), http(status=429, count=20)]})[0], [])
        self.assertEqual(run(s, 'http', {1: [http(status=429, count=10)]})[0], ['SIG-02:h20301139'])

    def test_opened_signal_carries_the_raw_ip_but_state_does_not(self):
        s = State.new()
        opened, _ = process_source(s, 'http', {b(0): [http(count=40)]})
        self.assertEqual(opened[0]['ip'], '203.0.113.9')
        self.assertNotIn('203.0.113.9', s.dump())


class Sig03Scanning(unittest.TestCase):  # AC4
    def test_surge_opens_on_the_zone(self):
        s = State.new()
        run(s, 'fw', {0: [fw(count=10)]}, baseline=True)
        opened, _ = run(s, 'fw', {1: [fw(count=250)]})
        self.assertEqual(opened, ['SIG-03:zone'])

    def test_new_host_opens_even_below_threshold(self):
        s = State.new()
        run(s, 'fw', {0: [fw(host='a.example.com')]}, baseline=True)
        self.assertEqual(run(s, 'fw', {1: [fw(host='a.example.com', count=5)]})[0], [])
        self.assertEqual(run(s, 'fw', {2: [fw(host='b.example.com')]})[0], ['SIG-03:b.example.com'])

    def test_skip_and_log_actions_are_not_blocks(self):
        s = State.new()
        self.assertEqual(run(s, 'fw', {0: [fw(action='skip', count=500), fw(action='log', count=500)]})[0], [])


class Sig04AccessOrigin(unittest.TestCase):  # AC5
    def test_new_country_success_opens_failure_does_not(self):
        s = State.new()
        run(s, 'access', {0: [access()]}, baseline=True)
        self.assertEqual(run(s, 'access', {1: [access(success=False, country='RU')]})[0], [])
        self.assertEqual(run(s, 'access', {2: [access(country='RU')]})[0], ['SIG-04:country:RU'])

    def test_new_device_opens(self):
        s = State.new()
        run(s, 'access', {0: [access()]}, baseline=True)
        self.assertEqual(run(s, 'access', {1: [access(device='dev-2')]})[0], ['SIG-04:device:dev-2'])

    def test_seen_older_than_30_days_counts_as_new_even_before_trim(self):  # review P2
        s = State.new()
        run(s, 'access', {0: [access(country='RU')]}, baseline=True)
        self.assertEqual(run(s, 'access', {31 * 96: [access(country='RU')]})[0], ['SIG-04:country:RU', 'SIG-04:device:dev-1'])

    def test_ack_resolves(self):
        s = State.new()
        run(s, 'access', {0: [access()]}, baseline=True)
        run(s, 'access', {1: [access(country='RU')]})
        s.acks.append('SIG-04:country:RU')
        self.assertEqual(run(s, 'access', {2: []})[1], ['SIG-04:country:RU'])


class Sig05Bypass(unittest.TestCase):
    def test_enforce_bypass_is_high_report_bypass_is_medium(self):
        s = State.new()
        opened, _ = process_source(s, 'bypass', {b(0): [{'system': 'diary', 'mode': 'enforce', 'count': 1},
                                                         {'system': 'goals', 'mode': 'report', 'count': 2}]})
        self.assertEqual({o['id']: o['severity'] for o in opened}, {'SIG-05:diary': 'high', 'SIG-05:goals': 'medium'})


class Sig06Identity(unittest.TestCase):
    def test_failure_surge(self):
        s = State.new()
        self.assertEqual(run(s, 'idp', {0: [idp(reason='invalid_client', client='x', count=19)]})[0], [])
        self.assertEqual(run(s, 'idp', {1: [idp(reason='invalid_client', client='x', count=20)]})[0], ['SIG-06:identity'])

    def test_known_client_failing_is_new_signal_random_ids_are_not(self):
        s = State.new()
        run(s, 'idp', {0: [idp(client='c-1')]}, baseline=True)
        self.assertEqual(run(s, 'idp', {1: [idp(reason='invalid_client', client='random')]})[0], [])
        self.assertEqual(run(s, 'idp', {2: [idp(reason='invalid_grant', client='c-2')]})[0], ['SIG-06:client:c-2'])


class Sig07Silent(unittest.TestCase):  # AC6
    def test_failed_source_keeps_its_signals_and_opens_sig07(self):
        s = State.new()
        run(s, 'gw', {0: [gw(count=80)]})
        opened = source_failed(s, 'gw', b(10), 'HTTPError')
        self.assertEqual([o['id'] for o in opened], ['SIG-07:gw'])
        self.assertIn('SIG-01:habits', s.signals)  # not resolved by a failed pull
        self.assertEqual(source_failed(s, 'gw', b(11), 'HTTPError'), [])  # no re-alert
        _, resolved = run(s, 'gw', {1: []})
        self.assertIn('SIG-07:gw', resolved)

    def test_source_gone_quiet_against_its_own_history(self):
        s = State.new()
        day = 96
        run(s, 'fw', {n: [fw(action='skip')] for n in range(0, 4)}, baseline=True)
        run(s, 'fw', {n: [] for n in range(4, day)}, baseline=True)
        opened, _ = run(s, 'fw', {n: [] for n in range(day, day + 4)})
        self.assertEqual(opened, ['SIG-07:fw'])


class Partial(unittest.TestCase):
    def test_partial_buckets_open_but_never_resolve(self):
        s = State.new()
        process_source(s, 'gw', {b(0): [gw(count=80)]})
        opened, resolved = process_source(s, 'gw', {b(n): [] for n in range(1, 9)}, partial={b(n) for n in range(1, 9)})
        self.assertEqual(resolved, [])
        opened, _ = process_source(s, 'gw', {b(9): [gw(system='diary', count=60)]}, partial={b(9)})
        self.assertEqual([o['id'] for o in opened], ['SIG-01:diary'])
        # the hold counts from the last cut bucket: 3 clean buckets later it is still open, the 4th resolves
        self.assertEqual(process_source(s, 'gw', {b(n): [] for n in range(10, 13)})[1], [])
        self.assertIn('SIG-01:habits', [r['id'] for r in process_source(s, 'gw', {b(13): []})[1]])


class Engine(unittest.TestCase):
    def test_baseline_run_opens_nothing(self):  # R4
        s = State.new()
        self.assertEqual(run(s, 'http', {0: [http(count=500)]}, baseline=True), ([], []))

    def test_reprocessing_a_bucket_is_idempotent(self):  # AC9
        s1, s2 = State.new(), State.new()
        run(s1, 'gw', {0: [gw(count=5)]})
        run(s2, 'gw', {0: [gw(count=5)]})
        run(s2, 'gw', {0: [gw(count=5)]})
        self.assertEqual(json.loads(s1.dump())['series'], json.loads(s2.dump())['series'])

    def test_cursor_moves_to_last_bucket(self):
        s = State.new()
        run(s, 'gw', {0: [], 1: []})
        self.assertEqual(s.cursors['gw'], b(1))

    def test_state_round_trip_and_trim(self):
        s = State.new()
        run(s, 'http', {0: [http(count=3)]})
        run(s, 'gw', {0: [gw(count=3)]})
        s2 = State.load(s.dump())
        self.assertEqual(s2.dump(), s.dump())
        s2.trim(b(96 * 40))
        self.assertEqual(s2.series.get('ip_401', {}), {})
        self.assertEqual(s2.series.get('auth_fail', {}), {})


if __name__ == '__main__':
    unittest.main()
