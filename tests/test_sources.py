"""Collector contracts against the response shapes seen in the spike (synthetic values)."""
import io
import json
import unittest
import urllib.error

from security_signals.sources import CF_LIMIT, RAILWAY_LIMIT, Cloudflare, ProviderError, Railway, _path_prefix

from .helpers import KEY, T0


class FakeOpener:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.requests = []

    def __call__(self, req, timeout):
        self.requests.append(json.loads(req.data))
        r = self.responses.pop(0)
        if isinstance(r, Exception):
            raise r
        return io.BytesIO(json.dumps(r).encode())


def zone(field, rows):
    return {'data': {'viewer': {'zones': [{field: rows}]}}}


def fw_row(minute=1, ip='203.0.113.7', path='/.env?x=1'):
    return {'datetime': f'2026-11-12T00:{minute:02d}:30Z', 'action': 'block', 'source': 'firewallCustom',
            'clientRequestHTTPHost': 'app.example.com', 'clientRequestPath': path, 'clientCountryName': 'NL',
            'clientIP': ip}


class CloudflareFirewall(unittest.TestCase):
    def test_rows_are_bucketed_aggregated_and_hashed(self):
        op = FakeOpener(zone('firewallEventsAdaptive', [fw_row(1), fw_row(2), fw_row(16)]))
        rows = Cloudflare('t', 'z', 'a', KEY, opener=op).firewall(T0, T0 + 1800)
        by_bucket = {b: r for b, r in rows}
        self.assertEqual(by_bucket[T0]['count'], 2)
        self.assertEqual(by_bucket[T0 + 900]['count'], 1)
        self.assertEqual(by_bucket[T0]['path_prefix'], '/.env')
        self.assertEqual(len(by_bucket[T0]['ip_hash']), 16)
        self.assertNotEqual(by_bucket[T0]['ip_hash'], '203.0.113.7')

    def test_full_page_splits_the_range(self):
        full = [fw_row(1)] * CF_LIMIT
        op = FakeOpener(zone('firewallEventsAdaptive', full), zone('firewallEventsAdaptive', [fw_row(1)]),
                        zone('firewallEventsAdaptive', [fw_row(16)]))
        rows = Cloudflare('t', 'z', 'a', KEY, opener=op).firewall(T0, T0 + 1800)
        self.assertEqual(len(op.requests), 3)
        self.assertEqual(sum(r['count'] for _, r in rows), 2)

    def test_graphql_error_and_http_error_raise(self):
        with self.assertRaises(ProviderError):
            Cloudflare('t', 'z', 'a', KEY, opener=FakeOpener({'errors': [{'message': 'x'}]})).firewall(T0, T0 + 900)
        err = urllib.error.HTTPError('u', 403, 'no', {}, None)
        with self.assertRaises(ProviderError) as ctx:
            Cloudflare('t', 'z', 'a', KEY, opener=FakeOpener(err)).firewall(T0, T0 + 900)
        self.assertEqual(str(ctx.exception), 'http 403')

    def test_path_prefix(self):
        self.assertEqual(_path_prefix('/v1/habits/x?y'), '/v1')
        self.assertEqual(_path_prefix(''), '/')
        self.assertEqual(len(_path_prefix('/' + 'a' * 100)), 25)


class CloudflareHttpAndAccess(unittest.TestCase):
    def test_gateway_http_passes_host_and_maps_rows(self):
        row = {'count': 7, 'dimensions': {'datetimeFifteenMinutes': '2026-11-12T00:15:00Z', 'edgeResponseStatus': 429,
                                          'clientIP': '198.51.100.3', 'clientCountryName': 'US'}}
        op = FakeOpener(zone('httpRequestsAdaptiveGroups', [row]))
        rows = Cloudflare('t', 'z', 'a', KEY, opener=op).gateway_http(T0, T0 + 1800, 'gw.example.com')
        self.assertEqual(op.requests[0]['variables']['h'], 'gw.example.com')
        self.assertEqual(rows[0][0], T0 + 900)
        self.assertEqual((rows[0][1]['status'], rows[0][1]['count']), (429, 7))

    def test_access_maps_rows_and_never_spans_more_than_a_week(self):  # AC10
        row = {'count': 1, 'dimensions': {'datetimeFifteenMinutes': '2026-11-12T00:00:00Z', 'isSuccessfulLogin': 1,
                                          'country': 'TH', 'deviceId': '', 'ipAddress': '198.51.100.4', 'appId': 'abcdef123'}}
        op = FakeOpener({'data': {'viewer': {'accounts': [{'accessLoginRequestsAdaptiveGroups': [row]}]}}})
        rows = Cloudflare('t', 'z', 'a', KEY, opener=op).access(T0, T0 + 900)
        self.assertEqual(rows[0][1]['device_hash'], '')
        self.assertTrue(rows[0][1]['success'])
        with self.assertRaises(ValueError):
            Cloudflare('t', 'z', 'a', KEY, opener=FakeOpener()).access(T0, T0 + 8 * 86_400)


def line(ts, **attrs):
    return {'timestamp': ts, 'attributes': [{'key': k, 'value': str(v)} for k, v in attrs.items()]}


class RailwayLogs(unittest.TestCase):
    def test_gateway_counts_errors_per_bucket_and_system(self):
        lines = [line('2026-11-12T00:01:00.123456789Z', event='request.completed', status=401, system='habits'),
                 line('2026-11-12T00:02:00Z', event='request.completed', status=401, system='habits'),
                 line('2026-11-12T00:03:00Z', event='request.completed', status=200, system='habits'),
                 line('2026-11-12T00:31:00Z', event='request.completed', status=403, system='diary')]  # after end
        op = FakeOpener({'data': {'environmentLogs': lines}})
        rows = Railway('t', opener=op).gateway('env', T0, T0 + 1800)
        self.assertEqual(rows, [(T0, {'system': 'habits', 'status': 401, 'count': 2})])
        self.assertEqual(op.requests[0]['variables']['f'], '@event:request.completed')

    def test_project_token_header(self):
        self.assertEqual(Railway('t', project_token=True).header, {'Project-Access-Token': 't'})

    def test_full_page_not_reaching_start_is_an_error(self):
        lines = [line('2026-11-12T00:10:00Z', status=401, system='x')] * RAILWAY_LIMIT
        with self.assertRaises(ProviderError):
            Railway('t', opener=FakeOpener({'data': {'environmentLogs': lines}})).gateway('env', T0, T0 + 1800)

    def test_identity_failures(self):
        lines = [line('2026-11-12T00:05:00Z', event='token.issue_failed', reason='invalid_grant', client_hash='c1')] * 3
        rows = Railway('t', opener=FakeOpener({'data': {'environmentLogs': lines}})).identity('env', T0, T0 + 900)
        self.assertEqual(rows, [(T0, {'reason': 'invalid_grant', 'client_hash': 'c1', 'count': 3})])


if __name__ == '__main__':
    unittest.main()
