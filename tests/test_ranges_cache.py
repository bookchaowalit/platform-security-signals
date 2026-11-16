import json
import unittest

from security_signals.run import RANGES_MAX_AGE, cached_ranges, self_ips
from security_signals.sources import ProviderError, github_actions_ranges


def failing(token=None):
    raise ProviderError('HTTPError')


class RangesCacheTest(unittest.TestCase):
    def test_fresh_pull_is_cached(self):
        own, cache = self_ips({}, None, now=1000, fetch=lambda token=None: ['192.0.2.0/24'])
        self.assertIsNotNone(own)
        self.assertEqual(cache, {'at': 1000, 'ranges': ['192.0.2.0/24']})

    def test_failed_pull_uses_recent_cache(self):
        cache = {'at': 1000, 'ranges': ['192.0.2.0/24']}
        own, kept = self_ips({}, cache, now=1000 + 3600, fetch=failing)
        self.assertIsNotNone(own)
        self.assertEqual(kept, cache)

    def test_failed_pull_with_stale_or_no_cache_fails(self):
        cache = {'at': 0, 'ranges': ['192.0.2.0/24']}
        self.assertIsNone(self_ips({}, cache, now=RANGES_MAX_AGE + 1, fetch=failing)[0])
        self.assertIsNone(self_ips({}, None, now=1, fetch=failing)[0])

    def test_token_is_passed(self):
        seen = {}
        self_ips({'GITHUB_TOKEN': 't'}, None, now=1, fetch=lambda token=None: seen.setdefault('t', token) and [])
        self.assertEqual(seen['t'], 't')

    def test_cached_ranges_reads_state(self):
        self.assertIsNone(cached_ranges(''))
        self.assertIsNone(cached_ranges('not json'))
        text = json.dumps({'version': 1, 'gh_ranges': {'at': 5, 'ranges': []}})
        self.assertEqual(cached_ranges(text), {'at': 5, 'ranges': []})

    def test_meta_call_retries_once_and_sends_token(self):
        calls = []

        class Resp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self, *a):
                return b'{"actions": ["198.51.100.0/24"]}'

        def opener(req, timeout):
            calls.append(req.get_header('Authorization'))
            if len(calls) == 1:
                raise OSError('refused')
            return Resp()

        self.assertEqual(github_actions_ranges(opener, token='x'), ['198.51.100.0/24'])
        self.assertEqual(calls, ['Bearer x', 'Bearer x'])


if __name__ == '__main__':
    unittest.main()
