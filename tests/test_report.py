"""Telegram message and counts-only public summary (R2, R4, AC7, AC8)."""
import json
import unittest

from security_signals.report import message, public_summary

OPEN = {'id': 'SIG-02:h2030113', 'rule': 'SIG-02', 'subject': 'h2030113', 'severity': 'high',
        'detail': '40× 401 in 1 h on the gateway (DE)', 'ip': '203.0.113.9'}
GONE = {'id': 'SIG-03:zone', 'rule': 'SIG-03', 'subject': 'zone', 'severity': 'medium',
        'detail': '250 blocks in 15 min, top path /.env'}


class Message(unittest.TestCase):
    def test_nothing_changed_sends_nothing(self):
        self.assertIsNone(message([], [], open_count={}, baseline=None))

    def test_lists_opened_with_ip_and_resolved(self):
        text = message([OPEN], [GONE], open_count={'high': 1}, baseline=None)
        self.assertIn('203.0.113.9', text)
        self.assertIn('SIG-02', text)
        self.assertIn('✅ SIG-03', text)

    def test_ip_is_shown_only_for_sig02_and_sig04(self):
        other = dict(OPEN, id='SIG-03:x', rule='SIG-03')
        self.assertNotIn('203.0.113.9', message([other], [], open_count={}, baseline=None))

    def test_baseline_message(self):
        text = message([], [], open_count={}, baseline={'fw': 424, 'http': 860})
        self.assertIn('baseline', text)
        self.assertIn('424', text)

    def test_high_before_medium(self):
        med = dict(GONE, id='SIG-03:zone')
        text = message([med, OPEN], [], open_count={}, baseline=None)
        self.assertLess(text.index('SIG-02'), text.index('SIG-03'))


class PublicSummary(unittest.TestCase):  # AC8
    def test_counts_only(self):
        out = public_summary(rows={'http': 12}, sources={'http': 'ok', 'gw': 'failed'},
                             open_signals=[OPEN, GONE], opened=[OPEN], resolved=[GONE])
        for leak in ('203.0.113.9', 'h2030113', '/.env', 'DE', 'zone'):
            self.assertNotIn(leak, out)
        data = json.loads(out)
        self.assertEqual(data['open_by_rule'], {'SIG-02': 1, 'SIG-03': 1})
        self.assertEqual(data['sources'], {'http': 'ok', 'gw': 'failed'})


if __name__ == '__main__':
    unittest.main()
