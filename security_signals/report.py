"""Telegram message and the counts-only public summary (SPEC-001 R2, R4)."""
import json
from collections import Counter

from .model import SEVERITY_ORDER

ICON = {'high': '🔴', 'medium': '🟠', 'low': '⚪'}
SHOW_IP = {'SIG-02', 'SIG-04'}  # R3: the raw address only where the owner may want to block it
MAX_LINES = 40
MAX_CHARS = 4000


def bound(text):
    return text if len(text) <= MAX_CHARS else text[:MAX_CHARS - 12] + '\n… (cut)'


def _line(s, icon):
    ip = f' ip {s["ip"]}' if s.get('ip') and s['rule'] in SHOW_IP else ''
    return f'{icon} {s["rule"]} {s["detail"]}{ip}'


def _sorted(items):
    return sorted(items, key=lambda s: (SEVERITY_ORDER.get(s['severity'], 9), s['id']))


def message(opened, resolved, open_count, baseline):
    if baseline is not None:
        counts = ', '.join(f'{k} {v}' for k, v in sorted(baseline.items()))
        return bound(f'Security signals baseline: first run, no signals opened. Rows per source: {counts}')
    if not opened and not resolved:
        return None
    head = ', '.join(f'{n} {sev}' for sev, n in sorted(open_count.items(), key=lambda kv: SEVERITY_ORDER.get(kv[0], 9)))
    lines = [f'Security signals: changes (open: {head or "none"})']
    if opened:
        lines.append('\nOpened:')
        lines += [_line(s, ICON.get(s['severity'], '•')) for s in _sorted(opened)]
    if resolved:
        lines.append('\nResolved:')
        lines += [_line(s, '✅') for s in _sorted(resolved)]
    if len(lines) > MAX_LINES:
        lines = lines[:MAX_LINES] + [f'… and {len(lines) - MAX_LINES} more']
    return bound('\n'.join(lines))


def public_summary(rows, sources, open_signals, opened, resolved):
    """Counts only: no address, hash, path, host, country or subject (AC8)."""
    return json.dumps({'rows': rows, 'sources': sources,
                       'open_by_rule': dict(sorted(Counter(s['rule'] for s in open_signals).items())),
                       'opened': len(opened), 'resolved': len(resolved)}, sort_keys=True)
