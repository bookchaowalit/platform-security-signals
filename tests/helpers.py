"""Synthetic rows in the normalized shape the collectors produce (documentation IPs only, RFC 5737)."""
from security_signals.model import BUCKET

T0 = 1_794_441_600  # 2026-11-12T00:00:00Z, a bucket start
KEY = b'test-ip-key'


def b(n):
    """Start of the n-th bucket after T0."""
    return T0 + n * BUCKET


def fw(ip='203.0.113.7', host='app.example.com', path='/.env', action='block', count=1, country='NL'):
    return {'ip': ip, 'ip_hash': 'h' + ip.replace('.', ''), 'host': host, 'path_prefix': path,
            'country': country, 'action': action, 'source': 'firewallCustom', 'count': count}


def http(ip='203.0.113.9', status=401, count=1, country='DE'):
    return {'ip': ip, 'ip_hash': 'h' + ip.replace('.', ''), 'status': status, 'country': country, 'count': count}


def gw(system='habits', status=401, count=1):
    return {'system': system, 'status': status, 'count': count}


def access(success=True, country='TH', device='dev-1', ip='198.51.100.4', app='app-1', count=1):
    return {'ip': ip, 'ip_hash': 'h' + ip.replace('.', ''), 'success': success, 'country': country,
            'device_hash': device, 'app': app, 'count': count}


def idp(reason='invalid_grant', client='c-1', count=1):
    return {'reason': reason, 'client_hash': client, 'count': count}
