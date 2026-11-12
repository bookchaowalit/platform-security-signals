"""Buckets, IP hashing and the self-traffic allowlist (SPEC-001 SIG-00, R3)."""
import hashlib
import hmac
import ipaddress
from datetime import UTC, datetime

BUCKET = 900  # 15 minutes
DAY = 96  # buckets per day
SEVERITY_ORDER = {'high': 0, 'medium': 1, 'low': 2}


def bucket_of(epoch):
    return int(epoch) // BUCKET * BUCKET


def parse_time(text):
    """RFC 3339 (Cloudflare and Railway, with or without fractions) to epoch seconds."""
    text = text.replace('Z', '+00:00')
    if '.' in text:  # Railway sends nanoseconds; datetime takes at most microseconds
        head, rest = text.split('.', 1)
        frac, _, tz = rest.partition('+')
        text = f'{head}.{frac[:6]}+{tz}' if tz else f'{head}.{frac[:6]}'
    return int(datetime.fromisoformat(text).timestamp())


def iso(epoch):
    return datetime.fromtimestamp(int(epoch), UTC).strftime('%Y-%m-%dT%H:%M:%SZ')


def ip_hash(ip, key):
    """HMAC-SHA256 of the address, first 16 hex characters; the raw address is never stored (R3)."""
    return hmac.new(key, ip.encode(), hashlib.sha256).hexdigest()[:16]


class SelfIPs:
    """Our own egress (SIG-00): GitHub Actions ranges plus addresses from SIGNALS_SELF_IPS."""

    def __init__(self, cidrs=(), addresses=()):
        self.networks = []
        for c in [*cidrs, *addresses]:
            try:
                self.networks.append(ipaddress.ip_network(c.strip(), strict=False))
            except ValueError:
                continue
        self.v4 = [n for n in self.networks if n.version == 4]
        self.v6 = [n for n in self.networks if n.version == 6]

    def contains(self, ip):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in n for n in (self.v4 if addr.version == 4 else self.v6))


def drop_self(rows, own):
    return [r for r in rows if not own.contains(r.get('ip', ''))]
