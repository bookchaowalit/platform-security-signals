"""Opened and resolved signals as security-api audit events (SPEC-001 R11).

The job is platform-identity service client `security-signals` (audience `security-api`, scope
`audit:write` only): it signs a short client assertion (RS256, `private_key_jwt`), exchanges it for a
token and appends one event per change through the edge gateway. RS256 is signed with the `openssl`
binary so the package keeps no third-party dependency (R7). Same shape as platform-posture-monitor.
"""
import base64
import hashlib
import json
import os
import re
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
import uuid

from .sources import ProviderError

IDENTITY = 'https://identity-api-production-fad1.up.railway.app'  # the token endpoint is not behind the gateway
SECURITY_API = 'https://gateway.bookchaowalit.com/v1/platform-security'
CLIENT_ID = 'security-signals'
USER_AGENT = 'security-signals/1'
TARGET = re.compile(r'[a-z][a-z0-9_.-]{0,63}')  # security-api identifier rule


def _b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def assertion(client_id, token_url, private_key_pem, now=None):
    now = int(now if now is not None else time.time())
    header = _b64(json.dumps({'alg': 'RS256', 'typ': 'JWT'}).encode())
    claims = _b64(json.dumps({'iss': client_id, 'sub': client_id, 'aud': token_url, 'iat': now,
                              'exp': now + 120, 'jti': str(uuid.uuid4())}).encode())
    signing_input = f'{header}.{claims}'
    fd, path = tempfile.mkstemp()
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(private_key_pem)
        sig = subprocess.run(['openssl', 'dgst', '-sha256', '-sign', path], input=signing_input.encode(),
                             capture_output=True, check=True).stdout
    finally:
        os.unlink(path)
    return f'{signing_input}.{_b64(sig)}'


def event_target(signal_id):
    """`<rule>.<subject>` in security-api's identifier alphabet, else `<rule>.h<hash>`.

    Subjects are hashes, system names or source names already (R3), never a raw IP.
    """
    rule, _, subject = signal_id.partition(':')
    readable = f'{rule}.{subject}'.lower() if subject else rule.lower()
    if TARGET.fullmatch(readable):
        return readable
    return f'{rule.lower()}.h{hashlib.sha256(signal_id.encode()).hexdigest()[:16]}'


def idempotency_key(event):
    """One key per signal lifetime and change: `at` is the bucket the signal opened in, so a retried
    run never duplicates and a signal that reopens later is a new event."""
    basis = f'{event["change"]}\n{event["id"]}\n{event["at"]}'
    return 'signals-' + hashlib.sha256(basis.encode()).hexdigest()


def _call(req):
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.load(resp)
    except Exception as exc:  # noqa: BLE001  only the endpoint and error type leave this function
        raise ProviderError(f'{urllib.parse.urlsplit(req.full_url).path}: {type(exc).__name__}') from None


def service_token(private_key_pem):
    form = urllib.parse.urlencode({
        'grant_type': 'client_credentials',
        'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        'client_assertion': assertion(CLIENT_ID, f'{IDENTITY}/v1/token', private_key_pem),
        'audience': 'security-api', 'scope': 'audit:write'}).encode()
    req = urllib.request.Request(f'{IDENTITY}/v1/token', data=form,
                                 headers={'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': USER_AGENT})
    return _call(req)['access_token']


def post_event(body, key, token):
    req = urllib.request.Request(f'{SECURITY_API}/v1/audit', method='POST', data=json.dumps(body).encode(),
                                 headers={'Authorization': f'Bearer {token}', 'Content-Type': 'application/json',
                                          'User-Agent': USER_AGENT, 'Idempotency-Key': key})
    _call(req)


class AuditSink:
    def __init__(self, token, post=post_event):
        self.token, self.post = token, post

    def __call__(self, events):
        """Post events in order; return the ones not posted (from the first failure on)."""
        if not events:
            return []
        try:
            token = self.token()
        except (ProviderError, subprocess.CalledProcessError, OSError, KeyError):
            return list(events)  # identity down or the key unusable: retry next run (R8)
        for n, event in enumerate(events):
            try:
                self.post({'action': f'signal.{event["change"]}', 'target': event_target(event['id'])},
                          idempotency_key(event), token)
            except ProviderError:
                return list(events[n:])
        return []
