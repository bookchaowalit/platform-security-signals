"""State and bronze objects on R2 over the S3 API, SigV4 with the standard library only (SPEC-001 R1, R7).

    python -m security_signals.r2 get <key> <file>     # a missing object leaves <file> absent, exit 0
    python -m security_signals.r2 put <key> <file>
    python -m security_signals.r2 put-dir <dir>        # every file under <dir>, key = its relative path

Same signer as platform-vuln-digest. Credentials cover the one bucket `security-signals`.
"""
import hashlib
import hmac
import os
import sys
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote, urlsplit

BUCKET = 'security-signals'


def _hmac(key, msg):
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def signed_request(method, endpoint, bucket, key, access_key, secret_key, body=b'', now=None):
    now = now or datetime.now(UTC)
    amz_date, day = now.strftime('%Y%m%dT%H%M%SZ'), now.strftime('%Y%m%d')
    host = urlsplit(endpoint).netloc
    path = f'/{bucket}/{quote(key, safe="/")}'
    payload_hash = hashlib.sha256(body).hexdigest()
    headers = {'host': host, 'x-amz-content-sha256': payload_hash, 'x-amz-date': amz_date}
    signed = ';'.join(sorted(headers))
    canonical = '\n'.join([method, path, '', *(f'{k}:{headers[k]}' for k in sorted(headers)), '', signed,
                           payload_hash])
    scope = f'{day}/auto/s3/aws4_request'
    to_sign = '\n'.join(['AWS4-HMAC-SHA256', amz_date, scope, hashlib.sha256(canonical.encode()).hexdigest()])
    k = _hmac(_hmac(_hmac(_hmac(f'AWS4{secret_key}'.encode(), day), 'auto'), 's3'), 'aws4_request')
    signature = hmac.new(k, to_sign.encode(), hashlib.sha256).hexdigest()
    headers['Authorization'] = (f'AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed}, '
                                f'Signature={signature}')
    del headers['host']
    return urllib.request.Request(endpoint + path, data=body if method == 'PUT' else None, method=method,
                                  headers=headers)


def _creds(env, key):
    return (env['SIGNALS_R2_ENDPOINT'], BUCKET, key, env['SIGNALS_R2_ACCESS_KEY_ID'], env['SIGNALS_R2_SECRET_ACCESS_KEY'])


def put(env, key, body, opener=urllib.request.urlopen):
    opener(signed_request('PUT', *_creds(env, key), body=body), timeout=30).close()


def main(argv=None, env=os.environ):
    argv = argv or sys.argv[1:]
    op = argv[0]
    try:
        if op == 'get':
            key, path = argv[1:]
            try:
                with urllib.request.urlopen(signed_request('GET', *_creds(env, key)), timeout=30) as resp:
                    data = resp.read()
            except urllib.error.HTTPError as exc:
                if exc.code == 404:
                    return 0
                raise
            Path(path).write_bytes(data)
        elif op == 'put':
            key, path = argv[1:]
            put(env, key, Path(path).read_bytes())
        elif op == 'put-dir':
            root = Path(argv[1])
            files = sorted(p for p in root.rglob('*') if p.is_file()) if root.exists() else []
            for p in files:
                put(env, p.relative_to(root).as_posix(), p.read_bytes())
            print(f'{len(files)} objects written')
        else:
            raise SystemExit(f'unknown operation {op}')
    except (OSError, urllib.error.URLError) as exc:
        print(f'r2 {op} failed: {type(exc).__name__}', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
