"""Collectors: Cloudflare GraphQL and Railway logs into normalized rows (SPEC-001 "Sources").

Every collector returns [(bucket start, row)] for [start, end). Rows keep the raw `ip` in memory only;
the hash is what gets stored (R3). A provider problem raises ProviderError; the run then marks only
that source failed (R5).
"""
import json
import urllib.error
import urllib.request
from collections import Counter

from .model import bucket_of, ip_hash, iso, parse_time

CF_GRAPHQL = 'https://api.cloudflare.com/client/v4/graphql'
RAILWAY_GRAPHQL = 'https://backboard.railway.com/graphql/v2'
TIMEOUT = 20  # R6
CF_LIMIT = 10_000
CF_MAX_REQUESTS = 24  # per collector call; past this a full page is kept as is
RAILWAY_LIMIT = 5_000
ACCESS_MAX_SPAN = 7 * 86_400  # Cloudflare refuses a wider Access query (spike)
USER_AGENT = 'platform-security-signals'


class ProviderError(Exception):
    """A source could not be read; the message is an error type only, safe for the public log."""


def _post(url, headers, body, opener):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method='POST',
                                 headers={'Content-Type': 'application/json', 'User-Agent': USER_AGENT, **headers})
    try:
        with opener(req, timeout=TIMEOUT) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as exc:
        raise ProviderError(f'http {exc.code}') from None
    except (OSError, ValueError) as exc:
        raise ProviderError(type(exc).__name__) from None


def _path_prefix(path):
    seg = (path or '/').split('?', 1)[0].lstrip('/').split('/', 1)[0]
    return '/' + seg[:24]


class Cloudflare:
    def __init__(self, token, zone_id, account_id, key, opener=urllib.request.urlopen):
        self.token, self.zone, self.account, self.key, self.opener = token, zone_id, account_id, key, opener
        self.truncated = 0  # full pages kept without splitting further (flood or request budget)
        self.partial = []  # [(start, end)] kept full pages: counts there are a lower bound
        self.skipped = []  # kept for the run's interface; breadth-first splitting never skips a slice

    def _gql(self, query, variables):
        data = _post(CF_GRAPHQL, {'Authorization': f'Bearer {self.token}'}, {'query': query, 'variables': variables},
                     self.opener)
        if data.get('errors'):
            raise ProviderError('graphql error')
        return data.get('data') or {}

    def _zone_rows(self, query, field, start, end, extra=None):
        """Raw or grouped rows for [start, end); a full page is split in two, breadth first.

        Every slice is queried at least once: a split happens only while the request budget still covers
        one request for each slice waiting in the queue plus both halves. So a flood early in the window
        cannot starve later slices (security review on 0ce442a), and nothing is skipped. A full page that
        cannot be split further is kept as is (10 000 blocks still open SIG-03), counted in `truncated` and
        listed in `partial`, so its buckets never resolve a signal.
        """
        queue, done, left = [(start, end)], [], CF_MAX_REQUESTS
        while queue:
            a, b = queue.pop(0)
            left -= 1
            data = self._gql(query, {'z': self.zone, 'a': iso(a), 'b': iso(b), 'n': CF_LIMIT, **(extra or {})})
            zones = (data.get('viewer') or {}).get('zones') or []
            rows = zones[0].get(field) if zones else None
            if rows is None:
                raise ProviderError('no data')
            if len(rows) >= CF_LIMIT:
                if b - a > 60 and left >= len(queue) + 2:
                    mid = (a + b) // 2
                    queue += [(a, mid), (mid, b)]
                    continue
                self.truncated += 1
                self.partial.append((a, b))
            done.append((a, rows))
        return [r for _, rows in sorted(done, key=lambda d: d[0]) for r in rows]

    def firewall(self, start, end):
        q = """query($z:String!,$a:Time!,$b:Time!,$n:Int!){viewer{zones(filter:{zoneTag:$z}){
 firewallEventsAdaptive(limit:$n,filter:{datetime_geq:$a,datetime_lt:$b},orderBy:[datetime_ASC]){
  datetime action source clientRequestHTTPHost clientRequestPath clientCountryName clientIP}}}}"""
        agg = Counter()
        for r in self._zone_rows(q, 'firewallEventsAdaptive', start, end):
            agg[(bucket_of(parse_time(r['datetime'])), r['clientIP'], r['clientRequestHTTPHost'],
                 _path_prefix(r['clientRequestPath']), r['clientCountryName'], r['action'], r['source'])] += 1
        return [(b, {'ip': ip, 'ip_hash': ip_hash(ip, self.key), 'host': host, 'path_prefix': path,
                     'country': country, 'action': action, 'source': source, 'count': n})
                for (b, ip, host, path, country, action, source), n in agg.items()]

    def gateway_http(self, start, end, host):
        q = """query($z:String!,$a:Time!,$b:Time!,$n:Int!,$h:String!){viewer{zones(filter:{zoneTag:$z}){
 httpRequestsAdaptiveGroups(limit:$n,filter:{datetime_geq:$a,datetime_lt:$b,clientRequestHTTPHost:$h,
  edgeResponseStatus_geq:400}){count dimensions{datetimeFifteenMinutes edgeResponseStatus clientIP clientCountryName}}}}}"""
        out = []
        for r in self._zone_rows(q, 'httpRequestsAdaptiveGroups', start, end, {'h': host}):
            d = r['dimensions']
            out.append((bucket_of(parse_time(d['datetimeFifteenMinutes'])),
                        {'ip': d['clientIP'], 'ip_hash': ip_hash(d['clientIP'], self.key),
                         'status': d['edgeResponseStatus'], 'country': d['clientCountryName'], 'count': r['count']}))
        return out

    def access(self, start, end):
        if end - start > ACCESS_MAX_SPAN:  # AC10
            raise ValueError('Access query wider than 1 week')
        q = """query($acc:String!,$a:Time!,$b:Time!,$n:Int!){viewer{accounts(filter:{accountTag:$acc}){
 accessLoginRequestsAdaptiveGroups(limit:$n,filter:{datetime_geq:$a,datetime_lt:$b}){
  count dimensions{datetimeFifteenMinutes isSuccessfulLogin country deviceId ipAddress appId}}}}}"""
        data = self._gql(q, {'acc': self.account, 'a': iso(start), 'b': iso(end), 'n': CF_LIMIT})
        accounts = (data.get('viewer') or {}).get('accounts') or []
        rows = accounts[0].get('accessLoginRequestsAdaptiveGroups') if accounts else None
        if rows is None:
            raise ProviderError('no data')
        if len(rows) >= CF_LIMIT:
            self.truncated += 1  # kept: thousands of login groups is itself what SIG-04 should see
            self.partial.append((start, end))
        out = []
        for r in rows:
            d = r['dimensions']
            device = d.get('deviceId') or ''
            out.append((bucket_of(parse_time(d['datetimeFifteenMinutes'])),
                        {'ip': d['ipAddress'], 'ip_hash': ip_hash(d['ipAddress'], self.key),
                         'success': bool(d['isSuccessfulLogin']), 'country': d['country'] or '?',
                         'device_hash': ip_hash(device, self.key) if device else '', 'app': (d['appId'] or '')[:8],
                         'count': r['count']}))
        return out


class Railway:
    """Structured stdout logs that Railway parsed into attributes (spike: gateway `request.completed`)."""

    def __init__(self, token, project_token=False, opener=urllib.request.urlopen):
        header = {'Project-Access-Token': token} if project_token else {'Authorization': f'Bearer {token}'}
        self.header, self.opener = header, opener

    def logs(self, environment_id, event, start, end):
        """Lines of `event` in [start, end).

        Railway reads `beforeDate` as the lower bound and keeps the newest lines when a page is full
        (spike 2026-11-12), so a full page that does not reach back to `start` is an error, not a cut.
        """
        q = """query($e:String!,$a:String!,$f:String!,$n:Int!){environmentLogs(environmentId:$e,filter:$f,
 afterDate:$a,beforeDate:$a,beforeLimit:$n){timestamp attributes{key value}}}"""
        variables = {'e': environment_id, 'a': iso(start), 'f': f'@event:{event}', 'n': RAILWAY_LIMIT}
        data = _post(RAILWAY_GRAPHQL, self.header, {'query': q, 'variables': variables}, self.opener)
        if data.get('errors'):
            raise ProviderError('graphql error')
        lines = (data.get('data') or {}).get('environmentLogs')
        if lines is None:
            raise ProviderError('no data')
        if len(lines) >= RAILWAY_LIMIT and parse_time(lines[0]['timestamp']) > start:
            raise ProviderError('page full')
        out = []
        for line in lines:
            t = parse_time(line['timestamp'])
            if start <= t < end:
                out.append((t, {a['key']: a['value'] for a in line.get('attributes') or []}))
        return out

    def gateway(self, environment_id, start, end):
        agg = Counter()
        for t, a in self.logs(environment_id, 'request.completed', start, end):
            try:
                status = int(a.get('status', ''))
            except ValueError:
                continue
            if status >= 400:
                agg[(bucket_of(t), a.get('system') or a.get('route') or '?', status)] += 1
        return [(b, {'system': system, 'status': status, 'count': n}) for (b, system, status), n in agg.items()]

    def identity(self, environment_id, start, end):
        agg = Counter()
        for t, a in self.logs(environment_id, 'token.issue_failed', start, end):
            agg[(bucket_of(t), a.get('reason') or '?', a.get('client_hash') or '')] += 1
        return [(b, {'reason': reason, 'client_hash': client, 'count': n}) for (b, reason, client), n in agg.items()]


def github_actions_ranges(opener=urllib.request.urlopen):
    """SIG-00: GitHub Actions egress ranges from the public meta API."""
    req = urllib.request.Request('https://api.github.com/meta', headers={'User-Agent': USER_AGENT,
                                                                         'Accept': 'application/vnd.github+json'})
    try:
        with opener(req, timeout=TIMEOUT) as resp:
            return json.load(resp).get('actions') or []
    except (OSError, ValueError) as exc:
        raise ProviderError(type(exc).__name__) from None
