---
title: "SPEC-001 Security signals: attack detection on the edge, gateway and identity"
status: draft-for-review
created: 2026-11-12
owner: bookchaowalit
plan: knowledge store plans/security-gaps/PLAN.md (WS2)
evidence: knowledge store plans/security-gaps/SPIKE-WS2.md
description: Every 15 minutes, read security-relevant counts from Cloudflare, Railway gateway logs and identity, keep them in R2 and alert once when an attack pattern opens or resolves.
---

# SPEC-001 Security signals

## Problem

Protection is layered (WAF custom rule, rate limit, gateway RS256 + origin lock, Access, posture
monitor, uptime, Sentry), but nothing watches for attacks. Uptime catches "down", Sentry catches
"error", posture-monitor catches "misconfigured". Nobody sees "someone is trying to get in".

The spike on 2026-11-12 found, in 24 hours: 424 blocked requests on the zone (WAF custom 267,
rate limit 135, managed 14) from 32 IPs in 12 countries, mostly probing `/.git`, `/.env` and
`/.github`; and on the gateway 112 × 401, 16 × 403 and 377 × 429. The data exists. Nobody reads it.

## Outcome

Every 15 minutes a job collects counts from four sources, stores them in R2, evaluates rules
SIG-00…SIG-07 and sends one Telegram message only when a signal opens or resolves. Each change is
also a `security-api` audit event. A missed or silent run alerts through the uptime Worker
heartbeat `security-signals`.

## Sources (verified in the spike)

| Source | API | Limits found |
|---|---|---|
| `cf-firewall` | Cloudflare GraphQL `firewallEventsAdaptive` (raw rows) | Free plan: raw rows only (`firewallEventsAdaptiveGroups` is refused), ≥ 30 days look-back, 10 000 rows per query |
| `cf-http` | Cloudflare GraphQL `httpRequestsAdaptiveGroups`, host `gateway.bookchaowalit.com`, status ≥ 400, by status × clientIP × country | ≥ 8 days look-back |
| `cf-access` | Cloudflare GraphQL `accessLoginRequestsAdaptiveGroups` (account) by isSuccessfulLogin × country × deviceId × appId | one query may span at most 1 week |
| `gw-app` | Railway GraphQL `environmentLogs(filter:"@event:request.completed")` on project `platform-api-gateway`, attributes `status route system subject_hash` | ~1 000 lines ≈ 9 h per call; page by `beforeDate` |
| `idp` | Railway logs of identity, event `token.issue_failed` | live since 2026-11-13: platform-identity SPEC-007 (`docs/TOKEN-FAILURE-EVENT.md`, 6bac1f6) |

## Rules (v1)

All windows are evaluated on 15-minute buckets. Self traffic (SIG-00) is removed before any other rule.

| ID | Signal | Source | Opens when | Resolves when | Severity |
|---|---|---|---|---|---|
| SIG-00 | self-traffic filter (not alerting) | all | an IP is in the allowlist: GitHub Actions ranges from `https://api.github.com/meta`, `SIGNALS_SELF_IPS` secret (Railway egress, Worker egress, home IP) | — | — |
| SIG-01 | auth failure spike | `gw-app` + `cf-http` | 401+403 on one `system` in 15 min ≥ 50 **and** ≥ 5× its 7-day 15-min mean | 4 buckets in a row below the open threshold | high |
| SIG-02 | token brute force | `cf-http` | one non-self IP-hash gets ≥ 30 × 429 or ≥ 30 × 401 on the gateway within 1 h | 1 h without it | high |
| SIG-03 | scanning / WAF surge | `cf-firewall` | ≥ 200 blocks in 15 min, **or** blocks on a host that had none in the previous 30 days | 4 quiet buckets | medium |
| SIG-04 | new Access login origin | `cf-access` | a successful login from a country or deviceId not seen in the 30-day baseline (R2) | operator acknowledges via state file, or 7 days | high |
| SIG-05 | gateway bypass | `gw-app` + service logs | any direct call (assertion missing) to a service in `enforce`, or > 0 per day on a service in `report` (fed by WS3) | 24 h without it | medium (`enforce`: high) |
| SIG-06 | identity failures | `idp` | ≥ 20 `token.issue_failed` in 15 min, or a `client_id` not seen in 30 days | 4 quiet buckets | high |
| SIG-07 | collector silent | all | a source returns an error or zero rows where it had > 0 in the same hour of the previous 7 days, for 1 h | next good pull | medium |

Signal id: `<rule>:<subject>` (subject = system, host, IP-hash, country or client_id hash), so one
attacker on two systems is two signals and repeated pulls of the same attack do not re-alert.

## Requirements

- **R1 Read-only.** Cloudflare token `CF_SIGNALS_TOKEN` holds only Account Analytics Read,
  Access: Audit Logs Read and Zone Analytics Read on bookchaowalit.com (owner action O-6). Railway
  access uses project tokens of the gateway and identity projects (O-7); if the owner accepts the
  account token instead, that is recorded as an accepted risk in the ADR. R2 credentials cover one
  bucket, `security-signals`. The job never changes any system.
- **R2 Public log stays quiet.** The repository is public. Job log and step summary print only
  counts per source and rule and the exit status. No IP, IP-hash, path, host, country,
  subject or client id. Details go only to Telegram and to `security-api`.
- **R3 Personal data (PDPA).** IPs are stored as HMAC-SHA256 with key `SIGNALS_IP_KEY`
  (Infisical `/security-signals`). Raw IPs are kept only under `raw-ip/` for 7 days for
  investigation if the owner chooses D-2 = keep; otherwise never written. The Telegram message
  shows the raw IP only for SIG-02/SIG-04, so the owner can block it. Bronze retention 90 days
  (R2 lifecycle rule), state and baselines kept.
- **R4 Alert on change.** One message per run listing opened signals highest severity first
  and resolved ones; nothing when nothing changed. The first run (no state) sends one baseline
  message with counts per rule and writes baselines; it does not open signals.
- **R5 Fail loudly, never resolve on failure.** If any source fails, its rules are skipped,
  their open signals stay open, the other sources still run, SIG-07 counts the failure,
  the heartbeat reports `ok: false` and the run exits 2. A partial pull never resolves a signal.
- **R6 Bounded and incremental.** Each source keeps a cursor (last bucket end) in R2 and
  pulls only new 15-minute buckets, at most 24 h back after an outage (firewall and Access
  allow 7 days; the job never asks Access for more than 1 week). Each call 20 s timeout. A run
  finishes within 3 minutes.
- **R7 Standard library only,** as posture-monitor and vuln-digest. Python 3.12, `urllib`, `hmac`.
- **R8 Undelivered alerts are kept.** A message Telegram refused stays in the state and is sent
  first next run; the run exits 3. An audit event `security-api` refused is retried the same way.
- **R9 Identity event.** `platform-identity` emits one stdout JSON line per failed token request:
  `{"event":"token.issue_failed","grant_type":…,"reason":<invalid_client|invalid_grant|invalid_scope|unauthorized_client|rate_limited>,"client_hash":<HMAC of client_id>}`.
  No secret, assertion, scope list or IP. Done in its own worktree with its own SPEC entry and tests;
  the gateway needs no change (spike).
- **R10 Runs from the jobs Worker.** Job `security-signals` in `platform-jobs-worker`
  (`*/15 * * * *`) dispatches the GitHub workflow; the workflow has no `schedule:` of its own
  (Workers Free allows 5 cron triggers per account; ADR-0008).
- **R11 Audit.** Each opened or resolved signal is one `security-api` `/v1/audit` event
  (`signal.opened|resolved`, target `<rule>.<subject>`), via the gateway with the service client
  `security-signals` (identity `client_credentials`, scope `audit:write`).

## Storage layout (R2 bucket `security-signals`)

```
bronze/<source>/dt=YYYY-MM-DD/<bucket-end>.jsonl   # aggregated counts only, IP hashed (90 d)
raw-ip/dt=YYYY-MM-DD/<bucket-end>.jsonl            # only if D-2 = keep (7 d)
state/cursors.json                                  # last bucket per source
state/signals.json                                  # open signals + undelivered messages
state/baselines.json                                # 7-day means, 30-day seen countries/devices/hosts/clients
```

## Acceptance criteria

- AC1 SIG-00: an event from a GitHub Actions range or a `SIGNALS_SELF_IPS` address never counts toward any rule.
- AC2 SIG-01 opens only when both the absolute (≥ 50) and relative (≥ 5× mean) thresholds hold; it resolves after 4 buckets below.
- AC3 SIG-02: 30 × 401 from one non-self IP within 1 h opens one signal; the same IP in the next pull does not re-alert.
- AC4 SIG-03: 250 blocks on `/.env` in 15 min opens a signal; blocks on a host first seen today open one even below 200.
- AC5 SIG-04: a successful login from a new country opens a signal; a failed one does not.
- AC6 SIG-07: a source that errors keeps its open signals open, opens SIG-07 and makes the run exit 2.
- AC7 Diffing previous and current open signals yields exactly the opened and resolved sets; an unchanged set yields no message.
- AC8 The public summary contains no IP, hash, path, host, country or subject.
- AC9 Cursors make two runs over the same bucket produce the same bronze file and no duplicate signals (idempotent).
- AC10 Access queries never span more than 7 days; after a 3-day outage the job catches up at most 24 h.
- AC11 Live test (controlled): 30 requests with a forged token from one outside IP → SIG-02 in Telegram within 30 min; 250 requests to `/.env` → SIG-03; both resolve on their own.
- AC12 Phase A done: 7 days with heartbeat ok and at most 1 false alert per day.

## Test plan

Unit tests per rule from fixtures captured in the spike shape (counts only, synthetic IPs);
red/green log per ADR-0004. Contract tests for the four GraphQL/Railway query shapes with
recorded responses. The live test AC11 runs from a laptop hotspot (outside every allowlist),
announced in Telegram first.

## Out of scope (v1)

Blocking automatically (the job only reports; the owner adds WAF rules), Railway cell logs and
GitHub signals (phase B), homelab logs (phase C), any always-on service, SIEM or BI server
(ADR-0013), gateway code changes.

## Open items

- O-6 Cloudflare read-only token, O-7 Railway project tokens (owner).
- D-2 keep raw IPs 7 days (recommended) or hashes only.
- Thresholds are first guesses from one day of data; tune after the 7-day run (AC12) and record changes here.

## Changes during build (2026-11-12)

- SIG-06 "client not seen in 30 days" counts only failures where the client exists
  (`invalid_grant`, `invalid_scope`, `unauthorized_client`). `invalid_client` comes from random ids an
  attacker sends, and counting it would open one signal per guess. The surge rule still counts every reason.
- SIG-02 and SIG-04 have a `hold` of 4 buckets and 7 days; SIG-05 one day; SIG-07 resolves on the next good pull.
- Railway `environmentLogs` reads `beforeDate` as the lower bound and keeps the newest lines when a page is
  full (5 000 lines; about 2 500 per day today). The collector asks from the range start and fails the source
  when a full page does not reach back to it, so no lines are lost without notice.
- An Access device id is often empty (no WARP); empty devices are not tracked.
- Exit code 4 added for missing configuration.
- First live dry run (24 h, no Telegram): 424 firewall rows, 858 gateway HTTP errors, 568 gateway app errors,
  0 Access logins. A replay without baseline opened one SIG-02 from a Thai address (likely our own testing):
  the home IP must be in `SIGNALS_SELF_IPS` before going live.

## Changes after review (2026-11-12)

Independent Codex review and the automated security review of 817db1d found six issues; all fixed:

- A refused Telegram message is kept for retry **without** raw IPs (R3); only the copy sent at once shows them.
- The workflow writes state only after every bronze object landed, so cursors never pass unstored buckets.
- "Seen in 30 days" is checked against the bucket being evaluated, not only by the end-of-run trim
  (an outage longer than the remaining age no longer hides a new country, device, host or client).
- A first run that already has a failing source reports its SIG-07 in the baseline message.
- SIG-00 scope: anyone can run code on GitHub Actions, so its ranges only filter the gateway HTTP source
  (SIG-02); firewall events use only `SIGNALS_SELF_IPS` and Access logins are never filtered.
- A flood can fill a Cloudflare page. A page that cannot be split, or a split past the 24-request budget,
  is kept (or skipped) and reported as `SIG-07:<source>-capacity` and `truncated` in the summary, instead of
  failing the source and blinding the rules that should fire.
- Second review round (929936b): a cut page must not count as calm. Buckets with a kept full page are
  `partial`: signals may open there, nothing resolves, SIG-07 "quiet" is not judged, and open signals of
  that source restart their hold from the last cut bucket. `SIG-07:<source>-capacity` is `high` and stays open
  until a pull without cuts.
- Third review round (b76d295): a slice skipped for the request budget no longer stops the cursor. Stalling
  dropped the rows already pulled in that bucket and let one flooded bucket blind every later one. Skipped
  slices now make their buckets partial too (rows kept and evaluated, nothing resolves) and the cursor moves
  on; the skipped rows are lost, and the capacity signal says so. SIG-07 "quiet" needs a complete hour: cut
  buckets are kept in state (`partial` series, 1 h) and any cut bucket in the window blocks the judgement.
- Fourth round (0ce442a, security review): skipped slices were lost for good. Cloudflare pages are now split
  breadth first and a split happens only while the budget still covers one request for every queued slice,
  so every part of the window is queried at least once and nothing is skipped. Under a flood above 10 000
  events per slice the counts stay a lower bound (partial buckets, capacity signal); a backfill of those
  slices was considered and left out, because the sampled rows already open the signals that matter.
- Fifth round (9c05d7f): `partial` markers are trimmed against each source's own cursor, so a source that
  keeps failing still has them when it catches up. Heartbeats: every POST is one KV write on the uptime
  Worker (free plan, 1 000 a day, shared with every other job), so a good run reports once an hour (the
  :07 slot) and a failed run always reports; 24 writes a day instead of 96.
- Sixth round (72a113a): SIG-07 resolves only after a complete hour with rows or a good pull and no cut
  bucket left in the 1-hour window; a clean bucket next to a cut one proves nothing.

### R11 built (2026-11-13)

- identity service client `security-signals` registered in identity-api `IDENTITY_SERVICE_CLIENTS_JSON`
  (system workspace, own random subject, audience `security-api`, scope `audit:write` only; checked with
  identity's own parser, then a redeploy of the same commit `ab9645e`). Private key (RSA 3072) and subject
  live only in Infisical `/security-signals` and the Actions secret `SIGNALS_IDENTITY_PRIVATE_KEY_PEM`.
- `engine` queues `{change, id, at}` in the state (`audit`, at most 500, oldest dropped) whenever a signal
  opens or resolves; `at` is the bucket it opened in, so the idempotency key is stable across retries and a
  reopened signal is a new event. The run posts the queue after Telegram; refused events stay and the run
  exits 3 (R8). Local `--no-notify` runs keep the queue and post nothing.
- Live check: a token (600 s, aud `security-api`, scope `audit:write`) and one `signal.selftest` event
  `sig-00.wiring` were accepted through the gateway.
- Review round on 36c4ba3: the audit drain posts at most 100 events and spends at most 90 s per run (the
  rest waits), so a backlog can never run the 8-minute job out before it writes state. SIG-07 for a failed
  pull and for a capacity cut now opens in a bucket that follows the cursor (`start` / first cut bucket),
  so a replay after a lost state write reuses the same audit idempotency key instead of a second
  `signal.opened`.
- Security review on aa70a27: a burst of opens larger than the queue used to lose the oldest events
  silently. The queue now holds 2 000 events; past that the oldest still go, but a `signal.dropped` event
  `sig-07.audit-dropped-<running total>` takes their place and is posted first, and the run summary shows
  `audit_dropped`.
- Review round on 3a0c351: the capacity signal opens at the pull's `start` (from the stored cursor), not
  the first cut bucket, because page splits change with the window length on a replay. The audit queue is
  bounded before the run summary, so `audit_pending` / `audit_dropped` match the state that is written.
- Review round on 47a493f: after an outage longer than 24 h the capped window start moves with the clock,
  so SIG-07 (failed pull, capacity) is anchored to the stored cursor instead. A source with no cursor yet
  has nothing stored to anchor to and uses its window start (a lost first state write can repeat one event).

### R9 built (2026-11-13)

- platform-identity SPEC-007 (6bac1f6, deployed): every 4xx `/v1/token` answer writes one stdout JSON
  line `{"event":"token.issue_failed","level":"warning","grant_type","reason","client_hash"}`. Reasons are
  the OAuth error codes plus `rate_limited` (the 429); `client_hash` is an HMAC only for a registered
  client, else `""`. The reason set is wider than this spec first listed (`invalid_request`,
  `invalid_target`, `unsupported_grant_type` added); SIG-06 counts every reason and judges the "new
  client" case on `invalid_grant|invalid_scope|unauthorized_client` as before.
- Railway returns every parsed attribute JSON-encoded (`"habits"` with its quotes, `401`). The collector
  now decodes them; without that SIG-01 system names carried quotes and no SIG-06 reason ever matched.
- Live check: two refused requests (forged assertion, unknown grant) read back through the collector as
  `invalid_client` (hashed) and `unsupported_grant_type` (no hash) in the same bucket.
- The `idp` and `gw` sources still need the Railway project tokens (O-7) to run in the job.
- Security review on 7cd5713: a gateway `status` that is not an integer (NaN, Infinity, floats, objects)
  is skipped instead of raising, JSON constants stay text, and any unexpected collector exception fails
  only its own source (`internal <type>`, SIG-07) so one broken source can never stop the run.

### First live day (2026-11-13)

- No alert came from our own traffic (no SIG-02/SIG-03 in ~33 h). SIG-07 "quiet" on `fw` opened and
  resolved about ten times: firewall events are sparse (rows in 29 of ~130 buckets) and the rule fired when
  the same hour had rows on *any* of the previous 7 days. It now needs rows in that hour on at least 4 of
  the previous 7 days (`QUIET_MIN_DAYS`), so it only judges hours that are normally busy and stays silent
  during the first 4 days of history. Pull failures still open SIG-07 at once.
- `SIGNALS_SELF_IPS` stays the home address only. Railway (no static egress on this plan) and Workers
  egress are shared provider ranges: allowlisting them would also hide any attacker running on Railway or
  Workers, the same reason the GitHub Actions ranges only filter `http`. Revisit only if a real false alert
  traces back to our own egress.
