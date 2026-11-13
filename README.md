# platform-security-signals

Attack detection for the bookchaowalit edge, gateway and identity. Every 15 minutes it pulls new
counts from Cloudflare and Railway logs, keeps them in R2 and sends one Telegram message when a
signal opens or resolves. Spec: [docs/specs/001-security-signals.md](docs/specs/001-security-signals.md).

Same pattern as `platform-posture-monitor` and `platform-vuln-digest`: public repository, Python
standard library only, private state in R2, alerts on change only, heartbeat to the uptime Worker.

## Rules

| ID | Signal | Source |
|---|---|---|
| SIG-00 | drop our own traffic (GitHub Actions ranges + `SIGNALS_SELF_IPS`) | all IP sources |
| SIG-01 | 401/403 spike per system (≥ 50 and ≥ 5× the 7-day mean) | Railway gateway logs |
| SIG-02 | token brute force: one IP ≥ 30 × 401 or 429 in 1 h | Cloudflare HTTP on the gateway host |
| SIG-03 | WAF block surge (≥ 200 / 15 min) or blocks on a host new in 30 days | Cloudflare firewall events |
| SIG-04 | Access login from a new country or device | Cloudflare Access |
| SIG-05 | direct calls past the gateway | not wired yet (gateway enforce rollout) |
| SIG-06 | identity token failures (≥ 20 / 15 min) or a known client failing for the first time | identity logs (event not emitted yet) |
| SIG-07 | a source failed or went quiet against its own history | all |

## Run locally

```bash
python -m unittest discover -s tests -t . -v
SIGNALS_IP_KEY=… SIGNALS_CF_TOKEN=… SIGNALS_CF_ZONE_ID=… SIGNALS_CF_ACCOUNT_ID=… \
  python -m security_signals --state-in state.json --state-out state.json --bronze-dir bronze --no-notify
```

`--no-notify` prints the alert text to stderr; it can contain IP addresses, so do not paste it anywhere public.

## Configuration (Actions secrets, source of truth Infisical `/security-signals`)

| Name | What |
|---|---|
| `SIGNALS_IP_KEY` | HMAC key for IP, device and client hashes |
| `SIGNALS_SELF_IPS` | our own egress addresses/CIDRs, comma separated (Railway, Workers, home) |
| `SIGNALS_CF_TOKEN`, `SIGNALS_CF_ZONE_ID`, `SIGNALS_CF_ACCOUNT_ID` | read-only Cloudflare token: Account Analytics Read, Access: Audit Logs Read, Zone Analytics Read |
| `SIGNALS_RAILWAY_GW_TOKEN` / `SIGNALS_RAILWAY_IDP_TOKEN` (or `SIGNALS_RAILWAY_TOKEN`) | Railway project tokens for log reads; the account token is the fallback |
| `SIGNALS_GW_ENV_ID`, `SIGNALS_IDP_ENV_ID` | Railway environment ids |
| `SIGNALS_R2_*` | R2 keys for the bucket `security-signals` only |
| `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`, `HEARTBEAT_TOKEN` | alerts and heartbeat |
| `SIGNALS_IDENTITY_PRIVATE_KEY_PEM` | private key of identity service client `security-signals` (audience `security-api`, scope `audit:write` only); without it audit events wait in the state |
| variable `SIGNALS_KEEP_RAW_IP` | `1` keeps raw IPs under `raw-ip/` for 7 days (owner decision D-2); off by default |

A source with no configuration is reported as `off` and skipped.

## Exit codes

`0` ok · `2` a source or R2 failed (its signals stay open, SIG-07 opens) · `3` Telegram or security-api refused (message or audit event kept, sent next run) · `4` configuration missing.

## Status

Live since 2026-11-12: jobs Worker job `security-signals` (`7-59/15 * * * *`) dispatches `signals.yml`;
uptime heartbeat `security-signals` (2 h). R2 bucket `security-signals` with lifecycle `bronze/` 90 d,
`raw-ip/` 7 d. Sources live: `fw`, `http`, `access` (account-owned read-only Cloudflare token
`security-signals-read`; R2 key = token `security-signals-r2`, that bucket only).

Audit (R11) live since 2026-11-13: every opened or resolved signal is one `security-api` event
`signal.opened|resolved`, target `<rule>.<subject>`, idempotency key per signal lifetime.

Open: `gw` and `idp` need Railway project tokens (Railway refuses project-token creation through the
API, so the owner creates them in the dashboard); identity `token.issue_failed` event (R9); `SIGNALS_SELF_IPS` holds the home address only, Railway and Worker
egress still to add; controlled live test (AC11) and 7 quiet days (AC12).
