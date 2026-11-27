# 01 — Business process (As-Is / To-Be)

platform-security-signals คือ job ตรวจจับการโจมตีบน edge, gateway และ identity: ทุก 15 นาทีดึงตัวเลขจาก Cloudflare และ Railway logs เก็บใน R2 ประเมินกฎ SIG-00…SIG-07 แล้วส่ง Telegram ให้ owner เฉพาะตอน signal เปิดหรือปิด พร้อม audit event ไป `security-api`

Last reviewed: 2026-11-28 · commit `275cb2f`

## As-Is (จากโค้ดวันนี้)

```mermaid
flowchart TD
  JW["platform-jobs-worker job security-signals (every 15 min)"] -->|workflow_dispatch| WF["signals.yml (GitHub Actions, timeout 8 min)"]
  WF --> GET["r2 get state/state.json"]
  GET --> CFG{"collectors configured from env?"}
  CFG -->|"SIGNALS_CF_TOKEN set"| CF["Cloudflare GraphQL: fw (firewall), http (gateway 4xx), access (logins)"]
  CFG -->|"Railway token + env id set"| RW["Railway environmentLogs: gw (gateway), idp (token.issue_failed)"]
  CFG -->|"not set"| OFF["source reported off, skipped"]
  CF --> SELF["SIG-00: drop self IPs (SIGNALS_SELF_IPS; GitHub Actions ranges only for http)"]
  RW --> SELF
  SELF --> HASH["HMAC IP / device / client hashes; new 15-min buckets since cursor (max 24 h)"]
  HASH --> RULES["rules SIG-01..SIG-04, SIG-06, SIG-07 (SIG-05 has no collector)"]
  RULES --> DIFF{"signal opened or resolved?"}
  DIFF -->|no| SUM["counts-only step summary"]
  DIFF -->|yes| TG["Telegram message (raw IP only for SIG-02/SIG-04)"]
  TG --> AUD["security-api /v1/audit signal.opened / resolved (client_credentials, audit:write)"]
  AUD --> SUM
  SUM --> PUT["r2 put-dir bronze/, then put state only if all bronze landed"]
  PUT --> HB["heartbeat to uptime Worker (hourly if ok, always if failed)"]
  TG -->|"refused"| KEEP["kept in state, exit 3, sent next run"]
  KEEP --> PUT
```

Sources: `.github/workflows/signals.yml`, `security_signals/run.py` (`run`, `collectors_from_env`, `self_ips`), `security_signals/sources.py` (`Cloudflare`, `Railway`), `security_signals/rules.py`, `security_signals/engine.py`, `security_signals/audit.py`, `security_signals/r2.py`, `README.md` §Status

ข้อเท็จจริงจากโค้ด:

- `collectors_from_env` ไม่มี collector ของ `bypass` (SIG-05) ใน v1 (`# 'bypass' has no collector in v1 (fed by WS3 later)`) กฎ `_sig05` มีแล้วแต่ไม่มีข้อมูลเข้า
- `gw` และ `idp` รันเฉพาะเมื่อมี Railway token และ environment id; README §Status บอกว่ายังรอ project tokens จาก owner ว่า production ใช้ account token แทนอยู่หรือไม่ [ต้องยืนยัน]
- state เก็บเป็นไฟล์เดียว `state/state.json` (ตาม `signals.yml`) ไม่ใช่สามไฟล์ตาม §Storage layout ของ spec
- exit code: `0` ok, `2` source หรือ R2 ล้ม, `3` Telegram หรือ security-api ปฏิเสธ, `4` config ขาด

## To-Be (`docs/specs/001-security-signals.md`, status draft-for-review)

```mermaid
flowchart TD
  JW["platform-jobs-worker job security-signals (every 15 min)"] -->|workflow_dispatch| WF["signals.yml"]
  WF --> CF["Cloudflare: fw, http, access"]
  WF --> RW["Railway project tokens: gw, idp"]
  WF --> BY["bypass feed from gateway enforce rollout (WS3)"]
  CF --> SELF["SIG-00 self-traffic filter"]
  RW --> SELF
  BY --> SELF
  SELF --> RULES["rules SIG-01..SIG-07 all fed"]
  RULES --> DIFF{"signal opened or resolved?"}
  DIFF -->|yes| TG["Telegram"]
  TG --> AUD["security-api audit event"]
  DIFF -->|no| SUM["counts-only summary"]
  AUD --> SUM
  SUM --> PUT["R2 bronze + state"]
  PUT --> HB["heartbeat; AC11 live test passed, AC12 7 days at most 1 false alert per day"]
```

Sources: `docs/specs/001-security-signals.md` (§Sources, §Rules, R1, R10, R11, §Acceptance criteria, §Open items)

## Gap

| ID | As-Is → To-Be | Status | Owner | Evidence |
|---|---|---|---|---|
| G1 | SIG-05 (gateway bypass) มีกฎแต่ไม่มี collector → ป้อนข้อมูลจาก gateway enforce rollout (WS3) | blocked | claude | `security_signals/run.py` `collectors_from_env`; `README.md` §Rules SIG-05 "not wired yet" |
| G2 | source `gw` และ `idp` ยังไม่มี Railway project tokens → project tokens ต่อ project (R1, O-7) | blocked | owner | `README.md` §Status "Open"; spec §Open items O-7 |
| G3 | ยังไม่ได้ทำ live test แบบควบคุม → AC11 ผ่าน (SIG-02 และ SIG-03 เข้า Telegram ภายใน 30 นาที แล้วปิดเอง) | todo | owner | spec AC11; `README.md` §Status |
| G4 | ยังไม่มีหลักฐาน 7 วันเงียบ → AC12: heartbeat ok 7 วัน, false alert ไม่เกิน 1 ต่อวัน | doing | claude | spec AC12, §First live day (2026-11-13) |
| G5 | D-2 (เก็บ raw IP 7 วันหรือ hash อย่างเดียว) ยังเป็น open item; variable `SIGNALS_KEEP_RAW_IP` ปิดเป็นค่าเริ่มต้น → owner ตัดสิน | decide | owner | spec §Open items D-2; `README.md` §Configuration |
| G6 | spec ยังเป็น `draft-for-review` → owner อนุมัติ spec | decide | owner | `docs/specs/001-security-signals.md` front matter |
| G7 | spec §Storage layout บอก `cursors.json`, `signals.json`, `baselines.json` แต่โค้ดใช้ `state/state.json` ไฟล์เดียว → spec ตรงกับโค้ด | todo | claude | `.github/workflows/signals.yml`; spec §Storage layout |

## Open questions

- ตอนนี้ `gw` / `idp` รันใน job อยู่หรือไม่ (ด้วย account token ชั่วคราว) หรือปิดอยู่ทั้งคู่
- threshold ปรับแล้วหลังรัน 7 วันหรือยัง (spec §Open items บอกให้บันทึกการเปลี่ยนไว้ใน spec)
