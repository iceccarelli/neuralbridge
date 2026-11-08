# Platform status

Industrial Autonomous Assurance is built on NeuralBridge, a smaller
integration layer in this same repository: a FastAPI backend, an MCP
gateway for AI tool exposure, and a small set of adapters whose supported
scope is intended, not yet claimed. This page states plainly what is
supported today versus still evolving. The table is the README's table,
word for word, and the [homepage](https://neuralbridge.io/#platform) shows
the same rows; `tests/test_site_honesty.py` fails if the three differ.

| Area | Status |
|---|---|
| FastAPI backend | **Supported** |
| Connection management model | **Supported as a core direction** |
| MCP tool listing / invocation layer | **Supported** |
| Customer workspace (the Next.js site: /assurance, /console, /ai, reading the real APIs) | **Experimental / evolving** |
| Basic audit trail (durable, append-only, hash-chained SQLite by default) | **Experimental / evolving** |
| Small set of working adapters | **Intended supported scope** |
| Broad adapter ecosystem | **Experimental / evolving** |
| Full enterprise compliance posture | **Not part of the core promise yet** |
| Full zero-trust posture | **Not part of the core promise yet** |
| Immutable enterprise-grade audit guarantees | **Not part of the core promise yet** |
| No-code enterprise deployment for any system | **Too broad for the current promise** |

What "small set of working adapters" means today: PostgreSQL and REST are the candidates. PostgreSQL has been exercised against a real server only by the /ai control-plane and MCP tests (they skip without one). The REST adapter sends real HTTP requests, bounded by SSRF refusal, size, time and redirect limits, and is tested only against a local HTTP server that its own test starts (tests/test_rest_adapter.py); it has not been run against any third-party API.

No enterprise certification or compliance attestation is held.

**Audit trail, as the code now is.** The platform audit trail defaults to a durable, append-only SQLite file (`neuralbridge-audit.db` next to the /ai store; `NEURALBRIDGE_AUDIT_DB` overrides; PostgreSQL via `NEURALBRIDGE_AUDIT_BACKEND=postgres`; in-memory only by explicit opt-in). It is hash-chained, safe for several worker processes, free of credentials, and refuses to start, turns `/health/ready` red (503) and refuses security-relevant calls (503) if it cannot record. It records connection create / rotate / revoke / delete, plan propose / approve / deny / execute, every adapter call and every entitlement or policy denial, each with actor and tenant. It is not an immutable-by-construction store: anyone with write access to the file can edit it, and the hash chain then fails verification (`/api/v1/logs/export` recomputes it); there is no external anchoring or signed head for this trail, so truncation of the whole file is not detected. Retention is the operator's: nothing here deletes or rotates records. The row above still reads "in memory by default" because the homepage copy that must match it word for word (`app/lib/platformStatus.ts`) has not been updated yet; the code, and this paragraph, are the current state.

**Bound `/ai` connections across worker processes, as the code now is.** The root image starts `uvicorn --workers 4`.
A connection bound with `POST /ai/connections` used to keep its password only in the worker that bound it, so the other
workers answered `409 no live adapter`, a rotation reached one worker, in-memory rate limits multiplied by the worker count,
and a restore of an older backup could resurrect a revoked connection. What is enforced now (code: `src/neuralbridge/ai/credentials.py`;
tests: `tests/test_credential_custody.py`, `tests/test_platform_rollback.py`, `tests/test_platform_multiworker_custody.py` which starts
four real workers):

* **Credential custody, fail closed.** The credential is sealed with AES-256-GCM (a fresh nonce per record; the associated data binds the
  tenant, the connection id, the credential version, the key id and a digest of host/port/database/ssl mode) and stored as ciphertext in the
  `/ai` store. **The key is never in that database:** it comes from `NEURALBRIDGE_CREDENTIAL_KEYS` (`id:base64(32 bytes)[,..]`, for example a
  KMS-issued data key injected as a secret) or `NEURALBRIDGE_CREDENTIAL_KEY_FILE` (mode 0600, outside the store's directory), with
  `NEURALBRIDGE_CREDENTIAL_ACTIVE_KEY` naming the key new records are sealed under. **With no key, or no anti-rollback journal (below), binding and
  rotating answer `503 credential_custody_unconfigured`** and nothing is stored; revoking and deleting always work. Every worker reads the
  shared record on every use: a bound connection is usable from all of them, a rotation is used by the others on their next call, a revocation is
  refused by all of them on their next call (and a worker still holding the adapter drops it).
* **Key rotation.** Add the new key, make it active, restart, run `python -m neuralbridge.ai.credentials reencrypt`, and remove the old key once
  `python -m neuralbridge.ai.credentials status` shows nothing sealed under it. A record whose key is missing fails closed (`503`), never open.
* **Retention.** Only the current ciphertext of a connection is kept. Revoke and delete remove it in the transaction that changes the record, and the
  store runs with `secure_delete` (freed pages are zeroed). Earlier backups still hold earlier ciphertext sealed under keys you control; retiring a
  key makes the backups sealed under it unreadable. SQLite's `-wal` file can still hold an old page image until it is checkpointed.
* **Anti-rollback.** `NEURALBRIDGE_CREDENTIAL_JOURNAL` names an append-only, hash-chained file that must live **outside the `/ai` store's
  directory** (a journal inside it is refused). Each create, rotate, revoke and delete is written to it before the store changes, and every use of a
  stored credential is checked against it: revoked or deleted in the journal means refused, a credential version below the journal's high-water mark
  means refused, and a lost, replaced or corrupt journal stops every stored credential being served. After `restore_check restore` of an older backup the
  revoked or rotated-away credential is **not** usable (the restored store is corrected on first use; `python -m neuralbridge.ai.credentials reconcile`
  does it in bulk). **Limits, stated:** the journal protects against restoring the store, not against a whole-volume snapshot restore that rewinds the
  journal with it (`/health/ready` warns `credential_journal_same_device` when both share a device; put the journal on separate storage); it is a hash chain,
  not a signature, so someone who can rewrite the journal can recompute it; all workers must share one filesystem for the store and one for the journal (SQLite
  on a network filesystem without working locks is not supported).
* **Single-worker mode, labelled.** `NEURALBRIDGE_AI_PROCESS_LOCAL_CREDENTIALS=single-worker` keeps the old behaviour (nothing stored; the connection is live
  only in the process that bound it; `custody: "process_local"`), and is refused when `WEB_CONCURRENCY` is greater than 1. uvicorn's `--workers` flag is not
  visible to the process, so this is an assertion by the operator, not a detection; connections bound this way can be moved into the vault by rotating them.
* **Rate limits.** The per-tenant adapter-call limit (120 a minute by default, `NEURALBRIDGE_RATE_LIMIT_PER_MINUTE`) is now counted in the `/ai` store with one
  atomic upsert per call, so it is exact across worker processes on one host. It is a fixed window (a burst across a window boundary can admit up to twice the
  limit) and falls back to a per-process count, reported by `/health/ready`, if the store errors. **Still per process:** the in-flight concurrency gate (32 in
  total, 8 per adapter, per worker), the audit refusal-event limiter (a log-volume guard) and the assurance-side throttles (checkout, claim, Stripe budget); with
  `WEB_CONCURRENCY` greater than 1 `/health/ready` warns that they admit that many times their configured value. `security/rate_limit.py` (a Redis token bucket)
  is not wired to any route.
* **Four-eyes approval (opt-in, off by default).** When an account (`PUT /ai/policy`) or the deployment (`NEURALBRIDGE_AI_FOUR_EYES=1`) turns it on, the account
  that proposes a write plan cannot approve it with the same API key: for a customer account the proposer and the approver must each authenticate with a key bound to a
  **named operator**, and to different operators (an account-level key proves the account, not a person, and one holder can mint any number of them; an account-level
  key can create only the account's first operator, every further one needs a decider). `X-NB-Actor` is a label and plays no part. An unapproved proposal expires after 24 hours (`NEURALBRIDGE_AI_FOUR_EYES_TTL_S`) and a denied,
  expired, failed or executed plan can never run; the approver's identity and time are written once and the store refuses to change them. The policy is visible
  read-only in `GET /ai/policy`, `GET /ai/connections` (`four_eyes`) and the plan (`four_eyes`, `expires_at`). An account can switch it on for itself but only the
  operator can switch it off. A name binds a credential to a name and does not prove who holds it: one person given two operator keys is not detected.

Treat anything not marked **Supported** as evolving, whatever older marketing
copy elsewhere in this repository's history might have claimed. The former
`src/dashboard` Vite/React admin UI has been retired: it made no API calls and displayed fixed sample figures. The customer
workspace is the root Next.js app (`/assurance`, `/ai`, `/console`), which reads the real APIs and says so when it cannot —
stated here plainly rather than glossed over.

Full detail, including what is not yet claimed, is in the
[README's platform section](https://github.com/iceccarelli/neuralbridge#neuralbridge--the-platform-underneath).
