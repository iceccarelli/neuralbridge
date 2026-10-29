# Attestation — closing the hole every hash-chained audit log ships with

## The hole

A hash chain detects **editing**. Change a record and every link after it stops
matching, and `verify_chain` names the sequence number.

A hash chain does not detect **removal**. An administrator with write access to
the database can delete the last forty records, rebuild the chain from genesis
without them, and hand you a ledger that verifies perfectly. Nothing in the
file says anything was ever there. This is not a defect in this implementation;
it is a property of chains, and it is true of every product that sells you one.

Here is the attack, in full, against this system:

```sql
DELETE FROM chain WHERE seq > 12;
```

That is the entire attack when the chain was built naively. This ledger binds
each link hash to its own sequence and content, so a rewind followed by fresh
appends is needed rather than a raw delete — which is three lines of Python
instead of one. The difficulty is not the point. The point is that afterwards,
`verify_chain` returns `True`.

## The close

A value that depends on the whole history has to leave the building, and be
signed by a key the holder of the database does not have. Then a rewind is no
longer a matter of anybody's word: here is a signature, made at a stated time,
over a head this ledger can no longer produce.

Two deployments do this, and they are for different buyers.

---

## 1. Local signing — you hold the key, off the machine

For an operator who runs their own ledger and wants a signer under their own
control: a build server, a security team's host, an HSM, anything that is not
the box the ledger lives on.

```bash
# On the signing host — NOT on the ledger host.
assurance attest keygen \
    --out /secrets/attest.pem \
    --passphrase-env ATTEST_PASS

# The tool refuses to write the key into the ledger's directory:
assurance attest keygen --out /data/attest.pem --ledger /data/register.db
# error: refusing to write the signing key into /data, which is where
# register.db lives. [...]
```

That refusal is not paternalism. A key stored beside the records it signs is a
decoration, because whoever can rewrite the records can re-sign them.

Then, on a timer:

```bash
0 3 * * *  assurance attest sign \
               --ledger /data/register.db \
               --key /secrets/attest.pem \
               --log /vault/attest.jsonl \
               --note nightly || alert "attestation refused"
```

**The exit code is the interface.**

| code | meaning |
|-----:|---------|
| 0 | signed |
| 1 | a **finding** — a rewind, a fork, an unexpected key |
| 2 | the command could not run (missing file, bad passphrase) |
| 3 | the attestation log ends in an unterminated line (a write that did not finish): `verify` reports `ok: false` / `torn_tail: true` because the newest attestation may be missing; `sign` appended nothing |

A finding must not share an exit code with a missing file. If `sign` ever exits
1, do not investigate by re-running it: preserve the database and the
attestation log as they are, and read the message. Exit 3 is the log needing a
person, not a verdict on the ledger: copy the log aside, look at its last line
(`tail -c 400 attest.jsonl`), and only then repair it. A last line that is a complete
record merely missing its newline is repaired by the next `sign`; one that is cut
off mid-record has to be truncated back to the previous newline by hand, which gives
up the attestation that was being written. A real finding (exit 1) is reported as
exit 1 even when the tail is also torn.

Checking, by anybody who has the public key:

```bash
assurance attest verify \
    --log /vault/attest.jsonl \
    --public-key /vault/attest.pem.pub \
    --ledger /data/register.db
```

With `--ledger` this asks the question that matters: does the ledger in front of
us still hold every head that was signed for? Without it, the command says so
plainly rather than letting you assume otherwise.

---

## 2. Counter-signature — we hold the key, and never see your ledger

For a manufacturer or integrator who does not want to run a second host, and
whose auditor will not accept self-signed evidence anyway. Cell plan.

**Status: needs a service key that is not configured on any deployment today.** Until
the operator sets `ASSURANCE_ATTEST_KEY_PEM` (or `ASSURANCE_ATTEST_KEY`), this route
answers 503 `no_attestation_key_configured`. The offline path in section 1 needs no
service key.

**The ledger never leaves the premises** for this call (that is true of attestation
only: hosted `POST /v1/machine/verify` receives the full trace you submit, and the
hosted routes receive what you send them). The customer computes their own head —
which requires trusting nobody — and sends three numbers:

```bash
curl -sS https://assurance-register.fly.dev/v1/ledger/attest \
  -H "X-API-Key: $ASSURANCE_KEY" \
  -H 'content-type: application/json' \
  -d '{"ledger_length": 412,
       "head_seq": 412,
       "head_link_hash": "9f2c...",
       "note": "weekly"}'
```

The service signs that, records it in an append-only log belonging to that
account, and refuses exactly the cases the local signer refuses. A shorter
ledger comes back **409**, not 422 — it is a finding, not a malformed request:

```json
{"error": "attestation_refused",
 "finding": "refusing to attest: the ledger holds 380 record(s), but attestation 6 signed for 412 at 2026-09-07T03:00:00Z. An append-only ledger does not get shorter. [...]"}
```

What this buys, precisely:

* The customer's own administrator cannot rewind, because the removed records
  were counted in a statement signed by a key nobody at the customer holds.
* The service cannot fabricate the customer's evidence, because the service
  never had it. All it ever saw was a hash.
* Neither party can quietly change the story, because each holds a copy of a log
  that chains to itself.

Every attestation made this way carries `"basis": "declared_by_holder"` **inside
the signed bytes**. The service did not see the chain verify, and it is not
going to let that be read as something stronger later. Locally signed
attestations carry `"basis": "read_from_ledger"`.

### Declared heads are about *your* ledger, and bounded

A declared head is compared only with heads **you declared earlier**. Your ledger
and the one this service hosts for you (the register, the change cases) are two
ledgers; the account's log may hold records about both, and comparing one with the
other would tell you records were removed because the hosted ledger happened to be
longer. The hash chain of the log and the key check still span the whole file.

`ledger_length` and `head_seq` are capped at 10,000,000 (`MAX_DECLARED_LEDGER`);
beyond that the answer is **422**. The cap is a sanity bound, not a plan limit: an
unbounded number in an append-only log is a lever.

`note` (500 characters) is **your text**. The signature covers it because it
covers every field, which does not make it a statement by the key holder about your
ledger. The response carries `note_is_tenant_supplied`, and every verification
(`POST /v1/ledger/attest/verify`, `assurance attest verify`, which add a `notes`
list) says the note is the requester's free text. Do not read a note as an
assurance; the signed values are the three numbers.

### When the service is busy or the log is damaged

* **503 `attestation_busy`** with `Retry-After`: another request holds the log's
  lock and did not release it within 10 seconds. Nothing was signed; retry.
* **500 `attestation_log_damaged`**: the account's log cannot be read, or ends in
  a write that did not finish (a crash mid-append). This is a fault to repair, not a
  finding about your ledger, and it is not a 409. Nothing is appended onto a damaged
  tail: the file is evidence and is left as found. `GET /v1/ledger/attest/log` still
  answers, lists the readable records and puts the unfinished line in `warnings`.
  **A hosted export does not read around it:** the unfinished line may be the newest
  attestation, so choosing the record before it could anchor the export to a stale
  head after a rewind. `GET /v1/cases/{id}/export` and `GET /v1/change/cases/{id}/export`
  look again briefly (a writer may be mid-append), then answer **503 `attestation_busy`**
  (a signer holds the log's lock: retry) or **500 `attestation_log_damaged`** (nobody is
  writing: repair the file, see exit 3 above). `?anchor=false` exports without an anchor
  and says nothing about the log.
* The tenant API has no `rotating` flag: changing the signing key is acknowledged only
  by the operator (`assurance attest sign --rotating`). A request that sends `rotating`
  is refused with 422.
* Error text never names a server path.

### Verification is free and always will be

```bash
curl -sS https://assurance-register.fly.dev/v1/ledger/attest/verify \
  -H 'content-type: application/json' \
  -d '{"attestations": [ ... ]}'
```

No key, no account, no quota. The audience for an attestation is a regulator, an
insurer, or a customer's customer — none of whom will ever hold an API key here,
and all of whom must be able to check the thing without asking us. An
attestation only a paying customer can verify is worth nothing.

The public key is at `GET /v1/ledger/attest/key`, free. Obtaining it over the
same connection as the signatures proves only that one party was consistent, and
the response says so.

---

---

## 3. Anchoring a hosted export — an operator procedure, not a customer feature

A hosted case export (`GET /v1/cases/{id}/export`, `GET /v1/change/cases/{id}/export`)
embeds an `anchor` only when the account's attestation log holds an attestation the
service **read from that account's own ledger** (`basis: read_from_ledger`). **No
customer route writes one.** `POST /v1/ledger/attest` writes `declared_by_holder`
records about the customer's ledger, and those are never embedded. The only
producer of a `read_from_ledger` record for a hosted ledger is the operator's
`assurance attest sign` run against that account's ledger file, so **until the
operator has done it, a hosted export has no `anchor` and its completeness is
`not_checked`.** Do not describe it to a customer as anchored.

On the host that holds the ledgers (the lock is a file lock: run it on the same
host, or the API's writers and yours do not exclude each other):

```bash
# ASSURANCE_TENANT_LEDGERS/<account-id>.db is the account's ledger;
# $ASSURANCE_ATTEST_LOGS/<account-id>.jsonl is the account's attestation log.
assurance attest sign \
    --ledger "$ASSURANCE_TENANT_LEDGERS/$ACCOUNT_ID.db" \
    --key /secrets/attest.pem \
    --log "$ASSURANCE_ATTEST_LOGS/$ACCOUNT_ID.jsonl" \
    --note "operator, hosted ledger"
```

* Use the **same key** the service counter-signs with, or the log is refused as a
  key change (`--rotating` only for a deliberate rotation).
* Length, head and fork checks compare only records of the same basis, so the
  customer's declared heads and your read heads coexist in one log. A refusal here
  (exit 1) is about the hosted ledger itself: preserve it and the log.
* This anchor is weak by construction: the service holds the ledger, the log and
  (here) the key. It protects only a customer who **keeps their own copy** of a
  signed attestation and checks later exports against it
  (`assurance evidence verify BUNDLE --public-key KEY.pub --attestations THEIR.jsonl`).
  Signing from a host that does not hold the ledger directory is the stronger
  arrangement, and section 1 describes it.
* The offline CLI's `--attestations LOG` (`assurance change export`,
  `assurance art14 export`) uses the same selection rule as the API: the newest
  `read_from_ledger` record. A log that holds only `declared_by_holder` records is
  accepted there because a person named it, and the export says so: the embedded
  anchor carries `"basis": "declared_by_holder"` and the CLI prints that it was
  declared by the holder and not read from the ledger. A declared head over zero
  records anchors nothing and is refused.

## Checking an export without our software

An auditor who does not want to install or trust this package can check a whole-ledger export with one
file, `scripts/verify_export_standalone.py`: Python standard library only, readable end to end, no network.

```bash
python verify_export_standalone.py export.json                         # internal consistency; exit 3
python verify_export_standalone.py export.json --public-key signer.pub # + completeness; needs `cryptography`
```

Exit 0 only with a trusted public key and a signed head the signer *read from the ledger*. Without a key it
says "completeness not checked" (exit 3): anyone holding the file can rebuild a consistent chain with entries
left out, and the exporter's own head record can be rewritten to match. It is deliberately narrower than the
product's verifier (whole-ledger exports of schema 1 only; anything else is exit 3, never a pass). The
independent test suite (`neuralbridge-stress-test`, `tests/test_standalone_verifier.py`) checks that it is
never more lenient than the product's verifier across the tamper matrix, including a forgery in which every
hash is recomputed and only the signed head exposes it.

## Deploying the counter-signer

```bash
assurance attest keygen --out ./attest-service.pem
fly secrets set ASSURANCE_ATTEST_KEY_PEM="$(cat ./attest-service.pem)"
```

| variable | meaning |
|---|---|
| `ASSURANCE_ATTEST_KEY_PEM` | the Ed25519 private key itself — what a secrets manager hands a container. Checked first |
| `ASSURANCE_ATTEST_KEY` | path to that key, for a deployment that mounts a volume or a token |
| `ASSURANCE_ATTEST_PASSPHRASE` | passphrase for it, if encrypted |
| `ASSURANCE_ATTEST_LOGS` | directory holding one JSONL log per account (put it on the volume). Writers take a file lock on `<log>.lock`, keyed by the log's real path |

With no key configured, every signing route returns **503** with
`no_attestation_key_configured`. The service will not generate a key on demand:
a key that appears when first needed, on the machine that needs it, is not a
second party.

## What none of this establishes

* **That the public key belongs to whom you think.** A signature is worth
  exactly the provenance of the key. Confirm the fingerprint by a route other
  than the one the attestations travelled on — reading sixteen hex characters
  aloud over a telephone is a real and sufficient method.
* **That records appended since the last attestation are intact.** They rest on
  the chain alone until the next signature. Attest on a cadence that matches
  how much history you are willing to lose the ability to defend.
* **That the records were true when written.** Attestation is about custody,
  not about content. Nothing here says a manifest was read from the machine it
  claims to describe; that is what the assurance tiers are for.
