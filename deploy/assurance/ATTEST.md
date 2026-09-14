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

A finding must not share an exit code with a missing file. If `sign` ever exits
1, do not investigate by re-running it: preserve the database and the
attestation log as they are, and read the message.

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

**The ledger never leaves the premises.** The customer computes their own head —
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
| `ASSURANCE_ATTEST_LOGS` | directory holding one JSONL log per account (put it on the volume) |

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
