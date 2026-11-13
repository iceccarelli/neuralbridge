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

## What `verify` establishes, and what it cannot

`assurance attest verify --log L --public-key K [--ledger DB]` establishes that the
attestations in `L` are genuine (signatures, unbroken sequence, each naming its
predecessor, lengths never decreasing; one key, or, across a rotation, each record under the
key it names: repeat `--public-key` or give a `--keyset`, see "Key history" below) and, with
`--ledger`, that the ledger still contains every head `L` attests.

It does **not** establish that `L` is the newest log. Whoever can write both the ledger
and the log can truncate the ledger to an older signed head, cut the log back to the
attestation that signed it, and leave a pair that verifies: every remaining signature is
genuine and every remaining head is present. (Reproduced: sign at length 10, append to 20,
sign again, `DELETE FROM chain WHERE seq > 10`, keep only the first log line: `ok`.) Nothing
inside the pair can show it. Only the verifier's own memory can:

```bash
# first check: note the two values printed under "keep for your next check"
assurance attest verify --log L --public-key K --ledger DB
#   --min-sequence 2 --expect-head 3f9c...   (the newest attestation seen)

# every later check
assurance attest verify --log L --public-key K --ledger DB \
    --min-sequence 2 --expect-head 3f9c... --max-age 26
```

* `--min-sequence N` fails the check ("rollback or withheld newer attestation") when the
  log's newest attestation is older than N.
* `--expect-head HASH` (12+ hex characters of the head link hash) fails it when no
  attestation in the log has that head.
* `--max-age HOURS` fails it when the newest attestation is older than that: signing has
  stopped, or newer attestations are being withheld.
* With neither expectation, a passing check says so: *cannot detect a withheld newer
  attestation or a rollback; keep and pass the newest head from your last check*. The
  same note appears in `checks_skipped` of the JSON output, and `remember_for_next_check`
  holds the values to keep. Keep them somewhere the ledger's operator cannot write.

**Which ledger a signed head describes.** A head read from a ledger that has a lineage id is
signed as format `assurance.head-attestation.v2`: the ledger id (and the tenant, when given) is
inside the signed bytes, so a head from tenant A's ledger cannot be replayed as tenant B's, and
stripping the id changes the bytes. A ledger with no lineage id, and every counter-signature of a
head somebody declared, is `v1`: **unbound**, a statement that a head with these numbers was signed,
not that it was this ledger's. `verify` says which each record is (`binding`, `unbound`), `--ledger`
or an expected ledger id compares the bound ones, and an *export bundle* names no ledger id, so
whether a bound anchor describes the bundle's ledger is stated as not checked. Records written
after the newest signature are covered by no signature.

Reading is read-only: `verify`, `sign` and the other read verbs open the ledger without
writing to it (no journal-mode change, no schema script, no ledger id minted, no `-wal` or
`-shm` created), so the bytes you verified are the bytes that were there.

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

## Checking an exported bundle against what you remember

`assurance evidence verify BUNDLE --public-key KEY.pub` shows a bundle agrees with a signed head.
It cannot show it is the **newest**: a bundle cut back to any older genuine head, with the unsigned
head record rewritten and the older anchor embedded, is consistent and anchored (reproduced: 13
records, signed at 11 and at 13, last two deleted: `VERIFIED - anchored ... 11 entries`, exit 0).
Only your own record of the last check closes it, so a passing anchored check prints

```
KEEP FOR YOUR NEXT CHECK ... --min-sequence 2 --expect-head 3f9c...(64 hex) --min-length 13
```

and `evidence verify` (and `scripts/verify_export_standalone.py`) take them back:

* `--min-sequence N`: the bundle's newest signed head must be attestation N or later;
* `--expect-head HASH` (12+ hex): that head must still be in the bundle's chain;
* `--min-length N`: the chain must be at least N records; a shorter one says how many were removed;
* `--max-age HOURS`: the signed head must have been signed within that time.

A violated value is exit 1 (the headline names the attestation, seq, head and age it rests on).
A value that cannot be compared (a subject export without a skeleton has no complete chain to look in)
is exit 3, never a pass. They need `--public-key` or `--keyset`. The values are the *export's* anchor
(the signer's `read_from_ledger` head); a hosted account's log also holds `declared_by_holder`
records with their own sequence numbers, so keep the values `evidence verify` printed, not those of
`attest verify`, for exports.

**`--expect-fingerprint FP`** (on `evidence verify`, `attest verify` and the standalone file; repeat
it for several keys) is the signing key's fingerprint as you wrote it down from a source other than
the bundle. Without it a forged shorter ledger signed with the forger's key verifies "anchored" when
you are handed the forger's public key. With it a different key, or a record signed by a key you did
not list, is exit 1. A fingerprint is 16 hex characters, **64 bits** of SHA-256 over the raw public
key: it catches a swapped or mistyped key and is a weaker defence against a deliberately ground-out
one; compare the whole key file where the stakes justify it. (The format is unchanged.)

### Key history: `--keyset`

After a rotation the old key still signed every earlier anchor. A verifier holding only today's key
(`--public-key` once) still calls an earlier-era anchor a *foreign anchor*, exit 1, as before. For a
history, keep a **keyset**: a public-key-only JSON file `assurance.attest.keyset.v1` with each key's
fingerprint, PEM, `status` (`active`, `retired`, `revoked`) and `effective_from` / `effective_until`
(UTC, `YYYY-MM-DDTHH:MM:SSZ`; a retired key needs its end, an active one has none).

```bash
assurance attest keyset add --keyset keys.json --public-key old.pub --fingerprint <FP you wrote down> \
    --status retired --effective-from 2025-01-01T00:00:00Z --effective-until 2026-06-01T00:00:00Z --label "first era"
assurance attest keyset add --keyset keys.json --public-key new.pub --fingerprint <FP> \
    --status active --effective-from 2026-06-01T00:00:00Z
assurance attest keyset check --keyset keys.json
assurance evidence verify BUNDLE --keyset keys.json [--attestations MY.jsonl]
assurance attest verify --log L --keyset keys.json
```

The key that checks an anchor is the one whose fingerprint the anchor names, from this file, never
from the bundle. A **revoked** key's anchor is a problem whatever date it carries; an anchor dated
outside a **retired** key's window is a problem; a fingerprint **not in the file** is *not
established* (exit 3), because it may be a genuine anchor from a key you hold no record of; it is
neither a forgery finding nor a pass. Repeating `--public-key` (two or more) is a keyset without
history. The loader fails closed: it refuses private key material, a repeated JSON name, an unknown
field, a wrong type, a fingerprint that is not the key's, a repeated key, a bad date and any other
format version. An anchor's date is the signer's own claim, so a window makes a retired key's honest
anchors checkable and cannot expose a leaked key's forged ones.

## Checking an export without our software

An auditor who does not want to install or trust this package can check an export with one
file, `scripts/verify_export_standalone.py`: Python standard library only (plus `cryptography` for the
signature), readable end to end, no network.

```bash
python verify_export_standalone.py export.json                         # internal consistency; exit 3
python verify_export_standalone.py export.json --public-key signer.pub # + completeness
python verify_export_standalone.py export.json --keyset keys.json --attestations mine.jsonl \
    --expect-fingerprint <FP> --min-sequence 2 --expect-head 3f9c... --min-length 13 --max-age 26
```

Exit codes: **0** only with a key and a signed head the signer *read from the ledger* covering every
record, with every remembered value met; **1** the file contradicts itself or a signed statement
(edited, rebuilt, cut, a rollback, a substituted key, a revoked key); **2** not a readable export, or
an unreadable keyset or attestation log; **3** nothing wrong was found but something is not
established. Without a key it says "completeness not checked" (exit 3). A **subject-only export** (what
`GET /v1/cases/{id}/export` emits) is checked entry by entry and is **exit 3**: it cannot be shown
complete by this file, with or without a skeleton, and it is never reported as a removed record. It is
deliberately narrower than the product's verifier (schema 1 only; it never merges a skeleton; anything
it does not understand is exit 3, never a pass). The independent test suite
(`neuralbridge-stress-test`, `tests/test_standalone_verifier.py`) checks that it is never more lenient
than the product's verifier across the tamper matrix, and `tests/test_standalone_verifier_parity.py`
here runs each input class through both and compares the exit codes.

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

A key file that is present but unsafe (group/other access, a symlink, another account's
file, or a directory group/other can write) is refused too: **503** with
`attestation_key_unsafe`, distinct from `no_attestation_key_configured`.

## Canonicalisation and hashing recipe

Everything signed or chained here is a SHA-256 over a **canonical JSON** string, produced by
`assurance.core.identity.canonical_json`. It is the recipe of this implementation, **not** RFC 8785
(JCS): a reimplementation in another language must reproduce these steps exactly, including the ways
it differs from JCS.

1. Every number, integer or float, becomes `round(float(v), 6)`; negative zero becomes `0.0`;
   booleans are not numbers. So `1` hashes as `1.0`, `1` and `1.0` hash alike, and an integer
   beyond 2^53 or a fraction finer than 6 places is indistinguishable from its neighbour (the
   verifier reports such a number as unestablished).
2. Objects are written with keys sorted by Python's string order (code points), recursively.
3. `json.dumps(..., sort_keys=True, separators=(",", ":"), default=str)`: no whitespace; strings
   are **ASCII-only** (every non-ASCII character is `\uXXXX`, lower-case hex, surrogate pairs above
   U+FFFF; `ensure_ascii` is the default); floats use **Python's `repr`** (`1e+16`, `0.1`, `1e-05`),
   where JCS would write `10000000000000000`.
4. The string is encoded UTF-8 and hashed with SHA-256; the hex digest is the content / link hash.
5. A signature (Ed25519, 64 bytes, base64 in the record) is over the **canonical bytes themselves**,
   not over their hash.

What is hard-wired, with no algorithm identifier in any artefact: SHA-256; Ed25519; the format
strings `assurance.head-attestation.v1` / `.v2`, `assurance.attest.keyset.v1`, and ledger schema
version 1 (checked as `ledger_schema_version`); key fingerprint = first 16 hex characters of SHA-256
over the raw 32-byte public key. A different hash, curve or canonicalisation must be introduced as
a **new format version** (a new format string that the old verifier does not know): an old verifier
refuses an unknown format by name (a bundle with another `ledger_schema_version` or an anchor with
another `format` is "not one of ..." / exit 1 or 3, never a guess), and no format may be changed in
place.

Test vectors, generated by the code above (`tests/test_standalone_verifier_constants.py` pins them
and the standalone file reproduces them):

| # | input | canonical bytes | SHA-256 |
|--|--|--|--|
| 1 | `{"b": 1, "a": [2.5, -0.0, "é"], "c": {"z": 0.1234567}, "t": true}` | `{"a":[2.5,0.0,"\u00e9"],"b":1.0,"c":{"z":0.123457},"t":true}` | `8f45042f5f1c62124bab8111f7f69d43b09553a944a0e2fa41111f314e802bf8` |
| 2 (not JCS) | `{"x": 10000000000000000, "y": 1e-07, "n": null}` | `{"n":null,"x":1e+16,"y":0.0}` | `fefde0fdef586a2ed3a1f5dcd293f7e26be012ae91936b7f0b56300945bf43fc` |
| 3 (a ledger link) | seq 1, at `2026-01-02T03:04:05Z`, kind `t.record`, subject `CASE-A`, content_hash `aaaa...a` (64), prev_hash = 64 zeros | `{"at":"2026-01-02T03:04:05Z","content_hash":"` + 64 `a` + `","kind":"t.record","prev_hash":"` + 64 `0` + `","seq":1.0,"subject":"CASE-A"}` | `9a3020f18b95f8c255564b171c7a4f7e61d4fed65627009f87380457446aa613` |

Vector 4 is the byte string an attestation signature covers (a `v1` record, then base64 of the
Ed25519 signature over exactly these bytes; `sequence`, `head_seq`, `ledger_length` are `1.0`, `3.0`,
`3.0` in it):

```
{"attested_at":"2026-01-02T03:04:05Z","basis":"read_from_ledger","format":"assurance.head-attestation.v1","head_link_hash":"bbbb...b (64)","head_seq":3.0,"key_fingerprint":"0123456789abcdef","ledger_length":3.0,"note":"","previous":"","sequence":1.0}
```

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
